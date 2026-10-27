// SynFin for Windows: the desktop GUI, drawn with Dear ImGui on Direct3D 11.
//
// It mirrors the Linux GUI (gui/synfin_gui.py) — same palette, layout and features — but
// runs the analyzer in-process instead of starting the synfin binary, so the whole app is
// one portable .exe. Fonts, icon and version info are embedded as resources.
//
// Command line: SynFin.exe [capture files or folders...] adds them and starts the analysis.
// For automated checks (CI, README screenshots) there are a few extra options:
//   --export FILE         when the analysis is done, export (.csv or .jsonl) and exit
//   --capture FILE.bmp    when the analysis is done, save a screenshot of the window and exit
//   --status-filter KEY   show only fin / rst / timeout / end_of_capture sessions
//   --sort-duration       sort by duration, longest first
//   --timeout SECONDS, --threads N

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <shellapi.h>
#include <shobjidl.h>
#include <dwmapi.h>
#include <d3d11.h>

#include <algorithm>
#include <atomic>
#include <cctype>
#include <chrono>
#include <cstdio>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "imgui.h"
#include "imgui_impl_dx11.h"
#include "imgui_impl_win32.h"
#include "session_analyzer.h"
#include "gui_resources.h"

extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);

namespace fs = std::filesystem;
using Clock = std::chrono::steady_clock;
using CloseReason = SessionAnalyzer::CloseReason;
using SessionRecord = SessionAnalyzer::SessionRecord;

// ---------------------------------------------------------------------------------------
// Palette and sizes (the same values as the Linux GUI)

static ImU32 Rgb(unsigned hex, float alpha = 1.0f) {
    return IM_COL32((hex >> 16) & 0xFF, (hex >> 8) & 0xFF, hex & 0xFF, static_cast<int>(alpha * 255));
}
static ImVec4 RgbV(unsigned hex) { return ImGui::ColorConvertU32ToFloat4(Rgb(hex)); }

constexpr unsigned BG = 0x0d1117, SURFACE = 0x161b22, RAISED = 0x1f2630, HOVER = 0x262d38, BORDER = 0x30363d,
                   BORDER_HI = 0x484f58, TEXT = 0xe6edf3, MUTED = 0x8b949e, FAINT = 0x6e7681, ACCENT = 0x2f81f7,
                   ACCENT_HI = 0x4493f8, ACCENT_LO = 0x1f6feb, ROW_ALT = 0x1a2029, SELECT = 0x1c3a63, WHITE = 0xffffff;

struct StatusInfo {
    CloseReason reason;
    const char* key;
    const char* label;
    unsigned color;
};
static const StatusInfo kStatuses[] = {
    {CloseReason::Fin, "fin", "FIN", 0x3fb950},
    {CloseReason::Rst, "rst", "RST", 0xf85149},
    {CloseReason::Timeout, "timeout", "Timeout", 0xd29922},
    {CloseReason::EndOfCapture, "end_of_capture", "Still open", 0xa371f7},
};
static const StatusInfo& Status(CloseReason reason) {
    for (const auto& s : kStatuses)
        if (s.reason == reason) return s;
    return kStatuses[0];
}

// Font sizes in pixels at 100 % scaling.
constexpr float kBase = 13.5f, kSmall = 12.0f, kLabel = 11.0f, kH2 = 15.0f, kTitle = 23.0f, kStat = 29.0f, kMono = 12.5f;

// ---------------------------------------------------------------------------------------
// Small helpers

static std::string ToUtf8(const std::wstring& w) {
    if (w.empty()) return {};
    int n = WideCharToMultiByte(CP_UTF8, 0, w.data(), static_cast<int>(w.size()), nullptr, 0, nullptr, nullptr);
    std::string s(n, '\0');
    WideCharToMultiByte(CP_UTF8, 0, w.data(), static_cast<int>(w.size()), &s[0], n, nullptr, nullptr);
    return s;
}

static std::wstring ToWide(const std::string& s) {
    if (s.empty()) return {};
    int n = MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), nullptr, 0);
    std::wstring w(n, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), &w[0], n);
    return w;
}

static std::string Lower(std::string s) {
    for (char& c : s)
        if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
    return s;
}

// 1234567 -> "1 234 567", like the Linux GUI.
static std::string Grouped(size_t n) {
    std::string digits = std::to_string(n), out;
    for (size_t i = 0; i < digits.size(); ++i) {
        if (i && (digits.size() - i) % 3 == 0) out += ' ';
        out += digits[i];
    }
    return out;
}

// Local time with milliseconds (table) or microseconds (export).
static std::string FormatTime(const Timestamp& ts, bool precise) {
    std::time_t t = static_cast<std::time_t>(ts.sec);
    std::tm tm{};
    localtime_s(&tm, &t);
    char buf[64];
    std::strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &tm);
    char frac[16];
    if (precise)
        std::snprintf(frac, sizeof(frac), ".%06d", ts.usec);
    else
        std::snprintf(frac, sizeof(frac), ".%03d", ts.usec / 1000);
    return std::string(buf) + frac;
}

static bool IsCaptureFile(const fs::path& path) {
    std::string ext = Lower(path.extension().u8string());
    return ext == ".pcap" || ext == ".pcapng";
}

static std::vector<std::string> CapturesInFolder(const fs::path& folder) {
    std::vector<fs::path> found;
    std::error_code ec;
    for (fs::directory_iterator it(folder, ec), end; !ec && it != end; it.increment(ec))
        if (it->is_regular_file(ec) && IsCaptureFile(it->path())) found.push_back(it->path());
    std::sort(found.begin(), found.end());
    std::vector<std::string> out;
    for (const auto& p : found) out.push_back(p.u8string());
    return out;
}

static std::string CsvField(const std::string& s) {
    if (s.find_first_of(",\"\r\n") == std::string::npos) return s;
    std::string out = "\"";
    for (char c : s) {
        if (c == '"') out += '"';
        out += c;
    }
    return out + "\"";
}

// ---------------------------------------------------------------------------------------
// Direct3D

static ID3D11Device* g_device = nullptr;
static ID3D11DeviceContext* g_context = nullptr;
static IDXGISwapChain* g_swapChain = nullptr;
static ID3D11RenderTargetView* g_renderTarget = nullptr;
static UINT g_resizeWidth = 0, g_resizeHeight = 0;

static void CreateRenderTarget() {
    ID3D11Texture2D* backBuffer = nullptr;
    g_swapChain->GetBuffer(0, IID_PPV_ARGS(&backBuffer));
    g_device->CreateRenderTargetView(backBuffer, nullptr, &g_renderTarget);
    backBuffer->Release();
}

static void CleanupRenderTarget() {
    if (g_renderTarget) { g_renderTarget->Release(); g_renderTarget = nullptr; }
}

static bool CreateDeviceD3D(HWND hwnd) {
    DXGI_SWAP_CHAIN_DESC sd{};
    sd.BufferCount = 2;
    sd.BufferDesc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
    sd.BufferDesc.RefreshRate.Numerator = 60;
    sd.BufferDesc.RefreshRate.Denominator = 1;
    sd.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
    sd.OutputWindow = hwnd;
    sd.SampleDesc.Count = 1;
    sd.Windowed = TRUE;
    sd.SwapEffect = DXGI_SWAP_EFFECT_DISCARD;
    const D3D_FEATURE_LEVEL levels[] = {D3D_FEATURE_LEVEL_11_0, D3D_FEATURE_LEVEL_10_0};
    D3D_FEATURE_LEVEL level;
    HRESULT res = D3D11CreateDeviceAndSwapChain(nullptr, D3D_DRIVER_TYPE_HARDWARE, nullptr, 0, levels, 2,
                                               D3D11_SDK_VERSION, &sd, &g_swapChain, &g_device, &level, &g_context);
    if (res != S_OK)  // no usable GPU (e.g. a VM or a remote session): use the WARP software rasterizer
        res = D3D11CreateDeviceAndSwapChain(nullptr, D3D_DRIVER_TYPE_WARP, nullptr, 0, levels, 2, D3D11_SDK_VERSION,
                                            &sd, &g_swapChain, &g_device, &level, &g_context);
    if (res != S_OK) return false;
    CreateRenderTarget();
    return true;
}

static void CleanupDeviceD3D() {
    CleanupRenderTarget();
    if (g_swapChain) { g_swapChain->Release(); g_swapChain = nullptr; }
    if (g_context) { g_context->Release(); g_context = nullptr; }
    if (g_device) { g_device->Release(); g_device = nullptr; }
}

// Saves the current back buffer as a 32-bit BMP (used by --capture).
static bool SaveBackBuffer(const std::wstring& path) {
    ID3D11Texture2D* backBuffer = nullptr;
    if (FAILED(g_swapChain->GetBuffer(0, IID_PPV_ARGS(&backBuffer)))) return false;
    D3D11_TEXTURE2D_DESC desc;
    backBuffer->GetDesc(&desc);
    desc.Usage = D3D11_USAGE_STAGING;
    desc.BindFlags = 0;
    desc.CPUAccessFlags = D3D11_CPU_ACCESS_READ;
    desc.MiscFlags = 0;
    ID3D11Texture2D* staging = nullptr;
    bool ok = false;
    if (SUCCEEDED(g_device->CreateTexture2D(&desc, nullptr, &staging))) {
        g_context->CopyResource(staging, backBuffer);
        D3D11_MAPPED_SUBRESOURCE mapped;
        if (SUCCEEDED(g_context->Map(staging, 0, D3D11_MAP_READ, 0, &mapped))) {
            const UINT w = desc.Width, h = desc.Height;
            std::vector<uint8_t> pixels(static_cast<size_t>(w) * h * 4);
            for (UINT y = 0; y < h; ++y) {
                const uint8_t* src = static_cast<const uint8_t*>(mapped.pData) + y * mapped.RowPitch;
                uint8_t* dst = pixels.data() + static_cast<size_t>(y) * w * 4;
                for (UINT x = 0; x < w; ++x) {  // RGBA -> BGRA
                    dst[x * 4 + 0] = src[x * 4 + 2];
                    dst[x * 4 + 1] = src[x * 4 + 1];
                    dst[x * 4 + 2] = src[x * 4 + 0];
                    dst[x * 4 + 3] = 255;
                }
            }
            g_context->Unmap(staging, 0);
            BITMAPINFOHEADER info{};
            info.biSize = sizeof(info);
            info.biWidth = static_cast<LONG>(w);
            info.biHeight = -static_cast<LONG>(h);  // top-down
            info.biPlanes = 1;
            info.biBitCount = 32;
            info.biCompression = BI_RGB;
            BITMAPFILEHEADER file{};
            file.bfType = 0x4D42;
            file.bfOffBits = sizeof(file) + sizeof(info);
            file.bfSize = file.bfOffBits + static_cast<DWORD>(pixels.size());
            std::ofstream out(fs::path(path), std::ios::binary);
            out.write(reinterpret_cast<const char*>(&file), sizeof(file));
            out.write(reinterpret_cast<const char*>(&info), sizeof(info));
            out.write(reinterpret_cast<const char*>(pixels.data()), static_cast<std::streamsize>(pixels.size()));
            ok = static_cast<bool>(out);
        }
        staging->Release();
    }
    backBuffer->Release();
    return ok;
}

// The app icon from the resources as a texture, for the header logo.
static ID3D11ShaderResourceView* LoadIconTexture(int size) {
    HICON icon = static_cast<HICON>(LoadImageW(GetModuleHandleW(nullptr), MAKEINTRESOURCEW(IDI_SYNFIN), IMAGE_ICON,
                                               size, size, LR_DEFAULTCOLOR));
    if (!icon) return nullptr;
    ICONINFO info{};
    GetIconInfo(icon, &info);
    std::vector<uint8_t> pixels(static_cast<size_t>(size) * size * 4);
    BITMAPINFO bmi{};
    bmi.bmiHeader.biSize = sizeof(bmi.bmiHeader);
    bmi.bmiHeader.biWidth = size;
    bmi.bmiHeader.biHeight = -size;
    bmi.bmiHeader.biPlanes = 1;
    bmi.bmiHeader.biBitCount = 32;
    bmi.bmiHeader.biCompression = BI_RGB;
    HDC dc = GetDC(nullptr);
    GetDIBits(dc, info.hbmColor, 0, size, pixels.data(), &bmi, DIB_RGB_COLORS);
    ReleaseDC(nullptr, dc);
    if (info.hbmColor) DeleteObject(info.hbmColor);
    if (info.hbmMask) DeleteObject(info.hbmMask);
    DestroyIcon(icon);
    for (size_t i = 0; i < pixels.size(); i += 4) std::swap(pixels[i], pixels[i + 2]);  // BGRA -> RGBA

    D3D11_TEXTURE2D_DESC desc{};
    desc.Width = desc.Height = static_cast<UINT>(size);
    desc.MipLevels = desc.ArraySize = 1;
    desc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
    desc.SampleDesc.Count = 1;
    desc.Usage = D3D11_USAGE_DEFAULT;
    desc.BindFlags = D3D11_BIND_SHADER_RESOURCE;
    D3D11_SUBRESOURCE_DATA data{pixels.data(), static_cast<UINT>(size * 4), 0};
    ID3D11Texture2D* texture = nullptr;
    ID3D11ShaderResourceView* view = nullptr;
    if (SUCCEEDED(g_device->CreateTexture2D(&desc, &data, &texture))) {
        g_device->CreateShaderResourceView(texture, nullptr, &view);
        texture->Release();
    }
    return view;
}

// ---------------------------------------------------------------------------------------
// Native dialogs

static std::vector<std::string> PickFiles(HWND owner, bool folders) {
    std::vector<std::string> out;
    IFileOpenDialog* dialog = nullptr;
    if (FAILED(CoCreateInstance(CLSID_FileOpenDialog, nullptr, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&dialog))))
        return out;
    DWORD options = 0;
    dialog->GetOptions(&options);
    if (folders) {
        dialog->SetOptions(options | FOS_PICKFOLDERS | FOS_FORCEFILESYSTEM);
        dialog->SetTitle(L"Select folder with captures");
    } else {
        dialog->SetOptions(options | FOS_ALLOWMULTISELECT | FOS_FILEMUSTEXIST | FOS_FORCEFILESYSTEM);
        dialog->SetTitle(L"Select capture files");
        const COMDLG_FILTERSPEC types[] = {{L"Captures (*.pcap, *.pcapng)", L"*.pcap;*.pcapng"}, {L"All files", L"*.*"}};
        dialog->SetFileTypes(2, types);
    }
    if (SUCCEEDED(dialog->Show(owner))) {
        IShellItemArray* items = nullptr;
        if (SUCCEEDED(dialog->GetResults(&items))) {
            DWORD count = 0;
            items->GetCount(&count);
            for (DWORD i = 0; i < count; ++i) {
                IShellItem* item = nullptr;
                PWSTR path = nullptr;
                if (SUCCEEDED(items->GetItemAt(i, &item)) && SUCCEEDED(item->GetDisplayName(SIGDN_FILESYSPATH, &path))) {
                    out.push_back(ToUtf8(path));
                    CoTaskMemFree(path);
                }
                if (item) item->Release();
            }
            items->Release();
        }
    }
    dialog->Release();
    return out;
}

static std::string PickSaveFile(HWND owner) {
    std::string out;
    IFileSaveDialog* dialog = nullptr;
    if (FAILED(CoCreateInstance(CLSID_FileSaveDialog, nullptr, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&dialog))))
        return out;
    const COMDLG_FILTERSPEC types[] = {{L"CSV (*.csv)", L"*.csv"}, {L"JSON Lines (*.jsonl)", L"*.jsonl"}};
    dialog->SetFileTypes(2, types);
    dialog->SetDefaultExtension(L"csv");
    dialog->SetFileName(L"sessions");
    dialog->SetTitle(L"Export sessions");
    if (SUCCEEDED(dialog->Show(owner))) {
        IShellItem* item = nullptr;
        PWSTR path = nullptr;
        if (SUCCEEDED(dialog->GetResult(&item)) && SUCCEEDED(item->GetDisplayName(SIGDN_FILESYSPATH, &path))) {
            out = ToUtf8(path);
            CoTaskMemFree(path);
        }
        if (item) item->Release();
    }
    dialog->Release();
    return out;
}

// ---------------------------------------------------------------------------------------
// The app

struct Row {
    SessionRecord record;
    int num;
    std::string src, dst, start, end, duration;
    int64_t durationMicros;
    std::string haystack;  // lower-case text the search box matches against
};

struct LogLine {
    std::string text;
    unsigned color;
};

class App {
public:
    HWND hwnd = nullptr;
    float scale = 1.0f;

    // Settings and inputs
    std::vector<std::string> files;
    std::vector<bool> fileSelected;
    int timeout = 600;
    int threads = static_cast<int>(std::max(1u, std::thread::hardware_concurrency()));
    char search[256] = "";

    // Automation (see the comment at the top of the file)
    std::wstring exportPath, capturePath;
    bool autoStart = false;
    bool initialSortDuration = false;
    int framesSinceFinish = -1;

    ImFont* fontRegular = nullptr;
    ImFont* fontBold = nullptr;
    ImFont* fontMono = nullptr;
    ID3D11ShaderResourceView* logo = nullptr;

    // ---- results ----
    std::vector<Row> rows;
    std::vector<int> view;  // indices into rows, filtered and sorted
    size_t counts[4] = {0, 0, 0, 0};
    int statusFilter = -1;  // index into kStatuses, or -1 for all
    int sortColumn = -1;    // ColumnId, or -1 for arrival order
    bool sortDescending = false;
    bool viewDirty = false;
    Clock::time_point lastSort;
    int selectedRow = -1;
    std::vector<LogLine> log;
    bool scrollLog = false;

    // ---- the running analysis ----
    std::unique_ptr<SessionAnalyzer> analyzer;
    std::thread worker;
    std::atomic<bool> workerDone{false};
    bool running = false, finished = false, stopped = false;
    Clock::time_point startedAt;
    double elapsed = 0;
    uint64_t totalBytes = 0;
    std::mutex incomingMutex;
    std::vector<SessionRecord> incoming;
    std::vector<LogLine> incomingLog;

    float logHeight = 0;  // height of the log card; 0 = not laid out yet

    enum ColumnId { ColStatus, ColNum, ColSrc, ColDst, ColStart, ColEnd, ColDuration };

    ~App() {
        if (worker.joinable()) {
            analyzer->Cancel();
            worker.join();
        }
    }

    float S(float v) const { return v * scale; }

    // ------------------------------------------------------------------ files

    void AddPaths(const std::vector<std::string>& paths) {
        for (const auto& given : paths) {
            std::error_code ec;
            fs::path path = fs::absolute(fs::u8path(given), ec);  // relative paths from the command line
            if (ec) path = fs::u8path(given);
            std::vector<std::string> expanded;
            if (fs::is_directory(path, ec)) {
                expanded = CapturesInFolder(path);
            } else {
                expanded.push_back(path.u8string());
            }
            for (const auto& f : expanded)
                if (std::find(files.begin(), files.end(), f) == files.end()) files.push_back(f);
        }
        fileSelected.assign(files.size(), false);
    }

    void AddFolder() {
        auto picked = PickFiles(hwnd, true);
        if (picked.empty()) return;
        auto found = CapturesInFolder(fs::u8path(picked[0]));
        if (found.empty()) {
            MessageBoxW(hwnd, (L"No .pcap or .pcapng files in " + ToWide(picked[0])).c_str(), L"No captures",
                        MB_ICONINFORMATION);
            return;
        }
        AddPaths(found);
    }

    void RemoveSelectedFiles() {
        std::vector<std::string> kept;
        for (size_t i = 0; i < files.size(); ++i)
            if (!fileSelected[i]) kept.push_back(files[i]);
        files = kept;
        fileSelected.assign(files.size(), false);
    }

    // ------------------------------------------------------------------ analysis

    void Log(const std::string& text, unsigned color = MUTED) {
        log.push_back({text, color});
        if (log.size() > 5000) log.erase(log.begin(), log.begin() + 1000);
        scrollLog = true;
    }

    void ClearResults() {
        rows.clear();
        view.clear();
        std::fill(std::begin(counts), std::end(counts), 0);
        selectedRow = -1;
        log.clear();
        finished = stopped = false;
    }

    void Start() {
        if (running) return;
        if (files.empty()) {
            MessageBoxW(hwnd, L"Add at least one capture file.", L"No captures", MB_ICONERROR);
            return;
        }
        timeout = std::max(1, timeout);
        threads = std::max(1, threads);
        ClearResults();
        totalBytes = 0;
        for (const auto& f : files) {
            std::error_code ec;
            uintmax_t size = fs::file_size(fs::u8path(f), ec);
            if (!ec) totalBytes += size;
        }
        Log("Analyzing " + std::to_string(files.size()) + " capture(s), timeout " + std::to_string(timeout) +
                " s, " + std::to_string(threads) + " thread(s)",
            ACCENT_HI);
        for (const auto& f : files) Log("  " + f);

        analyzer = std::make_unique<SessionAnalyzer>(timeout, static_cast<unsigned>(threads));
        analyzer->SetSessionSink([this](const SessionRecord& r) {
            std::lock_guard<std::mutex> lock(incomingMutex);
            incoming.push_back(r);
        });
        analyzer->SetMessageSink([this](const std::string& message) {
            std::lock_guard<std::mutex> lock(incomingMutex);
            incomingLog.push_back({message, Status(CloseReason::Rst).color});
        });
        workerDone = false;
        running = true;
        startedAt = Clock::now();
        std::vector<std::string> inputs = files;
        worker = std::thread([this, inputs] {
            analyzer->Start();
            for (const auto& f : inputs) {
                if (analyzer->Cancelled()) break;
                analyzer->AnalyzePcapFile(fs::u8path(f));
            }
            analyzer->Stop();
            workerDone = true;
        });
    }

    void Stop() {
        if (!running) return;
        analyzer->Cancel();
        stopped = true;
        Log("Stopped by user.", Status(CloseReason::Rst).color);
    }

    // Moves sessions from the analyzer into the table; called once per frame.
    void Pump() {
        std::vector<SessionRecord> batch;
        std::vector<LogLine> messages;
        {
            std::lock_guard<std::mutex> lock(incomingMutex);
            batch.swap(incoming);
            messages.swap(incomingLog);
        }
        for (auto& m : messages) Log(m.text, m.color);
        if (!batch.empty()) {
            rows.reserve(rows.size() + batch.size());
            for (const auto& r : batch) AddRow(r);
        }
        if (running && workerDone) {
            worker.join();
            running = false;
            finished = true;
            elapsed = std::chrono::duration<double>(Clock::now() - startedAt).count();
            viewDirty = true;
            if (!stopped) Log("Done: " + Grouped(rows.size()) + " sessions.", Status(CloseReason::Fin).color);
        }
        if (viewDirty && (!running || Clock::now() - lastSort > std::chrono::milliseconds(300))) RebuildView();
    }

    void AddRow(const SessionRecord& r) {
        Row row;
        row.record = r;
        row.num = static_cast<int>(rows.size()) + 1;
        row.src = SessionAnalyzer::FormatIp(r.src_ip) + ":" + std::to_string(r.src_port);
        row.dst = SessionAnalyzer::FormatIp(r.dst_ip) + ":" + std::to_string(r.dst_port);
        row.start = FormatTime(r.start, false);
        row.end = FormatTime(r.end, false);
        row.durationMicros = r.end.MicrosSince(r.start);
        char buf[48];
        std::snprintf(buf, sizeof(buf), "%lld.%06lld", static_cast<long long>(row.durationMicros / 1000000),
                      static_cast<long long>(row.durationMicros % 1000000));
        row.duration = buf;
        row.haystack = Lower(row.src + "\x1f" + row.dst + "\x1f" + row.start + "\x1f" + row.end + "\x1f" +
                             row.duration + "\x1f" + Status(r.reason).label);
        counts[static_cast<int>(r.reason)]++;
        rows.push_back(std::move(row));
        int index = static_cast<int>(rows.size()) - 1;
        if (sortColumn < 0) {
            if (Matches(rows[index])) view.push_back(index);
        } else {
            viewDirty = true;
        }
    }

    bool Matches(const Row& row) const {
        if (statusFilter >= 0 && row.record.reason != kStatuses[statusFilter].reason) return false;
        if (!search[0]) return true;
        std::string needle = Lower(search);
        size_t a = needle.find_first_not_of(' '), b = needle.find_last_not_of(' ');
        if (a == std::string::npos) return true;
        return row.haystack.find(needle.substr(a, b - a + 1)) != std::string::npos;
    }

    void RebuildView() {
        view.clear();
        for (int i = 0; i < static_cast<int>(rows.size()); ++i)
            if (Matches(rows[i])) view.push_back(i);
        if (sortColumn >= 0) {
            auto key = [this](int i, int j) {
                const Row& a = rows[i];
                const Row& b = rows[j];
                switch (sortColumn) {
                    case ColStatus: return std::string(Status(a.record.reason).label) < Status(b.record.reason).label;
                    case ColNum: return a.num < b.num;
                    case ColSrc:
                        return std::make_pair(a.record.src_ip, a.record.src_port) <
                               std::make_pair(b.record.src_ip, b.record.src_port);
                    case ColDst:
                        return std::make_pair(a.record.dst_ip, a.record.dst_port) <
                               std::make_pair(b.record.dst_ip, b.record.dst_port);
                    case ColStart: return a.record.start.MicrosSince(b.record.start) < 0;
                    case ColEnd: return a.record.end.MicrosSince(b.record.end) < 0;
                    default: return a.durationMicros < b.durationMicros;
                }
            };
            if (sortDescending)
                std::stable_sort(view.begin(), view.end(), [&](int i, int j) { return key(j, i); });
            else
                std::stable_sort(view.begin(), view.end(), key);
        }
        viewDirty = false;
        lastSort = Clock::now();
    }

    bool Export(const std::wstring& path) {
        std::ofstream out(fs::path(path), std::ios::binary);
        bool jsonl = Lower(ToUtf8(fs::path(path).extension().wstring())) == ".jsonl";
        if (jsonl) {
            for (const auto& row : rows) out << SessionAnalyzer::ToJson(row.record) << "\n";
        } else {
            out << "#,Source,Destination,Start,End,\"Duration, s\",Closed by\r\n";
            for (const auto& row : rows)
                out << row.num << ',' << CsvField(row.src) << ',' << CsvField(row.dst) << ','
                    << FormatTime(row.record.start, true) << ',' << FormatTime(row.record.end, true) << ','
                    << row.duration << ',' << CsvField(Status(row.record.reason).label) << "\r\n";
        }
        if (!out) {
            MessageBoxW(hwnd, (L"Cannot write " + path).c_str(), L"Export failed", MB_ICONERROR);
            return false;
        }
        Log("Exported " + Grouped(rows.size()) + " sessions to " + ToUtf8(path), Status(CloseReason::Fin).color);
        return true;
    }

    void ExportWithDialog() {
        if (rows.empty()) {
            MessageBoxW(hwnd, L"Run an analysis first.", L"Nothing to export", MB_ICONINFORMATION);
            return;
        }
        std::string path = PickSaveFile(hwnd);
        if (!path.empty()) Export(ToWide(path));
    }

    // ------------------------------------------------------------------ drawing helpers

    void Text(ImFont* font, float size, unsigned color, const char* text) {
        ImGui::PushFont(font, size);
        ImGui::PushStyleColor(ImGuiCol_Text, Rgb(color));
        ImGui::TextUnformatted(text);
        ImGui::PopStyleColor();
        ImGui::PopFont();
    }

    ImVec2 TextSize(ImFont* font, float size, const char* text) const {
        return font->CalcTextSizeA(S(size), FLT_MAX, 0.0f, text);
    }

    // A card: SURFACE background, 1 px border, 16 px padding, optional title.
    bool BeginCard(const char* id, const ImVec2& size, const char* title, ImGuiChildFlags extra = 0) {
        ImGui::PushStyleColor(ImGuiCol_ChildBg, Rgb(SURFACE));
        ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(S(16), S(14)));
        bool open = ImGui::BeginChild(id, size, ImGuiChildFlags_Borders | ImGuiChildFlags_AlwaysUseWindowPadding | extra,
                                      ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse);
        ImGui::PopStyleVar();
        ImGui::PopStyleColor();
        if (title) Text(fontBold, kH2, TEXT, title);
        return open;
    }

    void EndCard() { ImGui::EndChild(); }

    void FieldLabel(const char* text) { Text(fontBold, kLabel, MUTED, text); }

    // A filled pill with a colored dot and text, drawn at the cursor; returns its size.
    void Pill(const ImVec2& pos, const char* text, unsigned fg, bool dot, float fontSize, ImFont* font) {
        ImDrawList* dl = ImGui::GetWindowDrawList();
        ImVec2 ts = TextSize(font, fontSize, text);
        float padX = S(dot ? 12 : 8), padY = S(dot ? 5 : 2), dotW = dot ? S(14) : 0;
        ImVec2 size(ts.x + padX * 2 + dotW, ts.y + padY * 2);
        dl->AddRectFilled(pos, ImVec2(pos.x + size.x, pos.y + size.y), Rgb(RAISED));
        if (dot) {
            dl->AddRect(pos, ImVec2(pos.x + size.x, pos.y + size.y), Rgb(BORDER));
            dl->AddCircleFilled(ImVec2(pos.x + padX + S(4), pos.y + size.y / 2), S(4), Rgb(fg));
        }
        dl->AddText(font, S(fontSize), ImVec2(pos.x + padX + dotW, pos.y + padY), Rgb(fg), text);
    }

    bool AccentButton(const char* label, const ImVec2& size, bool enabled) {
        ImGui::PushFont(fontBold, kBase);
        if (enabled) {
            ImGui::PushStyleColor(ImGuiCol_Button, Rgb(ACCENT));
            ImGui::PushStyleColor(ImGuiCol_ButtonHovered, Rgb(ACCENT_HI));
            ImGui::PushStyleColor(ImGuiCol_ButtonActive, Rgb(ACCENT_LO));
            ImGui::PushStyleColor(ImGuiCol_Border, Rgb(ACCENT));
            ImGui::PushStyleColor(ImGuiCol_Text, Rgb(WHITE));
        } else {
            ImGui::PushStyleColor(ImGuiCol_Button, Rgb(RAISED));
            ImGui::PushStyleColor(ImGuiCol_ButtonHovered, Rgb(RAISED));
            ImGui::PushStyleColor(ImGuiCol_ButtonActive, Rgb(RAISED));
            ImGui::PushStyleColor(ImGuiCol_Border, Rgb(BORDER));
            ImGui::PushStyleColor(ImGuiCol_Text, Rgb(FAINT));
        }
        ImGui::BeginDisabled(!enabled);
        bool clicked = ImGui::Button(label, size);
        ImGui::EndDisabled();
        ImGui::PopStyleColor(5);
        ImGui::PopFont();
        return clicked;
    }

    bool StopButton(const char* label, const ImVec2& size, bool enabled) {
        const unsigned red = Status(CloseReason::Rst).color;
        ImGui::PushFont(fontBold, kBase);
        ImGui::PushStyleColor(ImGuiCol_Button, Rgb(enabled ? RAISED : SURFACE));
        ImGui::PushStyleColor(ImGuiCol_ButtonHovered, Rgb(HOVER));
        ImGui::PushStyleColor(ImGuiCol_ButtonActive, Rgb(BORDER));
        ImGui::PushStyleColor(ImGuiCol_Text, Rgb(enabled ? red : FAINT));
        ImGui::BeginDisabled(!enabled);
        bool clicked = ImGui::Button(label, size);
        if (enabled && ImGui::IsItemHovered())
            ImGui::GetWindowDrawList()->AddRect(ImGui::GetItemRectMin(), ImGui::GetItemRectMax(), Rgb(red));
        ImGui::EndDisabled();
        ImGui::PopStyleColor(4);
        ImGui::PopFont();
        return clicked;
    }

    // ------------------------------------------------------------------ frame

    void Frame() {
        Pump();
        const ImGuiViewport* vp = ImGui::GetMainViewport();
        ImGui::SetNextWindowPos(vp->WorkPos);
        ImGui::SetNextWindowSize(vp->WorkSize);
        ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(0, 0));
        ImGui::PushStyleColor(ImGuiCol_WindowBg, Rgb(BG));
        ImGui::Begin("SynFin", nullptr,
                     ImGuiWindowFlags_NoDecoration | ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoSavedSettings |
                         ImGuiWindowFlags_NoBringToFrontOnFocus | ImGuiWindowFlags_NoScrollWithMouse);
        ImGui::PopStyleColor();
        ImGui::PopStyleVar();

        const ImVec2 origin = ImGui::GetWindowPos();
        const ImVec2 full = ImGui::GetWindowSize();
        const float footerH = S(30);
        const float headerH = DrawHeader(origin, full.x);

        // Body: sidebar + main column
        const float pad = S(24), gap = S(18);
        const float bodyTop = origin.y + headerH;
        const float bodyH = full.y - headerH - footerH - S(18);
        const float sidebarW = S(310);
        ImGui::SetCursorScreenPos(ImVec2(origin.x + pad, bodyTop));
        DrawSidebar(ImVec2(sidebarW, bodyH));
        ImGui::SetCursorScreenPos(ImVec2(origin.x + pad + sidebarW + gap, bodyTop));
        DrawMain(ImVec2(full.x - pad * 2 - sidebarW - gap, bodyH));
        DrawFooter(ImVec2(origin.x, origin.y + full.y - footerH), ImVec2(full.x, footerH));

        ImGui::End();
    }

    float DrawHeader(const ImVec2& origin, float width) {
        ImDrawList* dl = ImGui::GetWindowDrawList();
        const float top = origin.y + S(18), left = origin.x + S(24);
        float x = left;
        const float logoSize = S(48);
        if (logo) {
            dl->AddImage(static_cast<ImTextureID>(reinterpret_cast<intptr_t>(logo)), ImVec2(x, top),
                         ImVec2(x + logoSize, top + logoSize));
            x += logoSize + S(12);
        }
        ImVec2 titleSize = TextSize(fontBold, kTitle, "SynFin");
        ImVec2 subSize = TextSize(fontRegular, kBase, "Ag");
        float textTop = top + (logoSize - titleSize.y - subSize.y) / 2;
        dl->AddText(fontBold, S(kTitle), ImVec2(x, textTop), Rgb(TEXT), "SynFin");
        dl->AddText(fontRegular, S(kBase), ImVec2(x, textTop + titleSize.y), Rgb(MUTED),
                    "TCP sessions from SYN to FIN, reconstructed from .pcap captures");

        std::string version = std::string("synfin ") + SYNFIN_VERSION;
        ImVec2 vs = TextSize(fontRegular, kSmall, version.c_str());
        float pillW = vs.x + S(12) * 2 + S(14), pillH = vs.y + S(5) * 2;
        Pill(ImVec2(origin.x + width - S(24) - pillW, top + (logoSize - pillH) / 2), version.c_str(),
             Status(CloseReason::Fin).color, true, kSmall, fontRegular);
        return logoSize + S(18) + S(14);
    }

    void DrawSidebar(const ImVec2& size) {
        const ImVec2 start = ImGui::GetCursorScreenPos();
        const float gap = S(16);
        const float buttonH = S(42);
        const float progressH = running ? S(14) : 0;
        const float frameH = ImGui::GetFrameHeight();
        const float settingsH = S(14) + S(kH2) * 1.25f + S(10) + S(kLabel) * 1.3f + S(4) + frameH + S(16);
        const float capturesH = size.y - settingsH - gap - buttonH - gap - progressH;

        // Captures
        ImGui::SetCursorScreenPos(start);
        BeginCard("##captures", ImVec2(size.x, capturesH), "Captures");
        {
            std::string badge = Grouped(files.size()) + (files.size() == 1 ? " FILE" : " FILES");
            ImVec2 bs = TextSize(fontBold, kLabel, badge.c_str());
            ImVec2 win = ImGui::GetWindowPos();
            Pill(ImVec2(win.x + ImGui::GetWindowWidth() - S(16) - bs.x - S(16), win.y + S(14) + S(1)),
                 badge.c_str(), MUTED, false, kLabel, fontBold);

            ImGui::Dummy(ImVec2(0, S(2)));
            const float buttonsH = frameH * 2 + S(8) + S(10);
            const float listH = ImGui::GetContentRegionAvail().y - buttonsH;
            ImGui::PushStyleColor(ImGuiCol_ChildBg, Rgb(RAISED));
            ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(S(6), S(6)));
            ImGui::BeginChild("##files", ImVec2(0, listH), ImGuiChildFlags_Borders | ImGuiChildFlags_AlwaysUseWindowPadding);
            ImGui::PopStyleVar();
            if (files.empty()) {
                const char* l1 = "No captures yet";
                const char* l2 = "Add .pcap / .pcapng files or a folder";
                ImVec2 a = TextSize(fontRegular, kSmall, l1), b = TextSize(fontRegular, kSmall, l2);
                ImVec2 w = ImGui::GetWindowPos(), ws = ImGui::GetWindowSize();
                float y = w.y + (ws.y - a.y - b.y) / 2;
                ImDrawList* dl = ImGui::GetWindowDrawList();
                dl->AddText(fontRegular, S(kSmall), ImVec2(w.x + (ws.x - a.x) / 2, y), Rgb(FAINT), l1);
                dl->AddText(fontRegular, S(kSmall), ImVec2(w.x + (ws.x - b.x) / 2, y + a.y), Rgb(FAINT), l2);
            } else {
                ImGui::PushFont(fontRegular, kSmall);
                static int anchor = -1;
                for (int i = 0; i < static_cast<int>(files.size()); ++i) {
                    fs::path p = fs::u8path(files[i]);
                    std::string label = p.filename().u8string() + "   \xC2\xB7   " + p.parent_path().u8string() +
                                        "##f" + std::to_string(i);
                    if (ImGui::Selectable(label.c_str(), fileSelected[i])) {
                        ImGuiIO& io = ImGui::GetIO();
                        if (io.KeyShift && anchor >= 0) {
                            for (int k = 0; k < static_cast<int>(files.size()); ++k)
                                fileSelected[k] = (k >= std::min(anchor, i) && k <= std::max(anchor, i));
                        } else if (io.KeyCtrl) {
                            fileSelected[i] = !fileSelected[i];
                            anchor = i;
                        } else {
                            fileSelected.assign(files.size(), false);
                            fileSelected[i] = true;
                            anchor = i;
                        }
                    }
                }
                ImGui::PopFont();
                if (ImGui::IsWindowFocused() && ImGui::IsKeyPressed(ImGuiKey_Delete)) RemoveSelectedFiles();
            }
            ImGui::EndChild();
            ImGui::PopStyleColor();

            ImGui::Dummy(ImVec2(0, S(2)));
            const float half = (ImGui::GetContentRegionAvail().x - S(8)) / 2;
            if (ImGui::Button("Add files\xE2\x80\xA6", ImVec2(half, 0))) AddPaths(PickFiles(hwnd, false));
            ImGui::SameLine(0, S(8));
            if (ImGui::Button("Add folder\xE2\x80\xA6", ImVec2(half, 0))) AddFolder();
            if (ImGui::Button("Remove", ImVec2(half, 0))) RemoveSelectedFiles();
            ImGui::SameLine(0, S(8));
            if (ImGui::Button("Clear", ImVec2(half, 0))) {
                files.clear();
                fileSelected.clear();
            }
        }
        EndCard();

        // Settings
        ImGui::SetCursorScreenPos(ImVec2(start.x, start.y + capturesH + gap));
        BeginCard("##settings", ImVec2(size.x, settingsH), "Settings");
        {
            ImGui::Dummy(ImVec2(0, S(2)));
            const float half = (ImGui::GetContentRegionAvail().x - S(8)) / 2;
            const float x0 = ImGui::GetCursorPosX();
            FieldLabel("TIMEOUT, S");
            ImGui::SameLine(x0 + half + S(8));
            FieldLabel("THREADS");
            ImGui::SetNextItemWidth(half);
            ImGui::BeginDisabled(running);
            if (ImGui::InputInt("##timeout", &timeout, 60, 600)) timeout = std::clamp(timeout, 1, 86400);
            ImGui::SameLine(x0 + half + S(8));
            ImGui::SetNextItemWidth(half);
            if (ImGui::InputInt("##threads", &threads, 1, 4)) threads = std::clamp(threads, 1, 256);
            ImGui::EndDisabled();
        }
        EndCard();

        // Analyze / Stop and the progress bar
        const float actionsTop = start.y + capturesH + gap + settingsH + gap;
        const float half = (size.x - S(8)) / 2;
        ImGui::SetCursorScreenPos(ImVec2(start.x, actionsTop));
        if (AccentButton("\xE2\x96\xB6  Analyze", ImVec2(half, buttonH), !running)) Start();
        ImGui::SameLine(0, S(8));
        if (StopButton("\xE2\x96\xA0  Stop", ImVec2(half, buttonH), running)) Stop();
        if (running) {
            ImDrawList* dl = ImGui::GetWindowDrawList();
            ImVec2 a(start.x, actionsTop + buttonH + S(10)), b(start.x + size.x, actionsTop + buttonH + S(14));
            dl->AddRectFilled(a, b, Rgb(RAISED));
            double fraction = totalBytes ? static_cast<double>(analyzer->BytesProcessed()) / totalBytes : 0.0;
            fraction = std::clamp(fraction, 0.0, 1.0);
            dl->AddRectFilled(a, ImVec2(a.x + static_cast<float>((b.x - a.x) * fraction), b.y), Rgb(ACCENT));
        }
    }

    void DrawMain(const ImVec2& size) {
        const ImVec2 start = ImGui::GetCursorScreenPos();
        const float tileH = S(14) + S(kLabel) * 1.3f + S(2) + S(kStat) * 1.25f + S(12);
        DrawTiles(start, size.x, tileH);

        const float gap = S(16), splitter = S(12);
        const float areaTop = start.y + tileH + gap;
        const float areaH = size.y - tileH - gap;
        if (logHeight <= 0) logHeight = std::max(S(150), areaH / 5);
        logHeight = std::clamp(logHeight, S(90), std::max(S(90), areaH - S(200)));
        const float sessionsH = areaH - splitter - logHeight;

        ImGui::SetCursorScreenPos(ImVec2(start.x, areaTop));
        DrawSessions(ImVec2(size.x, sessionsH));

        // Draggable gap between the sessions and the log (like the Linux pane sash)
        ImGui::SetCursorScreenPos(ImVec2(start.x, areaTop + sessionsH));
        ImGui::InvisibleButton("##splitter", ImVec2(size.x, splitter));
        if (ImGui::IsItemHovered() || ImGui::IsItemActive()) ImGui::SetMouseCursor(ImGuiMouseCursor_ResizeNS);
        if (ImGui::IsItemActive()) logHeight -= ImGui::GetIO().MouseDelta.y;

        ImGui::SetCursorScreenPos(ImVec2(start.x, areaTop + sessionsH + splitter));
        DrawLog(ImVec2(size.x, logHeight));
    }

    void DrawTiles(const ImVec2& start, float width, float height) {
        const float gap = S(12);
        const float tileW = (width - gap * 4) / 5;
        ImDrawList* dl = ImGui::GetWindowDrawList();
        for (int i = -1; i < 4; ++i) {
            ImVec2 a(start.x + (i + 1) * (tileW + gap), start.y);
            ImVec2 b(a.x + tileW, a.y + height);
            ImGui::SetCursorScreenPos(a);
            ImGui::PushID(i);
            if (ImGui::InvisibleButton("##tile", ImVec2(tileW, height))) {
                statusFilter = (i < 0 || statusFilter == i) ? -1 : i;
                viewDirty = true;
                RebuildView();
            }
            if (ImGui::IsItemHovered()) ImGui::SetMouseCursor(ImGuiMouseCursor_Hand);
            ImGui::PopID();
            const bool selected = i >= 0 && statusFilter == i;
            const unsigned color = i < 0 ? TEXT : kStatuses[i].color;
            dl->AddRectFilled(a, b, Rgb(SURFACE));
            dl->AddRect(a, b, Rgb(selected ? color : (ImGui::IsItemHovered() ? BORDER_HI : BORDER)));

            float x = a.x + S(16), y = a.y + S(14);
            const char* caption = i < 0 ? "SESSIONS" : nullptr;
            std::string upper;
            if (i >= 0) {
                upper = kStatuses[i].label;
                for (char& c : upper) c = static_cast<char>(toupper(static_cast<unsigned char>(c)));
                caption = upper.c_str();
                dl->AddCircleFilled(ImVec2(x + S(4), y + S(kLabel) * 0.62f), S(4), Rgb(color));
                x += S(14);
            }
            dl->AddText(fontBold, S(kLabel), ImVec2(x, y), Rgb(MUTED), caption);
            size_t count = i < 0 ? rows.size() : counts[static_cast<int>(kStatuses[i].reason)];
            std::string number = Grouped(count);
            dl->AddText(fontBold, S(kStat), ImVec2(a.x + S(16), y + S(kLabel) * 1.3f + S(2)), Rgb(color),
                        number.c_str());
        }
    }

    void DrawSessions(const ImVec2& size) {
        BeginCard("##sessions", size, nullptr);
        // Header row: title, count, search, export
        {
            const float rowH = ImGui::GetFrameHeight();
            const float y0 = ImGui::GetCursorPosY();
            ImGui::SetCursorPosY(y0 + (rowH - S(kH2)) / 2 - S(1));
            Text(fontBold, kH2, TEXT, "Sessions");
            ImGui::SameLine(0, S(10));
            ImGui::SetCursorPosY(y0 + (rowH - S(kSmall)) / 2);
            std::string shown = "showing " + Grouped(view.size()) + " of " + Grouped(rows.size());
            Text(fontRegular, kSmall, MUTED, shown.c_str());

            const float exportW = TextSize(fontRegular, kBase, "Export\xE2\x80\xA6").x + S(32);
            const float searchW = S(320);
            ImGui::SameLine();
            ImGui::SetCursorPosX(ImGui::GetCursorPosX() + ImGui::GetContentRegionAvail().x - exportW - S(8) - searchW);
            ImGui::SetCursorPosY(y0);
            ImGui::SetNextItemWidth(searchW);
            ImGui::PushStyleColor(ImGuiCol_TextDisabled, Rgb(FAINT));
            if (ImGui::InputTextWithHint("##search", "Filter by IP, port, date or status", search, sizeof(search)))
                RebuildView();
            ImGui::PopStyleColor();
            ImGui::SameLine(0, S(8));
            ImGui::SetCursorPosY(y0);
            if (ImGui::Button("Export\xE2\x80\xA6", ImVec2(exportW, 0))) ExportWithDialog();
            ImGui::Dummy(ImVec2(0, S(4)));
        }

        const ImGuiTableFlags flags = ImGuiTableFlags_Sortable | ImGuiTableFlags_SortTristate |
                                      ImGuiTableFlags_RowBg | ImGuiTableFlags_BordersOuter |
                                      ImGuiTableFlags_ScrollY | ImGuiTableFlags_Resizable |
                                      ImGuiTableFlags_SizingFixedFit;
        ImGui::PushStyleVar(ImGuiStyleVar_CellPadding, ImVec2(S(8), (S(28) - S(kBase)) / 2));
        if (ImGui::BeginTable("##table", 7, flags, ImGui::GetContentRegionAvail())) {
            ImGui::TableSetupScrollFreeze(0, 1);
            // Fixed widths exclude the cell padding (8 px on each side).
            ImGui::TableSetupColumn("CLOSED BY", ImGuiTableColumnFlags_WidthFixed, S(94), ColStatus);
            ImGui::TableSetupColumn("#", ImGuiTableColumnFlags_WidthFixed, S(36), ColNum);
            ImGui::TableSetupColumn("SOURCE", ImGuiTableColumnFlags_WidthStretch, 1.0f, ColSrc);
            ImGui::TableSetupColumn("DESTINATION", ImGuiTableColumnFlags_WidthStretch, 1.0f, ColDst);
            ImGui::TableSetupColumn("START", ImGuiTableColumnFlags_WidthFixed, S(162), ColStart);
            ImGui::TableSetupColumn("END", ImGuiTableColumnFlags_WidthFixed, S(162), ColEnd);
            ImGuiTableColumnFlags durationFlags = ImGuiTableColumnFlags_WidthFixed | ImGuiTableColumnFlags_PreferSortDescending;
            if (initialSortDuration) durationFlags |= ImGuiTableColumnFlags_DefaultSort;
            ImGui::TableSetupColumn("DURATION, S", durationFlags, S(96), ColDuration);

            if (ImGuiTableSortSpecs* specs = ImGui::TableGetSortSpecs()) {
                if (specs->SpecsDirty) {
                    if (specs->SpecsCount > 0) {
                        sortColumn = static_cast<int>(specs->Specs[0].ColumnUserID);
                        sortDescending = specs->Specs[0].SortDirection == ImGuiSortDirection_Descending;
                    } else {
                        sortColumn = -1;
                    }
                    specs->SpecsDirty = false;
                    RebuildView();
                }
            }

            ImGui::PushFont(fontBold, kLabel);
            ImGui::PushStyleVar(ImGuiStyleVar_CellPadding, ImVec2(S(8), S(8)));
            ImGui::PushStyleColor(ImGuiCol_Text, Rgb(MUTED));
            ImGui::TableHeadersRow();
            ImGui::PopStyleColor();
            ImGui::PopStyleVar();
            ImGui::PopFont();

            ImGui::PushFont(fontRegular, kBase);
            ImGuiListClipper clipper;
            clipper.Begin(static_cast<int>(view.size()), S(28));
            while (clipper.Step()) {
                for (int v = clipper.DisplayStart; v < clipper.DisplayEnd; ++v) {
                    const Row& row = rows[view[v]];
                    ImGui::TableNextRow(0, S(28));
                    ImGui::TableSetColumnIndex(0);
                    ImGui::PushID(view[v]);
                    const ImVec2 cell = ImGui::GetCursorScreenPos();
                    if (ImGui::Selectable("##row", selectedRow == view[v],
                                          ImGuiSelectableFlags_SpanAllColumns | ImGuiSelectableFlags_AllowOverlap,
                                          ImVec2(0, S(kBase))))
                        selectedRow = view[v];
                    ImGui::PopID();
                    const StatusInfo& st = Status(row.record.reason);
                    ImDrawList* dl = ImGui::GetWindowDrawList();
                    dl->AddCircleFilled(ImVec2(cell.x + S(5), cell.y + S(kBase) * 0.55f), S(4.5f), Rgb(st.color));
                    dl->AddText(fontRegular, S(kBase), ImVec2(cell.x + S(20), cell.y), Rgb(TEXT), st.label);
                    ImGui::TableSetColumnIndex(1);
                    ImGui::Text("%d", row.num);
                    ImGui::TableSetColumnIndex(2);
                    ImGui::TextUnformatted(row.src.c_str());
                    ImGui::TableSetColumnIndex(3);
                    ImGui::TextUnformatted(row.dst.c_str());
                    ImGui::TableSetColumnIndex(4);
                    ImGui::TextUnformatted(row.start.c_str());
                    ImGui::TableSetColumnIndex(5);
                    ImGui::TextUnformatted(row.end.c_str());
                    ImGui::TableSetColumnIndex(6);
                    ImGui::TextUnformatted(row.duration.c_str());
                }
            }
            ImGui::PopFont();
            ImGui::EndTable();
        }
        ImGui::PopStyleVar();
        EndCard();
    }

    void DrawLog(const ImVec2& size) {
        BeginCard("##log", size, "Log");
        ImGui::Dummy(ImVec2(0, S(2)));
        ImGui::PushStyleColor(ImGuiCol_ChildBg, Rgb(SURFACE));
        ImGui::BeginChild("##loglines", ImVec2(0, 0), 0, ImGuiWindowFlags_HorizontalScrollbar);
        ImGui::PushFont(fontMono, kMono);
        for (const auto& line : log) {
            ImGui::PushStyleColor(ImGuiCol_Text, Rgb(line.color));
            ImGui::TextUnformatted(line.text.c_str());
            ImGui::PopStyleColor();
        }
        ImGui::PopFont();
        if (scrollLog) {
            ImGui::SetScrollHereY(1.0f);
            scrollLog = false;
        }
        ImGui::EndChild();
        ImGui::PopStyleColor();
        EndCard();
    }

    void DrawFooter(const ImVec2& pos, const ImVec2& size) {
        ImDrawList* dl = ImGui::GetWindowDrawList();
        dl->AddRectFilled(pos, ImVec2(pos.x + size.x, pos.y + size.y), Rgb(SURFACE));
        dl->AddLine(pos, ImVec2(pos.x + size.x, pos.y), Rgb(BORDER));
        unsigned dot = FAINT;
        std::string text = "Ready";
        char buf[160];
        if (running) {
            double seconds = std::chrono::duration<double>(Clock::now() - startedAt).count();
            std::snprintf(buf, sizeof(buf), "Analyzing %zu capture(s)\xE2\x80\xA6   %.1f s", files.size(), seconds);
            dot = ACCENT;
            text = buf;
        } else if (finished) {
            std::snprintf(buf, sizeof(buf), "%s %.1f s   \xC2\xB7   %s sessions", stopped ? "Stopped after" : "Done in",
                          elapsed, Grouped(rows.size()).c_str());
            dot = stopped ? Status(CloseReason::Rst).color : Status(CloseReason::Fin).color;
            text = buf;
        }
        const float y = pos.y + (size.y - S(kSmall)) / 2;
        dl->AddCircleFilled(ImVec2(pos.x + S(20), y + S(kSmall) * 0.55f), S(4), Rgb(dot));
        dl->AddText(fontRegular, S(kSmall), ImVec2(pos.x + S(32), y), Rgb(MUTED), text.c_str());
    }
};

// ---------------------------------------------------------------------------------------
// Style

static void ApplyStyle(float scale) {
    ImGuiStyle& style = ImGui::GetStyle();
    style = ImGuiStyle();
    style.WindowRounding = style.ChildRounding = style.FrameRounding = style.PopupRounding = 0;
    style.ScrollbarRounding = style.GrabRounding = style.TabRounding = 0;
    style.WindowBorderSize = 0;
    style.ChildBorderSize = 1;
    style.FrameBorderSize = 1;
    style.FramePadding = ImVec2(8, 7);
    style.ItemSpacing = ImVec2(8, 8);
    style.ItemInnerSpacing = ImVec2(6, 6);
    style.ScrollbarSize = 10;
    style.GrabMinSize = 24;
    style.DisabledAlpha = 1.0f;  // disabled widgets get their own colors instead of fading
    style.SelectableTextAlign = ImVec2(0, 0.5f);
    style.ScaleAllSizes(scale);
    style.FontSizeBase = kBase;
    style.FontScaleDpi = scale;

    ImVec4* c = style.Colors;
    c[ImGuiCol_Text] = RgbV(TEXT);
    c[ImGuiCol_TextDisabled] = RgbV(FAINT);
    c[ImGuiCol_WindowBg] = RgbV(BG);
    c[ImGuiCol_ChildBg] = RgbV(SURFACE);
    c[ImGuiCol_PopupBg] = RgbV(RAISED);
    c[ImGuiCol_Border] = RgbV(BORDER);
    c[ImGuiCol_BorderShadow] = ImVec4(0, 0, 0, 0);
    c[ImGuiCol_FrameBg] = RgbV(RAISED);
    c[ImGuiCol_FrameBgHovered] = RgbV(HOVER);
    c[ImGuiCol_FrameBgActive] = RgbV(HOVER);
    c[ImGuiCol_Button] = RgbV(RAISED);
    c[ImGuiCol_ButtonHovered] = RgbV(HOVER);
    c[ImGuiCol_ButtonActive] = RgbV(BORDER);
    c[ImGuiCol_Header] = RgbV(SELECT);
    c[ImGuiCol_HeaderHovered] = ImGui::ColorConvertU32ToFloat4(Rgb(SELECT, 0.45f));
    c[ImGuiCol_HeaderActive] = RgbV(SELECT);
    c[ImGuiCol_TableHeaderBg] = RgbV(RAISED);
    c[ImGuiCol_TableBorderStrong] = RgbV(BORDER);
    c[ImGuiCol_TableBorderLight] = RgbV(BORDER);
    c[ImGuiCol_TableRowBg] = RgbV(SURFACE);
    c[ImGuiCol_TableRowBgAlt] = RgbV(ROW_ALT);
    c[ImGuiCol_ScrollbarBg] = RgbV(SURFACE);
    c[ImGuiCol_ScrollbarGrab] = RgbV(BORDER);
    c[ImGuiCol_ScrollbarGrabHovered] = RgbV(BORDER_HI);
    c[ImGuiCol_ScrollbarGrabActive] = RgbV(BORDER_HI);
    c[ImGuiCol_Separator] = RgbV(BORDER);
    c[ImGuiCol_SeparatorHovered] = RgbV(BORDER_HI);
    c[ImGuiCol_SeparatorActive] = RgbV(ACCENT);
    c[ImGuiCol_ResizeGrip] = ImVec4(0, 0, 0, 0);
    c[ImGuiCol_TextSelectedBg] = RgbV(SELECT);
    c[ImGuiCol_NavCursor] = RgbV(ACCENT);
    c[ImGuiCol_CheckMark] = RgbV(ACCENT);
}

static ImFont* LoadFontResource(int id, const char* name) {
    HRSRC res = FindResourceW(nullptr, MAKEINTRESOURCEW(id), MAKEINTRESOURCEW(10) /* RT_RCDATA */);
    if (!res) return nullptr;
    const void* data = LockResource(LoadResource(nullptr, res));
    int size = static_cast<int>(SizeofResource(nullptr, res));
    ImFontConfig config;
    config.FontDataOwnedByAtlas = false;  // the data lives in the exe
    std::snprintf(config.Name, sizeof(config.Name), "%s", name);
    return ImGui::GetIO().Fonts->AddFontFromMemoryTTF(const_cast<void*>(data), size, kBase, &config);
}

// ---------------------------------------------------------------------------------------
// Window

static App* g_app = nullptr;

static void SetDarkTitleBar(HWND hwnd) {
    BOOL dark = TRUE;
    if (FAILED(DwmSetWindowAttribute(hwnd, 20 /* DWMWA_USE_IMMERSIVE_DARK_MODE */, &dark, sizeof(dark))))
        DwmSetWindowAttribute(hwnd, 19 /* the same, before Windows 10 20H1 */, &dark, sizeof(dark));
    COLORREF caption = RGB(0x0d, 0x11, 0x17);  // Windows 11: caption in the app's background color
    DwmSetWindowAttribute(hwnd, 35 /* DWMWA_CAPTION_COLOR */, &caption, sizeof(caption));
}

static LRESULT WINAPI WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    if (ImGui_ImplWin32_WndProcHandler(hwnd, msg, wParam, lParam)) return true;
    switch (msg) {
        case WM_SIZE:
            if (wParam != SIZE_MINIMIZED) {
                g_resizeWidth = LOWORD(lParam);
                g_resizeHeight = HIWORD(lParam);
            }
            return 0;
        case WM_GETMINMAXINFO: {
            float scale = g_app ? g_app->scale : 1.0f;
            auto* info = reinterpret_cast<MINMAXINFO*>(lParam);
            info->ptMinTrackSize.x = static_cast<LONG>(1100 * scale);
            info->ptMinTrackSize.y = static_cast<LONG>(680 * scale);
            // Allow a window larger than the screen (--size and --capture on small CI desktops).
            info->ptMaxTrackSize.x = info->ptMaxTrackSize.y = 16384;
            return 0;
        }
        case WM_DPICHANGED: {
            if (g_app) {
                g_app->scale = HIWORD(wParam) / 96.0f;
                ApplyStyle(g_app->scale);
                if (g_app->logo) g_app->logo->Release();
                g_app->logo = LoadIconTexture(static_cast<int>(48 * g_app->scale));
                g_app->logHeight = 0;
            }
            const RECT* r = reinterpret_cast<RECT*>(lParam);
            SetWindowPos(hwnd, nullptr, r->left, r->top, r->right - r->left, r->bottom - r->top,
                         SWP_NOZORDER | SWP_NOACTIVATE);
            return 0;
        }
        case WM_DROPFILES: {
            HDROP drop = reinterpret_cast<HDROP>(wParam);
            std::vector<std::string> paths;
            UINT count = DragQueryFileW(drop, 0xFFFFFFFF, nullptr, 0);
            for (UINT i = 0; i < count; ++i) {
                UINT length = DragQueryFileW(drop, i, nullptr, 0);
                std::wstring path(length, L'\0');
                DragQueryFileW(drop, i, &path[0], length + 1);
                paths.push_back(ToUtf8(path));
            }
            DragFinish(drop);
            if (g_app) g_app->AddPaths(paths);
            return 0;
        }
        case WM_SYSCOMMAND:
            if ((wParam & 0xfff0) == SC_KEYMENU) return 0;  // no window menu on Alt
            break;
        case WM_DESTROY:
            PostQuitMessage(0);
            return 0;
    }
    return DefWindowProcW(hwnd, msg, wParam, lParam);
}

int WINAPI wWinMain(HINSTANCE instance, HINSTANCE, PWSTR, int) {
    ImGui_ImplWin32_EnableDpiAwareness();
    CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE);

    App app;
    g_app = &app;

    // Command line
    int argc = 0;
    LPWSTR* argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    std::vector<std::string> inputs;
    int statusFilter = -1;
    bool sortDuration = false;
    int width = 1360, height = 840;
    for (int i = 1; i < argc; ++i) {
        std::wstring arg = argv[i];
        auto next = [&]() { return i + 1 < argc ? std::wstring(argv[++i]) : std::wstring(); };
        if (arg == L"--export") app.exportPath = next();
        else if (arg == L"--capture") app.capturePath = next();
        else if (arg == L"--status-filter") {
            std::string key = ToUtf8(next());
            for (int k = 0; k < 4; ++k)
                if (key == kStatuses[k].key) statusFilter = k;
        } else if (arg == L"--sort-duration") sortDuration = true;
        else if (arg == L"--timeout") app.timeout = _wtoi(next().c_str());
        else if (arg == L"--threads") app.threads = _wtoi(next().c_str());
        else if (arg == L"--size") {
            std::wstring value = next();
            size_t x = value.find(L'x');
            if (x != std::wstring::npos) {
                width = _wtoi(value.substr(0, x).c_str());
                height = _wtoi(value.substr(x + 1).c_str());
            }
        }
        else inputs.push_back(ToUtf8(arg));
    }
    LocalFree(argv);

    WNDCLASSEXW wc{};
    wc.cbSize = sizeof(wc);
    wc.style = CS_CLASSDC;
    wc.lpfnWndProc = WndProc;
    wc.hInstance = instance;
    wc.hIcon = LoadIconW(instance, MAKEINTRESOURCEW(IDI_SYNFIN));
    wc.hIconSm = static_cast<HICON>(LoadImageW(instance, MAKEINTRESOURCEW(IDI_SYNFIN), IMAGE_ICON,
                                               GetSystemMetrics(SM_CXSMICON), GetSystemMetrics(SM_CYSMICON), 0));
    wc.hCursor = LoadCursorW(nullptr, MAKEINTRESOURCEW(32512) /* IDC_ARROW */);
    wc.lpszClassName = L"SynFinWindow";
    RegisterClassExW(&wc);

    app.scale = ImGui_ImplWin32_GetDpiScaleForMonitor(MonitorFromPoint(POINT{0, 0}, MONITOR_DEFAULTTOPRIMARY));
    RECT rect{0, 0, static_cast<LONG>(width * app.scale), static_cast<LONG>(height * app.scale)};
    AdjustWindowRectEx(&rect, WS_OVERLAPPEDWINDOW, FALSE, 0);
    HWND hwnd = CreateWindowExW(0, wc.lpszClassName, L"SynFin \x2014 TCP Session Analyzer", WS_OVERLAPPEDWINDOW,
                                CW_USEDEFAULT, CW_USEDEFAULT, rect.right - rect.left, rect.bottom - rect.top, nullptr,
                                nullptr, instance, nullptr);
    app.hwnd = hwnd;
    SetDarkTitleBar(hwnd);
    DragAcceptFiles(hwnd, TRUE);

    if (!CreateDeviceD3D(hwnd)) {
        CleanupDeviceD3D();
        MessageBoxW(nullptr, L"Direct3D 11 is not available on this computer.", L"SynFin", MB_ICONERROR);
        return 1;
    }
    ShowWindow(hwnd, SW_SHOWDEFAULT);
    UpdateWindow(hwnd);

    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGuiIO& io = ImGui::GetIO();
    io.IniFilename = nullptr;  // portable: never write imgui.ini next to the exe
    io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;
    ApplyStyle(app.scale);
    app.fontRegular = LoadFontResource(IDR_FONT_REGULAR, "Inter");
    app.fontBold = LoadFontResource(IDR_FONT_BOLD, "Inter Bold");
    app.fontMono = LoadFontResource(IDR_FONT_MONO, "JetBrains Mono");
    if (!app.fontRegular || !app.fontBold || !app.fontMono) {
        ImFont* fallback = io.Fonts->AddFontDefault();
        if (!app.fontRegular) app.fontRegular = fallback;
        if (!app.fontBold) app.fontBold = fallback;
        if (!app.fontMono) app.fontMono = fallback;
    }
    ImGui_ImplWin32_Init(hwnd);
    ImGui_ImplDX11_Init(g_device, g_context);
    app.logo = LoadIconTexture(static_cast<int>(48 * app.scale));

    if (!inputs.empty()) {
        app.AddPaths(inputs);
        app.autoStart = true;
    }
    app.statusFilter = statusFilter;
    app.initialSortDuration = sortDuration;

    const bool automated = !app.exportPath.empty() || !app.capturePath.empty();
    bool done = false;
    int frame = 0;
    int exitCode = 0;
    while (!done) {
        // Sleep until something happens when idle; keep drawing while an analysis runs.
        if (!app.running && !automated && frame > 3)
            MsgWaitForMultipleObjects(0, nullptr, FALSE, 250, QS_ALLINPUT);
        MSG msg;
        while (PeekMessageW(&msg, nullptr, 0U, 0U, PM_REMOVE)) {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
            if (msg.message == WM_QUIT) {
                done = true;
                exitCode = static_cast<int>(msg.wParam);
            }
        }
        if (done) break;
        if (g_resizeWidth != 0 && g_resizeHeight != 0) {
            CleanupRenderTarget();
            g_swapChain->ResizeBuffers(0, g_resizeWidth, g_resizeHeight, DXGI_FORMAT_UNKNOWN, 0);
            g_resizeWidth = g_resizeHeight = 0;
            CreateRenderTarget();
        }

        ImGui_ImplDX11_NewFrame();
        ImGui_ImplWin32_NewFrame();
        if (automated) io.AddMousePosEvent(-FLT_MAX, -FLT_MAX);  // no hover effects in screenshots
        ImGui::NewFrame();
        ImGui::PushFont(app.fontRegular, kBase);
        app.Frame();
        ImGui::PopFont();
        ImGui::Render();

        const float clear[4] = {0x0d / 255.0f, 0x11 / 255.0f, 0x17 / 255.0f, 1.0f};
        g_context->OMSetRenderTargets(1, &g_renderTarget, nullptr);
        g_context->ClearRenderTargetView(g_renderTarget, clear);
        ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());

        ++frame;
        if (app.autoStart && frame == 2) {
            app.autoStart = false;
            app.Start();
        }
        if (automated && app.finished) {
            if (++app.framesSinceFinish == 8) {  // let the table settle for a few frames
                int code = 0;
                if (!app.capturePath.empty() && !SaveBackBuffer(app.capturePath)) code = 2;
                if (!app.exportPath.empty() && !app.Export(app.exportPath)) code = 3;
                PostQuitMessage(code);
            }
        }
        g_swapChain->Present(1, 0);
    }

    ImGui_ImplDX11_Shutdown();
    ImGui_ImplWin32_Shutdown();
    ImGui::DestroyContext();
    if (app.logo) app.logo->Release();
    CleanupDeviceD3D();
    DestroyWindow(hwnd);
    UnregisterClassW(wc.lpszClassName, wc.hInstance);
    CoUninitialize();
    return exitCode;
}
