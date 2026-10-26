#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <shellapi.h>
#endif

#include "session_analyzer.h"
#include <algorithm>
#include <cctype>
#include <filesystem>
#include <iostream>
#include <string>
#include <system_error>
#include <vector>

static const char* const kVersion = SYNFIN_VERSION;

static const char* const kUsage =
    "Usage: synfin [options] [capture files...]\n"
    "\n"
    "Reconstructs TCP sessions from .pcap / .pcapng captures and prints one JSON\n"
    "object per session.\n"
    "\n"
    "Options:\n"
    "  -i, --input FILE...      Capture files to analyze\n"
    "  -d, --dir DIR            Analyze every .pcap and .pcapng file in DIR\n"
    "  -t, --timeout SECONDS    Idle time, in capture time, after which an open\n"
    "                           session is reported as timed out (default 600)\n"
    "  -j, --threads N          Worker threads (default: number of CPU cores)\n"
    "  -q, --queue-size N       Packets buffered per worker thread (default 2048)\n"
    "  -v, --version            Show the version\n"
    "  -h, --help               Show this help\n";

static bool IsCaptureFile(const std::filesystem::path& path) {
    std::string ext = path.extension().string();
    std::transform(ext.begin(), ext.end(), ext.begin(), [](unsigned char c) { return std::tolower(c); });
    return ext == ".pcap" || ext == ".pcapng";
}

#ifdef _WIN32
// Started from Explorer (double-clicked, or capture files dropped onto it), synfin.exe
// gets a console window of its own that closes the moment it exits. Keep that window
// open until Enter is pressed so the help or the results can be read. Nothing changes
// when it runs in an existing console or with redirected output.
class KeepOwnConsoleOpen {
public:
    KeepOwnConsoleOpen() {
        DWORD processes[2];
        DWORD mode;
        own_console_ = GetConsoleProcessList(processes, 2) == 1 &&
                       GetConsoleMode(GetStdHandle(STD_OUTPUT_HANDLE), &mode);
    }

    ~KeepOwnConsoleOpen() {
        if (!own_console_) return;
        std::cout << "\nPress Enter to close this window..." << std::flush;
        std::cin.get();
    }

private:
    bool own_console_ = false;
};
#endif

// Command-line arguments as UTF-8. On Windows argv uses the ANSI code page, which can't
// hold every file name, so the arguments are taken from the UTF-16 command line instead.
static std::vector<std::string> Utf8Arguments(int argc, char* argv[]) {
#ifdef _WIN32
    (void)argc;
    (void)argv;
    std::vector<std::string> args;
    int count = 0;
    LPWSTR* wide = CommandLineToArgvW(GetCommandLineW(), &count);
    for (int i = 1; wide && i < count; ++i) {
        int size = WideCharToMultiByte(CP_UTF8, 0, wide[i], -1, nullptr, 0, nullptr, nullptr);
        std::string arg(size > 0 ? size - 1 : 0, '\0');
        if (size > 1) WideCharToMultiByte(CP_UTF8, 0, wide[i], -1, &arg[0], size, nullptr, nullptr);
        args.push_back(arg);
    }
    LocalFree(wide);
    return args;
#else
    return std::vector<std::string>(argv + 1, argv + argc);
#endif
}

static bool ParseNumber(const std::string& option, const std::string& text, long min, long& value) {
    try {
        size_t used = 0;
        long parsed = std::stol(text, &used);
        if (used == text.size() && parsed >= min) {
            value = parsed;
            return true;
        }
    } catch (const std::exception&) {
    }
    std::cerr << "Error parsing options: " << option << " expects a whole number >= " << min
              << ", got '" << text << "'" << std::endl;
    return false;
}

int main(int argc, char* argv[]) {
    std::vector<std::filesystem::path> input_files;
    std::vector<std::filesystem::path> input_dirs;
    long timeout = 600;
    long queue_size = 2048;
    long num_threads = std::max(1u, std::thread::hardware_concurrency());

#ifdef _WIN32
    KeepOwnConsoleOpen keep_console_open;
    SetConsoleOutputCP(CP_UTF8);  // file names are printed as UTF-8
#endif
    std::vector<std::string> args = Utf8Arguments(argc, argv);
    if (args.empty()) {
        std::cout << kUsage;
#ifdef _WIN32
        std::cout << "\nTip: drop .pcap / .pcapng files onto synfin.exe in Explorer to analyze them.\n";
#endif
        return 1;
    }
    for (size_t i = 0; i < args.size(); ++i) {
        std::string arg = args[i];
        std::string value;
        bool has_inline_value = false;
        if (arg.rfind("--", 0) == 0 && arg.find('=') != std::string::npos) {  // --option=value
            value = arg.substr(arg.find('=') + 1);
            arg = arg.substr(0, arg.find('='));
            has_inline_value = true;
        }
        auto next_value = [&](std::string& out) {
            if (has_inline_value) {
                out = value;
                return true;
            }
            if (i + 1 < args.size()) {
                out = args[++i];
                return true;
            }
            std::cerr << "Error parsing options: " << arg << " needs a value" << std::endl;
            return false;
        };

        if (arg == "-h" || arg == "--help") {
            std::cout << kUsage;
            return 0;
        } else if (arg == "-v" || arg == "--version") {
            std::cout << "synfin " << kVersion << std::endl;
            return 0;
        } else if (arg == "-i" || arg == "--input") {
            if (has_inline_value) input_files.push_back(std::filesystem::u8path(value));
            // Every following argument that is not an option is an input file.
            while (i + 1 < args.size() && (args[i + 1].empty() || args[i + 1][0] != '-')) {
                input_files.push_back(std::filesystem::u8path(args[++i]));
            }
        } else if (arg == "-d" || arg == "--dir") {
            std::string dir;
            if (!next_value(dir)) return 1;
            input_dirs.push_back(std::filesystem::u8path(dir));
        } else if (arg == "-t" || arg == "--timeout") {
            std::string text;
            if (!next_value(text) || !ParseNumber(arg, text, 1, timeout)) return 1;
        } else if (arg == "-j" || arg == "--threads") {
            std::string text;
            if (!next_value(text) || !ParseNumber(arg, text, 1, num_threads)) return 1;
        } else if (arg == "-q" || arg == "--queue-size") {
            std::string text;
            if (!next_value(text) || !ParseNumber(arg, text, 1, queue_size)) return 1;
        } else if (!arg.empty() && arg[0] == '-') {
            std::cerr << "Error parsing options: unknown option " << arg << "\n\n" << kUsage;
            return 1;
        } else {
            input_files.push_back(std::filesystem::u8path(arg));
        }
    }

    for (const auto& dir : input_dirs) {
        std::error_code ec;
        std::vector<std::filesystem::path> found;
        for (std::filesystem::directory_iterator it(dir, ec), end; !ec && it != end; it.increment(ec)) {
            if (it->is_regular_file(ec) && IsCaptureFile(it->path())) {
                found.push_back(it->path());
            }
        }
        if (ec) {
            std::cerr << "Error reading directory " << dir.u8string() << ": " << ec.message() << std::endl;
            return 1;
        }
        std::sort(found.begin(), found.end());
        input_files.insert(input_files.end(), found.begin(), found.end());
    }

    if (input_files.empty()) {
        std::cerr << "No input files provided." << std::endl;
        return 1;
    }

    SessionAnalyzer analyzer(timeout, static_cast<unsigned int>(num_threads),
                             static_cast<unsigned int>(queue_size));

    std::cout << "Analyzing files: ";
    for (const auto& file : input_files) {
        std::cout << file.u8string() << " ";
    }
    std::cout << "\nTimeout: " << timeout << " seconds\n";
    std::cout << "Threads: " << num_threads << std::endl;

    analyzer.Start();

    for (const auto& file : input_files) {
        analyzer.AnalyzePcapFile(file);
    }

    analyzer.Stop();

    return 0;
}
