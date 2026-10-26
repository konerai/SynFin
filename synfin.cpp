#include "session_analyzer.h"
#include <algorithm>
#include <cctype>
#include <filesystem>
#include <iostream>
#include <string>
#include <system_error>
#include <vector>

static const char* const kVersion = "0.4.0";

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

    std::vector<std::string> args(argv + 1, argv + argc);
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
            if (has_inline_value) input_files.emplace_back(value);
            // Every following argument that is not an option is an input file.
            while (i + 1 < args.size() && (args[i + 1].empty() || args[i + 1][0] != '-')) {
                input_files.emplace_back(args[++i]);
            }
        } else if (arg == "-d" || arg == "--dir") {
            std::string dir;
            if (!next_value(dir)) return 1;
            input_dirs.emplace_back(dir);
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
            input_files.emplace_back(arg);
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
