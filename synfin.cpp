#include "session_analyzer.h"
#include <boost/program_options.hpp>
#include <algorithm>
#include <filesystem>
#include <iostream>
#include <vector>

namespace po = boost::program_options;

static const char* const kVersion = "0.4.0";

int main(int argc, char* argv[]) {
    std::vector<std::string> input_files;
    std::string input_dir;
    long timeout = 600;
    unsigned int queue_size = 2048;
    unsigned int num_threads = std::max(1u, std::thread::hardware_concurrency());

    po::options_description desc("Allowed options");
    desc.add_options()
        ("help,h", "Show help")
        ("version,v", "Show version")
        ("input,i", po::value<std::vector<std::string>>(&input_files)->multitoken(), "Input pcap files")
        ("dir,d", po::value<std::string>(&input_dir), "Input directory containing pcap files")
        ("timeout,t", po::value<long>(&timeout), "Session timeout in seconds")
        ("threads,j", po::value<unsigned int>(&num_threads), "Number of worker threads")
        ("queue-size,q", po::value<unsigned int>(&queue_size), "Queue size");

    po::variables_map vm;
    try {
        po::store(po::parse_command_line(argc, argv, desc), vm);
        po::notify(vm);
    } catch (const po::error& ex) {
        std::cerr << "Error parsing options: " << ex.what() << std::endl;
        return 1;
    }

    if (vm.count("help")) {
        std::cout << desc << std::endl;
        return 0;
    }

    if (vm.count("version")) {
        std::cout << "synfin " << kVersion << std::endl;
        return 0;
    }

    if (!input_dir.empty()) {
        for (const auto& entry : std::filesystem::directory_iterator(input_dir)) {
            if (entry.path().extension() == ".pcap") {
                input_files.push_back(entry.path().string());
            }
        }
    }

    if (input_files.empty()) {
        std::cerr << "No input files provided." << std::endl;
        return 1;
    }

    SessionAnalyzer analyzer(timeout, num_threads);
    
    std::cout << "Analyzing files: ";
    for (const auto& file : input_files) {
        std::cout << file << " ";
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