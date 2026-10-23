#ifndef SESSION_ANALYZER_H
#define SESSION_ANALYZER_H

#include <pcap.h>
#include <filesystem>
#include <iostream>
#include <string>
#include <unordered_map>
#include <boost/lockfree/queue.hpp>
#include <ctime>
#include <sys/time.h>
#include <json/json.h>
#include <unistd.h>
#include <thread>
#include <atomic>
#include <endian.h>
#include <vector>
#include "tcp_ip_headers.h"

class SessionAnalyzer {
public:
    SessionAnalyzer(long timeout = 600, unsigned int threads = std::thread::hardware_concurrency())
        : sessionTimeout(timeout), numThreads(threads), stopProcessing(false), stopOutput(false), outputQueue(2048) {
        workerQueues.reserve(numThreads);
        for (unsigned int i = 0; i < numThreads; ++i) {
            workerQueues.push_back(new boost::lockfree::queue<PacketData>(1024));
        }
    }

    ~SessionAnalyzer() {
        Stop();
        for (auto queue : workerQueues) {
            delete queue;
        }
    }

    void Start() {
        stopProcessing = false;
        stopOutput = false;
        
        outputThreadObj = std::thread([this] { OutputThread(); });
        workerThreads.reserve(numThreads);
        for (unsigned int i = 0; i < numThreads; ++i) {
            workerThreads.emplace_back([this, i] { WorkerThread(workerQueues[i]); });
        }
    }

    void Stop() {
        stopProcessing = true;
        for (auto& t : workerThreads) {
            if (t.joinable()) t.join();
        }
        workerThreads.clear();

        stopOutput = true;
        if (outputThreadObj.joinable()) outputThreadObj.join();
    }

    void AnalyzePcapFile(const std::string& filename) {
        char errbuf[PCAP_ERRBUF_SIZE];
        pcap_t* handle = pcap_open_offline(filename.c_str(), errbuf);

        if (!handle) {
            std::cerr << "Error opening file " << filename << ": " << errbuf << std::endl;
            return;
        }

        if (pcap_datalink(handle) != DLT_EN10MB) {
            std::cerr << "Error: Unsupported link-layer type." << std::endl;
            pcap_close(handle);
            return;
        }

        struct pcap_pkthdr* header;
        const u_char* packet;
        int packetCount = 0;
        const int CHECK_TIMEOUT_INTERVAL = 1000;

        int ret;
        while ((ret = pcap_next_ex(handle, &header, &packet)) >= 0) {
            if (ret == 0) continue;

            PacketContext ctx;
            if (!ExtractPacketContext(header, packet, ctx)) continue;

            size_t workerIndex = sessionKeyHasher(ctx.key) % numThreads;
            PacketData data;
            data.type = PacketType::Data;
            data.header = *header;
            data.packet = new std::vector<u_char>(packet, packet + header->caplen);

            uint16_t attempts = 0;
            while (!workerQueues[workerIndex]->push(data)) {
                if (++attempts > 1000) {
                    std::cerr << "ERROR: Failed to enqueue PacketData after 1000 attempts\n";
                    delete data.packet;
                    break;
                }
                std::this_thread::yield();
            }

            if (++packetCount % CHECK_TIMEOUT_INTERVAL == 0) {
                PacketData timeoutCmd;
                timeoutCmd.type = PacketType::TimeoutCheck;
                timeoutCmd.header = *header; // idle time is measured against capture time
                timeoutCmd.packet = nullptr;

                for (auto& q : workerQueues) {
                    while (!q->push(timeoutCmd)) {
                        std::this_thread::yield();
                    }
                }
            }
        }

        if (ret == PCAP_ERROR) {
            std::cerr << "Error reading file " << filename << ": " << pcap_geterr(handle) << std::endl;
        }

        pcap_close(handle);
    }

private:
    enum class PacketType { Data, TimeoutCheck };
    enum class CloseReason { Fin, Rst, Timeout, EndOfCapture };

    struct PacketData {
        PacketType type;
        struct pcap_pkthdr header;
        std::vector<u_char>* packet;
    };

    class SessionKey {
    public:
        uint32_t ip1;
        uint16_t port1;
        uint32_t ip2;
        uint16_t port2;
        bool is_original_direction;
        
        SessionKey() = default;

        SessionKey(uint32_t src_ip, uint16_t src_port, uint32_t dst_ip, uint16_t dst_port) {
            if (src_ip < dst_ip || (src_ip == dst_ip && src_port <= dst_port)) {
                ip1 = src_ip;
                port1 = src_port;
                ip2 = dst_ip;
                port2 = dst_port;
                is_original_direction = true;
            } else {
                ip1 = dst_ip;
                port1 = dst_port;
                ip2 = src_ip;
                port2 = src_port;
                is_original_direction = false;
            }
        }

        bool operator==(const SessionKey& other) const {
            return ip1 == other.ip1 && port1 == other.port1 && 
                   ip2 == other.ip2 && port2 == other.port2;
        }
    };

    class SessionKeyHash {
    public:    
        std::size_t operator()(const SessionKey& key) const {
            uint32_t h = 0x9747b28c;

            auto hash_part = [&](uint32_t value) {
                value ^= value >> 16;
                value *= 0x85ebca6b;
                value ^= value >> 13;
                value *= 0xc2b2ae35;
                value ^= value >> 16;
                h ^= value;
                h *= 0x85ebca6b;
            };
        
            hash_part(key.ip1);
            hash_part(key.port1);
            hash_part(key.ip2);
            hash_part(key.port2);
        
            h ^= h >> 13;
            h *= 0x5bd1e995;
            h ^= h >> 15;
        
            return h;
        }
    };

    struct SessionInfo {
        struct timeval start_time = {0, 0};
        struct timeval end_time = {0, 0};
        long elapsed_time;

        bool FIN1 = false;
        bool FIN2 = false;

        // Which endpoint of the SessionKey opened the session; reported as "source".
        bool initiator_is_ip1 = true;

        void updateElapsedTime(const struct timeval& current_time) {
            elapsed_time = (current_time.tv_sec - end_time.tv_sec) * 1000000 + 
                          (current_time.tv_usec - end_time.tv_usec);
        }
    };

    struct PacketContext {
        SessionKey key;
        const struct ip* ip_header;
        const struct tcphdr_session* tcp_header;
    };

    struct FinalSession {
        SessionKey key;
        SessionInfo info;
        CloseReason reason;

        FinalSession() = default;
        FinalSession(const SessionKey& k, const SessionInfo& s, CloseReason r)
            : key(k), info(s), reason(r) {}
    };

    static bool ExtractPacketContext(const struct pcap_pkthdr* header, const u_char* packet, PacketContext& ctx) {
        const int kEthernetHeaderLength = 14;
        if (header->caplen < kEthernetHeaderLength + sizeof(struct ip)) 
            return false;

        const struct ether_header* eth_header = reinterpret_cast<const ether_header*>(packet);
        if (be16toh(eth_header->ether_type) != ETHERTYPE_IP) 
            return false;

        const struct ip* ip_header = reinterpret_cast<const struct ip*>(packet + kEthernetHeaderLength);
        if (ip_header->ip_p != IPPROTO_TCP) 
            return false;

        const int ip_header_length = ip_header->ip_hl * 4;
        if (header->caplen < kEthernetHeaderLength + ip_header_length + sizeof(struct tcphdr_session)) 
            return false;

        const struct tcphdr_session* tcp_header = 
            reinterpret_cast<const struct tcphdr_session*>(packet + kEthernetHeaderLength + ip_header_length);

        uint32_t src_ip = be32toh(ip_header->ip_src);
        uint32_t dst_ip = be32toh(ip_header->ip_dst);
        uint16_t src_port = be16toh(tcp_header->th_sport);
        uint16_t dst_port = be16toh(tcp_header->th_dport);

        ctx.key = SessionKey(src_ip, src_port, dst_ip, dst_port);
        ctx.ip_header = ip_header;
        ctx.tcp_header = tcp_header;

        return true;
    }

    using SessionMap = std::unordered_map<SessionKey, SessionInfo, SessionKeyHash>;
    // Sessions closed by FIN/RST, with the time of their last packet. Kept for --timeout
    // so that trailing packets (the final ACK, retransmitted FIN/RST) don't open a new session.
    using ClosedMap = std::unordered_map<SessionKey, struct timeval, SessionKeyHash>;

    void ProcessPacket(const struct pcap_pkthdr* header, const u_char* packet,
                      SessionMap& sessions, ClosedMap& closed) {
        PacketContext ctx;
        if (!ExtractPacketContext(header, packet, ctx)) 
            return;

        auto it = sessions.find(ctx.key);
        SessionInfo* session;

        if (it != sessions.end()) {
            session = &it->second;
        } else {
            auto closed_it = closed.find(ctx.key);
            if (closed_it != closed.end()) {
                if (!(ctx.tcp_header->th_flags & TH_SYN)) {
                    closed_it->second = header->ts;
                    return;
                }
                closed.erase(closed_it); // a new connection reusing the same ports
            }

            session = &sessions[ctx.key];
            session->start_time = header->ts;

            // The sender of the first packet opened the session, unless that packet is a
            // SYN-ACK (the capture started mid-handshake): then its receiver did.
            bool syn_ack = (ctx.tcp_header->th_flags & TH_SYN) && (ctx.tcp_header->th_flags & TH_ACK);
            session->initiator_is_ip1 = ctx.key.is_original_direction != syn_ack;
        }

        session->end_time = header->ts;
        session->updateElapsedTime(header->ts);

        bool fin = ctx.tcp_header->th_flags & TH_FIN;
        bool rst = ctx.tcp_header->th_flags & TH_RST;

        if (rst) {
            EnqueueSessionForOutput(ctx.key, *session, CloseReason::Rst);
            closed[ctx.key] = header->ts;
            sessions.erase(ctx.key);
            return;
        }

        if (fin) {
            if (ctx.key.is_original_direction) {
                session->FIN1 = true;
            } else {
                session->FIN2 = true;
            }

            if (session->FIN1 && session->FIN2) {
                EnqueueSessionForOutput(ctx.key, *session, CloseReason::Fin);
                closed[ctx.key] = header->ts;
                sessions.erase(ctx.key);
            }
        }
    }

    void CheckForTimeouts(SessionMap& sessions, ClosedMap& closed, const struct timeval& current_time) {
        for (auto it = sessions.begin(); it != sessions.end();) {
            it->second.updateElapsedTime(current_time);
            if (it->second.elapsed_time > sessionTimeout * 1000000) {
                EnqueueSessionForOutput(it->first, it->second, CloseReason::Timeout);
                it = sessions.erase(it);
            } else {
                ++it;
            }
        }

        for (auto it = closed.begin(); it != closed.end();) {
            long idle = (current_time.tv_sec - it->second.tv_sec) * 1000000 +
                        (current_time.tv_usec - it->second.tv_usec);
            if (idle > sessionTimeout * 1000000) {
                it = closed.erase(it);
            } else {
                ++it;
            }
        }
    }

    void WorkerThread(boost::lockfree::queue<PacketData>* queue) {
        SessionMap sessions;
        ClosedMap closed;
        PacketData packetData;
        struct timeval latest_time = {0, 0}; // newest capture timestamp this worker has seen

        while (!stopProcessing.load() || !queue->empty()) {
            if (queue->pop(packetData)) {
                if (timercmp(&packetData.header.ts, &latest_time, >)) {
                    latest_time = packetData.header.ts;
                }
                if (packetData.type == PacketType::Data) {
                    ProcessPacket(
                        &packetData.header,
                        packetData.packet->data(),
                        sessions,
                        closed
                    );
                    delete packetData.packet;
                } 
                else if (packetData.type == PacketType::TimeoutCheck) {
                    CheckForTimeouts(sessions, closed, packetData.header.ts);
                }
            } else {
                std::this_thread::sleep_for(std::chrono::microseconds(10));
            }
        }

        while (queue->pop(packetData)) {
            if (packetData.type == PacketType::Data && packetData.packet) {
                delete packetData.packet;
            }
        }

        // Input is exhausted: report what is left instead of dropping it.
        CheckForTimeouts(sessions, closed, latest_time);
        for (const auto& entry : sessions) {
            EnqueueSessionForOutput(entry.first, entry.second, CloseReason::EndOfCapture);
        }
        sessions.clear();
    }

    void EnqueueSessionForOutput(const SessionKey& key, const SessionInfo& session, CloseReason reason) {
        FinalSession fs(key, session, reason);
        int back_off = 1;
        const int max_back_off = 100;

        while (!outputQueue.push(std::move(fs))) {
            std::this_thread::sleep_for(std::chrono::microseconds(back_off));
            back_off = std::min(back_off * 2, max_back_off);
        }
    }

    void OutputThread() {
        FinalSession fs;
        while (!stopOutput.load() || !outputQueue.empty()) {
            while (outputQueue.pop(fs)) {
                const SessionKey& key = fs.key;
                const SessionInfo& session = fs.info;
                bool timeout = fs.reason == CloseReason::Timeout;
    
                Json::Value session_info;
    
                uint32_t src_ip, dst_ip;
                uint16_t src_port, dst_port;
    
                if (session.initiator_is_ip1) {
                    src_ip = key.ip1;
                    src_port = key.port1;
                    dst_ip = key.ip2;
                    dst_port = key.port2;
                } else {
                    src_ip = key.ip2;
                    src_port = key.port2;
                    dst_ip = key.ip1;
                    dst_port = key.port1;
                }
    
                std::string ip1_str = std::to_string((src_ip >> 24) & 0xFF) + "." +
                                      std::to_string((src_ip >> 16) & 0xFF) + "." +
                                      std::to_string((src_ip >> 8) & 0xFF) + "." +
                                      std::to_string(src_ip & 0xFF);
    
                std::string ip2_str = std::to_string((dst_ip >> 24) & 0xFF) + "." +
                                      std::to_string((dst_ip >> 16) & 0xFF) + "." +
                                      std::to_string((dst_ip >> 8) & 0xFF) + "." +
                                      std::to_string(dst_ip & 0xFF);
    
                session_info["source"]["ip"] = ip1_str;
                session_info["source"]["port"] = src_port;
                                      
    
                session_info["destination"]["ip"] = ip2_str;
                session_info["destination"]["port"] = dst_port;
                                      
    
                session_info["start_time"]["seconds"] = static_cast<Json::UInt64>(session.start_time.tv_sec);
                session_info["start_time"]["microseconds"] = static_cast<Json::UInt64>(session.start_time.tv_usec);
                session_info["end_time"]["seconds"] = static_cast<Json::UInt64>(session.end_time.tv_sec);
                session_info["end_time"]["microseconds"] = static_cast<Json::UInt64>(session.end_time.tv_usec);
    
                if (timeout) {
                    session_info["timeout"] = true;
                }else{
                    session_info["timeout"] = false;
                }
    
                std::ostringstream oss;
                oss << "{" << "\"source\":{" << "\"ip\":\"" << ip1_str << "\"," << "\"port\":" << src_port << "},"
                    << "\"destination\":{" << "\"ip\":\"" << ip2_str << "\"," << "\"port\":" << dst_port << "},"
                    << "\"start_time\":{" << "\"seconds\":" << session.start_time.tv_sec << "," << "\"microseconds\":" << session.start_time.tv_usec << "},"
                    << "\"end_time\":{" << "\"seconds\":" << session.end_time.tv_sec << "," << "\"microseconds\":" << session.end_time.tv_usec << "}";
    
                if (timeout) {
                    oss << ",\"timeout\":true";
                }else{
                    oss << ", \"timeout\":false";
                }
                oss << ",\"closed_by\":\"" << CloseReasonName(fs.reason) << "\"";
                oss << "}";
                
                std::cout << oss.str() << "\n";
            }
            std::this_thread::sleep_for(std::chrono::microseconds(10));
        }
    }
    

    static const char* CloseReasonName(CloseReason reason) {
        switch (reason) {
            case CloseReason::Fin: return "fin";
            case CloseReason::Rst: return "rst";
            case CloseReason::Timeout: return "timeout";
            case CloseReason::EndOfCapture: return "end_of_capture";
        }
        return "unknown";
    }

    long sessionTimeout;
    unsigned int numThreads;
    std::atomic<bool> stopProcessing;
    std::atomic<bool> stopOutput;

    std::vector<boost::lockfree::queue<PacketData>*> workerQueues;
    boost::lockfree::queue<FinalSession> outputQueue;

    std::vector<std::thread> workerThreads;
    std::thread outputThreadObj;
    SessionKeyHash sessionKeyHasher;
};

#endif // SESSION_ANALYZER_H