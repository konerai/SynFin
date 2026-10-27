#ifndef SESSION_ANALYZER_H
#define SESSION_ANALYZER_H

#include <atomic>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <iostream>
#include <memory>
#include <sstream>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>
#include "blocking_queue.h"
#include "capture_reader.h"
#include "tcp_ip_headers.h"

class SessionAnalyzer {
public:
    enum class CloseReason { Fin, Rst, Timeout, EndOfCapture };

    // A finished session, as reported to the session sink.
    struct SessionRecord {
        uint32_t src_ip;    // the endpoint that opened the connection
        uint16_t src_port;
        uint32_t dst_ip;
        uint16_t dst_port;
        Timestamp start;
        Timestamp end;
        CloseReason reason;
    };

    // Called from the output thread for every session; by default prints its JSON line.
    using SessionSink = std::function<void(const SessionRecord&)>;
    // Called with errors and warnings about the input; by default prints them to stderr.
    using MessageSink = std::function<void(const std::string&)>;

    // queue_size is the number of packets that may wait for each worker thread.
    SessionAnalyzer(long timeout = 600, unsigned int threads = std::thread::hardware_concurrency(),
                    unsigned int queue_size = 2048)
        : sessionTimeout(timeout), numThreads(threads ? threads : 1), outputQueue(4096) {
        size_t batches = queue_size / kBatchSize + 1;
        for (unsigned int i = 0; i < numThreads; ++i) {
            workerQueues.push_back(std::make_unique<BlockingQueue<Batch>>(batches));
        }
        pending.resize(numThreads);
        sessionSink = [](const SessionRecord& record) { std::cout << ToJson(record) << "\n"; };
        messageSink = [](const std::string& message) { std::cerr << message << std::endl; };
    }

    void SetSessionSink(SessionSink sink) { sessionSink = std::move(sink); }
    void SetMessageSink(MessageSink sink) { messageSink = std::move(sink); }

    // Stops reading as soon as possible; sessions still open are dropped, not reported.
    // Safe to call from any thread.
    void Cancel() { cancelled = true; }
    bool Cancelled() const { return cancelled; }

    // Bytes read from the current and all previous input files.
    uint64_t BytesProcessed() const { return bytesProcessed; }

    ~SessionAnalyzer() {
        Stop();
    }

    void Start() {
        outputThreadObj = std::thread([this] { OutputThread(); });
        workerThreads.reserve(numThreads);
        for (unsigned int i = 0; i < numThreads; ++i) {
            workerThreads.emplace_back([this, i] { WorkerThread(*workerQueues[i]); });
        }
    }

    void Stop() {
        if (workerThreads.empty() && !outputThreadObj.joinable()) return;
        FlushPending();
        for (auto& queue : workerQueues) queue->Close();
        for (auto& t : workerThreads) {
            if (t.joinable()) t.join();
        }
        workerThreads.clear();

        outputQueue.Close();
        if (outputThreadObj.joinable()) outputThreadObj.join();
    }

    void AnalyzePcapFile(const std::filesystem::path& path) {
        const std::string filename = path.u8string();
        CaptureReader reader;
        std::string error;
        if (!reader.Open(path, error)) {
            messageSink("Error opening file " + filename + ": " + error);
            return;
        }
        if (!reader.IsPcapng() && !IsSupportedLinkType(reader.PcapLinkType())) {
            messageSink("Error: Unsupported link-layer type " + std::to_string(reader.PcapLinkType()) +
                        " in " + filename + ".");
            return;
        }
        const uint64_t bytesBefore = bytesProcessed;

        const int kCheckTimeoutInterval = 1000;
        int packetCount = 0;
        bool warnedLinkType = false;
        CapturedPacket packet;
        int ret;
        int packetsRead = 0;
        while ((ret = reader.Next(packet, error)) > 0) {
            if (++packetsRead % 4096 == 0) {
                if (cancelled) break;
                bytesProcessed = bytesBefore + reader.Position();
            }
            if (!IsSupportedLinkType(packet.link_type)) {
                if (!warnedLinkType) {
                    messageSink("Warning: skipping packets with unsupported link-layer type " +
                                std::to_string(packet.link_type) + " in " + filename + ".");
                    warnedLinkType = true;
                }
                continue;
            }
            long offset = IpOffset(packet.link_type, packet.data, packet.length);
            TcpPacketInfo tcp;
            if (offset < 0 || !ParseIpv4Tcp(packet.data + offset, packet.length - offset, tcp)) continue;

            PacketData data;
            data.type = PacketType::Data;
            data.ts = packet.ts;
            data.key = SessionKey(tcp.src_ip, tcp.src_port, tcp.dst_ip, tcp.dst_port);
            data.flags = tcp.flags;
            Enqueue(sessionKeyHasher(data.key) % numThreads, data);

            if (++packetCount % kCheckTimeoutInterval == 0) {
                PacketData timeoutCmd;
                timeoutCmd.type = PacketType::TimeoutCheck;
                timeoutCmd.ts = packet.ts;  // idle time is measured against capture time
                for (unsigned int i = 0; i < numThreads; ++i) Enqueue(i, timeoutCmd);
            }
        }

        if (ret < 0) {
            messageSink("Error reading file " + filename + ": " + error);
        }
        bytesProcessed = bytesBefore + reader.Position();
        FlushPending();
    }

    static std::string FormatIp(uint32_t ip) {
        return std::to_string((ip >> 24) & 0xFF) + "." + std::to_string((ip >> 16) & 0xFF) + "." +
               std::to_string((ip >> 8) & 0xFF) + "." + std::to_string(ip & 0xFF);
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

    // The session as one line of JSON, as synfin prints it.
    static std::string ToJson(const SessionRecord& record) {
        std::ostringstream oss;
        oss << "{" << "\"source\":{" << "\"ip\":\"" << FormatIp(record.src_ip) << "\"," << "\"port\":" << record.src_port << "},"
            << "\"destination\":{" << "\"ip\":\"" << FormatIp(record.dst_ip) << "\"," << "\"port\":" << record.dst_port << "},"
            << "\"start_time\":{" << "\"seconds\":" << record.start.sec << "," << "\"microseconds\":" << record.start.usec << "},"
            << "\"end_time\":{" << "\"seconds\":" << record.end.sec << "," << "\"microseconds\":" << record.end.usec << "}";

        if (record.reason == CloseReason::Timeout) {
            oss << ",\"timeout\":true";
        }else{
            oss << ", \"timeout\":false";
        }
        oss << ",\"closed_by\":\"" << CloseReasonName(record.reason) << "\"";
        oss << "}";
        return oss.str();
    }

private:
    enum class PacketType { Data, TimeoutCheck };

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

    // What a worker needs to know about a packet; the reader thread parses the headers.
    struct PacketData {
        PacketType type;
        Timestamp ts;
        SessionKey key;
        uint8_t flags;
    };

    // Packets travel to workers in batches to keep queue locking cheap.
    using Batch = std::vector<PacketData>;
    static constexpr size_t kBatchSize = 256;

    struct SessionInfo {
        Timestamp start_time;
        Timestamp end_time;

        bool FIN1 = false;
        bool FIN2 = false;

        // Which endpoint of the SessionKey opened the session; reported as "source".
        bool initiator_is_ip1 = true;
    };

    struct FinalSession {
        SessionKey key;
        SessionInfo info;
        CloseReason reason;

        FinalSession() = default;
        FinalSession(const SessionKey& k, const SessionInfo& s, CloseReason r)
            : key(k), info(s), reason(r) {}
    };

    using SessionMap = std::unordered_map<SessionKey, SessionInfo, SessionKeyHash>;
    // Sessions closed by FIN/RST, with the time of their last packet. Kept for --timeout
    // so that trailing packets (the final ACK, retransmitted FIN/RST) don't open a new session.
    using ClosedMap = std::unordered_map<SessionKey, Timestamp, SessionKeyHash>;

    void Enqueue(size_t worker, const PacketData& data) {
        Batch& batch = pending[worker];
        batch.push_back(data);
        if (batch.size() >= kBatchSize) {
            workerQueues[worker]->Push(std::move(batch));
            batch = Batch();
            batch.reserve(kBatchSize);
        }
    }

    void FlushPending() {
        for (size_t i = 0; i < pending.size(); ++i) {
            if (!pending[i].empty()) {
                workerQueues[i]->Push(std::move(pending[i]));
                pending[i] = Batch();
            }
        }
    }

    void ProcessPacket(const PacketData& packet, SessionMap& sessions, ClosedMap& closed) {
        const SessionKey& key = packet.key;
        auto it = sessions.find(key);
        SessionInfo* session;

        if (it != sessions.end()) {
            session = &it->second;
        } else {
            auto closed_it = closed.find(key);
            if (closed_it != closed.end()) {
                if (!(packet.flags & TH_SYN)) {
                    closed_it->second = packet.ts;
                    return;
                }
                closed.erase(closed_it); // a new connection reusing the same ports
            }

            session = &sessions[key];
            session->start_time = packet.ts;

            // The sender of the first packet opened the session, unless that packet is a
            // SYN-ACK (the capture started mid-handshake): then its receiver did.
            bool syn_ack = (packet.flags & TH_SYN) && (packet.flags & TH_ACK);
            session->initiator_is_ip1 = key.is_original_direction != syn_ack;
        }

        session->end_time = packet.ts;

        bool fin = packet.flags & TH_FIN;
        bool rst = packet.flags & TH_RST;

        if (rst) {
            EnqueueSessionForOutput(key, *session, CloseReason::Rst);
            closed[key] = packet.ts;
            sessions.erase(key);
            return;
        }

        if (fin) {
            if (key.is_original_direction) {
                session->FIN1 = true;
            } else {
                session->FIN2 = true;
            }

            if (session->FIN1 && session->FIN2) {
                EnqueueSessionForOutput(key, *session, CloseReason::Fin);
                closed[key] = packet.ts;
                sessions.erase(key);
            }
        }
    }

    void CheckForTimeouts(SessionMap& sessions, ClosedMap& closed, const Timestamp& current_time) {
        const int64_t limit = static_cast<int64_t>(sessionTimeout) * 1000000;
        for (auto it = sessions.begin(); it != sessions.end();) {
            if (current_time.MicrosSince(it->second.end_time) > limit) {
                EnqueueSessionForOutput(it->first, it->second, CloseReason::Timeout);
                it = sessions.erase(it);
            } else {
                ++it;
            }
        }

        for (auto it = closed.begin(); it != closed.end();) {
            if (current_time.MicrosSince(it->second) > limit) {
                it = closed.erase(it);
            } else {
                ++it;
            }
        }
    }

    void WorkerThread(BlockingQueue<Batch>& queue) {
        SessionMap sessions;
        ClosedMap closed;
        Timestamp latest_time; // newest capture timestamp this worker has seen
        Batch batch;

        while (queue.Pop(batch)) {
            for (const PacketData& packet : batch) {
                if (packet.ts > latest_time) {
                    latest_time = packet.ts;
                }
                if (packet.type == PacketType::Data) {
                    ProcessPacket(packet, sessions, closed);
                } else {
                    CheckForTimeouts(sessions, closed, packet.ts);
                }
            }
        }

        if (cancelled) return;

        // Input is exhausted: report what is left instead of dropping it.
        CheckForTimeouts(sessions, closed, latest_time);
        for (const auto& entry : sessions) {
            EnqueueSessionForOutput(entry.first, entry.second, CloseReason::EndOfCapture);
        }
        sessions.clear();
    }

    void EnqueueSessionForOutput(const SessionKey& key, const SessionInfo& session, CloseReason reason) {
        outputQueue.Push(FinalSession(key, session, reason));
    }

    void OutputThread() {
        FinalSession fs;
        while (outputQueue.Pop(fs)) {
            const SessionKey& key = fs.key;
            const SessionInfo& session = fs.info;
            SessionRecord record;
            if (session.initiator_is_ip1) {
                record.src_ip = key.ip1;
                record.src_port = key.port1;
                record.dst_ip = key.ip2;
                record.dst_port = key.port2;
            } else {
                record.src_ip = key.ip2;
                record.src_port = key.port2;
                record.dst_ip = key.ip1;
                record.dst_port = key.port1;
            }
            record.start = session.start_time;
            record.end = session.end_time;
            record.reason = fs.reason;
            sessionSink(record);
        }
        std::cout.flush();
    }

    long sessionTimeout;
    unsigned int numThreads;

    std::vector<std::unique_ptr<BlockingQueue<Batch>>> workerQueues;
    std::vector<Batch> pending;  // per-worker batch being filled by the reader thread
    BlockingQueue<FinalSession> outputQueue;

    std::vector<std::thread> workerThreads;
    std::thread outputThreadObj;
    SessionKeyHash sessionKeyHasher;

    SessionSink sessionSink;
    MessageSink messageSink;
    std::atomic<bool> cancelled{false};
    std::atomic<uint64_t> bytesProcessed{0};
};

#endif // SESSION_ANALYZER_H
