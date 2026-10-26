#ifndef CAPTURE_READER_H
#define CAPTURE_READER_H

#include <cstdint>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

// A capture timestamp: whole seconds since the Unix epoch plus microseconds.
struct Timestamp {
    int64_t sec = 0;
    int32_t usec = 0;

    bool operator>(const Timestamp& other) const {
        return sec > other.sec || (sec == other.sec && usec > other.usec);
    }

    // Microseconds from `earlier` to this timestamp (negative if `earlier` is later).
    int64_t MicrosSince(const Timestamp& earlier) const {
        return (sec - earlier.sec) * 1000000 + (usec - earlier.usec);
    }
};

struct CapturedPacket {
    Timestamp ts;
    uint32_t link_type = 0;
    const uint8_t* data = nullptr;  // valid until the next call to Next()
    uint32_t length = 0;            // bytes captured
};

// Reads packets from a classic libpcap file (.pcap, microsecond or nanosecond
// timestamps, either byte order) or a pcapng file (.pcapng, any number of sections and
// interfaces). Needs no external library.
class CaptureReader {
public:
    bool Open(const std::filesystem::path& path, std::string& error) {
        in_.rdbuf()->pubsetbuf(buffer_, sizeof(buffer_));
        in_.open(path, std::ios::binary);
        if (!in_) {
            error = "cannot open the file";
            return false;
        }
        uint8_t magic[4];
        if (!ReadExact(magic, 4)) {
            error = "the file is empty or too short";
            return false;
        }
        uint32_t le = Get32(magic, false);
        if (le == 0x0A0D0D0A) {
            format_ = Format::Pcapng;
            return ReadSectionHeader(error);
        }
        switch (le) {
            case 0xA1B2C3D4: swapped_ = false; nanoseconds_ = false; break;
            case 0xD4C3B2A1: swapped_ = true;  nanoseconds_ = false; break;
            case 0xA1B23C4D: swapped_ = false; nanoseconds_ = true;  break;
            case 0x4D3CB2A1: swapped_ = true;  nanoseconds_ = true;  break;
            default:
                error = "not a pcap or pcapng file";
                return false;
        }
        format_ = Format::Pcap;
        uint8_t header[20];
        if (!ReadExact(header, sizeof(header))) {
            error = "truncated pcap file header";
            return false;
        }
        pcap_link_type_ = Get32(header + 16, swapped_) & 0xFFFF;  // upper bits hold FCS info
        return true;
    }

    // Link type of a classic pcap file (pcapng files can have one per interface).
    uint32_t PcapLinkType() const { return format_ == Format::Pcap ? pcap_link_type_ : 0; }
    bool IsPcapng() const { return format_ == Format::Pcapng; }

    // Returns 1 and fills `packet`, 0 at the end of the file, or -1 with `error` set.
    int Next(CapturedPacket& packet, std::string& error) {
        return format_ == Format::Pcap ? NextPcap(packet, error) : NextPcapng(packet, error);
    }

private:
    enum class Format { Pcap, Pcapng };

    struct Interface {
        uint32_t link_type = 0;
        uint64_t units_per_second = 1000000;  // if_tsresol, default microseconds
        int64_t offset_seconds = 0;           // if_tsoffset
    };

    static constexpr uint32_t kMaxPacket = 256 * 1024 * 1024;  // sanity limit for corrupt files

    bool ReadExact(void* dst, size_t n) {
        in_.read(static_cast<char*>(dst), static_cast<std::streamsize>(n));
        return static_cast<size_t>(in_.gcount()) == n;
    }

    static uint16_t Get16(const uint8_t* p, bool big_endian) {
        return big_endian ? static_cast<uint16_t>((p[0] << 8) | p[1])
                          : static_cast<uint16_t>(p[0] | (p[1] << 8));
    }

    static uint32_t Get32(const uint8_t* p, bool big_endian) {
        return big_endian ? (static_cast<uint32_t>(p[0]) << 24) | (static_cast<uint32_t>(p[1]) << 16) |
                                (static_cast<uint32_t>(p[2]) << 8) | p[3]
                          : p[0] | (static_cast<uint32_t>(p[1]) << 8) | (static_cast<uint32_t>(p[2]) << 16) |
                                (static_cast<uint32_t>(p[3]) << 24);
    }

    // ---- classic pcap ----

    int NextPcap(CapturedPacket& packet, std::string& error) {
        uint8_t header[16];
        in_.read(reinterpret_cast<char*>(header), sizeof(header));
        if (in_.gcount() == 0) return 0;
        if (in_.gcount() != sizeof(header)) {
            error = "truncated packet header at the end of the file";
            return -1;
        }
        uint32_t frac = Get32(header + 4, swapped_);
        uint32_t length = Get32(header + 8, swapped_);
        if (length > kMaxPacket) {
            error = "corrupt packet length";
            return -1;
        }
        data_.resize(length);
        if (!ReadExact(data_.data(), length)) {
            error = "truncated packet at the end of the file";
            return -1;
        }
        packet.ts.sec = Get32(header, swapped_);
        packet.ts.usec = static_cast<int32_t>(nanoseconds_ ? frac / 1000 : frac);
        packet.link_type = pcap_link_type_;
        packet.data = data_.data();
        packet.length = length;
        return 1;
    }

    // ---- pcapng ----

    // Called with the block type (0x0A0D0D0A) already consumed.
    bool ReadSectionHeader(std::string& error) {
        uint8_t raw[8];  // block total length + byte-order magic
        if (!ReadExact(raw, sizeof(raw))) {
            error = "truncated pcapng section header";
            return false;
        }
        uint32_t magic = Get32(raw + 4, false);
        if (magic == 0x1A2B3C4D) {
            big_endian_ = false;
        } else if (magic == 0x4D3C2B1A) {
            big_endian_ = true;
        } else {
            error = "bad pcapng byte-order magic";
            return false;
        }
        uint32_t total = Get32(raw, big_endian_);
        if (total < 28 || total % 4 != 0 || total > kMaxPacket) {
            error = "corrupt pcapng section header";
            return false;
        }
        block_.resize(total - 12);  // the rest of the block after type, length and magic
        if (!ReadExact(block_.data(), block_.size())) {
            error = "truncated pcapng section header";
            return false;
        }
        interfaces_.clear();  // interface ids are per section
        return true;
    }

    int NextPcapng(CapturedPacket& packet, std::string& error) {
        for (;;) {
            uint8_t head[8];
            in_.read(reinterpret_cast<char*>(head), sizeof(head));
            if (in_.gcount() == 0) return 0;
            if (in_.gcount() != sizeof(head)) {
                error = "truncated block at the end of the file";
                return -1;
            }
            uint32_t type = Get32(head, big_endian_);
            if (type == 0x0A0D0D0A) {
                // A new section; its byte order may differ, so re-read the length with it.
                in_.seekg(-4, std::ios::cur);
                if (!ReadSectionHeader(error)) return -1;
                continue;
            }
            uint32_t total = Get32(head + 4, big_endian_);
            if (total < 12 || total % 4 != 0 || total > kMaxPacket) {
                error = "corrupt pcapng block length";
                return -1;
            }
            block_.resize(total - 8);  // body + trailing length
            if (!ReadExact(block_.data(), block_.size())) {
                error = "truncated block at the end of the file";
                return -1;
            }
            const uint8_t* body = block_.data();
            size_t body_length = total - 12;

            switch (type) {
                case 1:  // Interface Description Block
                    if (!ReadInterface(body, body_length, error)) return -1;
                    break;
                case 6:  // Enhanced Packet Block
                    if (body_length < 20) {
                        error = "corrupt enhanced packet block";
                        return -1;
                    }
                    if (FillPacket(packet, Get32(body, big_endian_), Get32(body + 4, big_endian_),
                                   Get32(body + 8, big_endian_), Get32(body + 12, big_endian_),
                                   body + 20, body_length - 20, error)) {
                        return 1;
                    }
                    if (!error.empty()) return -1;
                    break;
                case 2:  // obsolete Packet Block
                    if (body_length < 20) {
                        error = "corrupt packet block";
                        return -1;
                    }
                    if (FillPacket(packet, Get16(body, big_endian_), Get32(body + 4, big_endian_),
                                   Get32(body + 8, big_endian_), Get32(body + 12, big_endian_),
                                   body + 20, body_length - 20, error)) {
                        return 1;
                    }
                    if (!error.empty()) return -1;
                    break;
                default:
                    // Simple Packet Blocks carry no timestamp; name resolution, statistics
                    // and custom blocks don't matter for session tracking.
                    break;
            }
        }
    }

    bool ReadInterface(const uint8_t* body, size_t length, std::string& error) {
        if (length < 8) {
            error = "corrupt interface description block";
            return false;
        }
        Interface iface;
        iface.link_type = Get16(body, big_endian_);
        size_t pos = 8;
        while (pos + 4 <= length) {
            uint16_t code = Get16(body + pos, big_endian_);
            uint16_t option_length = Get16(body + pos + 2, big_endian_);
            pos += 4;
            if (code == 0 || pos + option_length > length) break;  // opt_endofopt
            const uint8_t* value = body + pos;
            if (code == 9 && option_length >= 1) {  // if_tsresol
                uint8_t resolution = value[0];
                uint32_t exponent = resolution & 0x7F;
                uint64_t units = 1;
                bool power_of_two = resolution & 0x80;
                if ((power_of_two && exponent > 63) || (!power_of_two && exponent > 19)) {
                    error = "unsupported timestamp resolution";
                    return false;
                }
                for (uint32_t i = 0; i < exponent; ++i) units *= power_of_two ? 2 : 10;
                iface.units_per_second = units;
            } else if (code == 14 && option_length >= 8) {  // if_tsoffset
                uint64_t offset = big_endian_
                    ? (static_cast<uint64_t>(Get32(value, true)) << 32) | Get32(value + 4, true)
                    : (static_cast<uint64_t>(Get32(value + 4, false)) << 32) | Get32(value, false);
                iface.offset_seconds = static_cast<int64_t>(offset);
            }
            pos += (option_length + 3u) & ~3u;
        }
        interfaces_.push_back(iface);
        return true;
    }

    // Returns true if a packet was produced; false with an empty `error` means "skip".
    bool FillPacket(CapturedPacket& packet, uint32_t interface_id, uint32_t ts_high, uint32_t ts_low,
                    uint32_t captured, const uint8_t* data, size_t available, std::string& error) {
        if (interface_id >= interfaces_.size()) {
            error = "packet refers to an unknown interface";
            return false;
        }
        if (captured > available) {
            error = "corrupt packet length";
            return false;
        }
        const Interface& iface = interfaces_[interface_id];
        uint64_t ticks = (static_cast<uint64_t>(ts_high) << 32) | ts_low;
        uint64_t units = iface.units_per_second;
        uint64_t fraction = ticks % units;
        uint64_t micros = units <= 1000000000000ULL ? fraction * 1000000 / units : fraction / (units / 1000000);
        packet.ts.sec = static_cast<int64_t>(ticks / units) + iface.offset_seconds;
        packet.ts.usec = static_cast<int32_t>(micros);
        packet.link_type = iface.link_type;
        packet.data = data;
        packet.length = captured;
        return true;
    }

    std::ifstream in_;
    char buffer_[1 << 16];
    Format format_ = Format::Pcap;

    // classic pcap
    bool swapped_ = false;
    bool nanoseconds_ = false;
    uint32_t pcap_link_type_ = 0;
    std::vector<uint8_t> data_;

    // pcapng
    bool big_endian_ = false;
    std::vector<Interface> interfaces_;
    std::vector<uint8_t> block_;
};

#endif // CAPTURE_READER_H
