#pragma once

#include <string>
#include <vector>
#include <map>
#include <chrono>
#include <memory>
#include <functional>

namespace AzureIDS {

struct PacketInfo {
    std::string source_ip;
    std::string dest_ip;
    uint16_t source_port;
    uint16_t dest_port;
    std::string protocol;
    size_t packet_size;
    std::chrono::system_clock::time_point timestamp;
    std::vector<uint8_t> payload;
};

struct ThreatAlert {
    std::string alert_id;
    std::string threat_type;
    std::string severity;
    std::string source_ip;
    std::string description;
    std::chrono::system_clock::time_point timestamp;
    std::map<std::string, std::string> metadata;
};

struct NetworkFlow {
    std::string flow_id;
    std::string source_ip;
    std::string dest_ip;
    uint16_t source_port;
    uint16_t dest_port;
    std::string protocol;
    uint64_t packet_count;
    uint64_t byte_count;
    std::chrono::system_clock::time_point start_time;
    std::chrono::system_clock::time_point last_seen;
};

struct MLFeatures {
    std::vector<double> packet_rates;
    std::vector<double> byte_rates;
    std::vector<double> connection_durations;
    std::vector<double> port_entropy;
    std::vector<double> protocol_distribution;
    std::vector<double> payload_entropy;
};

enum class ThreatLevel {
    LOW = 1,
    MEDIUM = 2,
    HIGH = 3,
    CRITICAL = 4
};

enum class ResponseAction {
    LOG_ONLY,
    BLOCK_IP,
    RATE_LIMIT,
    QUARANTINE,
    NOTIFY_ADMIN
};

using PacketCallback = std::function<void(const PacketInfo&)>;
using ThreatCallback = std::function<void(const ThreatAlert&)>;
using ResponseCallback = std::function<void(const std::string&, ResponseAction)>;

}

