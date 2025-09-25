#include "detection/ddos_detector.h"
#include "utils/logger.h"
#include <algorithm>
#include <chrono>

namespace AzureIDS {

DDoSDetector::DDoSDetector()
    : threshold_(100.0)
    , window_size_seconds_(60)
    , max_connections_per_ip_(100)
    , last_cleanup_(std::chrono::system_clock::now()) {
}

DDoSDetector::~DDoSDetector() = default;

void DDoSDetector::initialize(double threshold, int window_size_seconds) {
    threshold_.store(threshold);
    window_size_seconds_.store(window_size_seconds);
    
    std::lock_guard<std::mutex> lock(mutex_);
    ip_stats_.clear();
    last_cleanup_ = std::chrono::system_clock::now();
    
    Logger::info("DDoS detector initialized with threshold: " + std::to_string(threshold) + 
                ", window: " + std::to_string(window_size_seconds) + "s");
}

bool DDoSDetector::analyze_packet(const PacketInfo& packet) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto now = std::chrono::system_clock::now();
    std::string source_ip = packet.source_ip;
    
    if (ip_stats_.find(source_ip) == ip_stats_.end()) {
        ip_stats_[source_ip] = {0, 0, now, now};
    }
    
    IPStats& stats = ip_stats_[source_ip];
    stats.packet_count++;
    stats.last_seen = now;
    
    if (packet.protocol == "TCP" && packet.dest_port != 0) {
        stats.connection_count++;
    }
    
    if (now - last_cleanup_ > std::chrono::seconds(30)) {
        cleanup_old_entries();
        last_cleanup_ = now;
    }
    
    return is_ddos_attack(source_ip, stats);
}

void DDoSDetector::reset() {
    std::lock_guard<std::mutex> lock(mutex_);
    ip_stats_.clear();
    last_cleanup_ = std::chrono::system_clock::now();
    Logger::info("DDoS detector reset");
}

void DDoSDetector::set_threshold(double threshold) {
    threshold_.store(threshold);
}

void DDoSDetector::set_window_size(int window_size_seconds) {
    window_size_seconds_.store(window_size_seconds);
}

void DDoSDetector::set_max_connections_per_ip(int max_connections) {
    max_connections_per_ip_.store(max_connections);
}

double DDoSDetector::get_threshold() const {
    return threshold_.load();
}

int DDoSDetector::get_window_size() const {
    return window_size_seconds_.load();
}

int DDoSDetector::get_max_connections_per_ip() const {
    return max_connections_per_ip_.load();
}

std::vector<std::string> DDoSDetector::get_suspicious_ips() const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::vector<std::string> suspicious_ips;
    for (const auto& pair : ip_stats_) {
        if (is_ddos_attack(pair.first, pair.second)) {
            suspicious_ips.push_back(pair.first);
        }
    }
    
    return suspicious_ips;
}

std::map<std::string, int> DDoSDetector::get_connection_counts() const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::map<std::string, int> connection_counts;
    for (const auto& pair : ip_stats_) {
        connection_counts[pair.first] = pair.second.connection_count;
    }
    
    return connection_counts;
}

void DDoSDetector::cleanup_old_entries() {
    auto now = std::chrono::system_clock::now();
    auto cutoff_time = now - std::chrono::seconds(window_size_seconds_.load());
    
    auto it = ip_stats_.begin();
    while (it != ip_stats_.end()) {
        if (it->second.last_seen < cutoff_time) {
            it = ip_stats_.erase(it);
        } else {
            ++it;
        }
    }
}

bool DDoSDetector::is_ddos_attack(const std::string& ip, const IPStats& stats) {
    double packet_rate = calculate_packet_rate(ip);
    double connection_rate = calculate_connection_rate(ip);
    
    bool high_packet_rate = packet_rate > threshold_.load();
    bool high_connection_count = stats.connection_count > max_connections_per_ip_.load();
    bool high_connection_rate = connection_rate > (threshold_.load() / 2.0);
    
    return high_packet_rate || high_connection_count || high_connection_rate;
}

double DDoSDetector::calculate_packet_rate(const std::string& ip) {
    auto it = ip_stats_.find(ip);
    if (it == ip_stats_.end()) {
        return 0.0;
    }
    
    const IPStats& stats = it->second;
    auto duration = std::chrono::duration_cast<std::chrono::seconds>(
        stats.last_seen - stats.first_seen).count();
    
    if (duration == 0) {
        return static_cast<double>(stats.packet_count);
    }
    
    return static_cast<double>(stats.packet_count) / duration;
}

double DDoSDetector::calculate_connection_rate(const std::string& ip) {
    auto it = ip_stats_.find(ip);
    if (it == ip_stats_.end()) {
        return 0.0;
    }
    
    const IPStats& stats = it->second;
    auto duration = std::chrono::duration_cast<std::chrono::seconds>(
        stats.last_seen - stats.first_seen).count();
    
    if (duration == 0) {
        return static_cast<double>(stats.connection_count);
    }
    
    return static_cast<double>(stats.connection_count) / duration;
}

}

