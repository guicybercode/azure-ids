#include "detection/port_scan_detector.h"
#include "utils/logger.h"
#include <algorithm>
#include <chrono>
#include <cmath>

namespace AzureIDS {

PortScanDetector::PortScanDetector()
    : min_ports_(10)
    , window_seconds_(60)
    , threshold_(0.7)
    , last_cleanup_(std::chrono::system_clock::now()) {
}

PortScanDetector::~PortScanDetector() = default;

void PortScanDetector::initialize(int min_ports, int window_seconds, double threshold) {
    min_ports_.store(min_ports);
    window_seconds_.store(window_seconds);
    threshold_.store(threshold);
    
    std::lock_guard<std::mutex> lock(mutex_);
    ip_scan_stats_.clear();
    recent_scans_.clear();
    last_cleanup_ = std::chrono::system_clock::now();
    
    Logger::info("Port scan detector initialized - min ports: " + std::to_string(min_ports) + 
                ", window: " + std::to_string(window_seconds) + "s, threshold: " + std::to_string(threshold));
}

bool PortScanDetector::analyze_packet(const PacketInfo& packet) {
    if (!is_syn_scan_packet(packet) && !is_connect_scan_packet(packet)) {
        return false;
    }
    
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto now = std::chrono::system_clock::now();
    std::string source_ip = packet.source_ip;
    
    if (ip_scan_stats_.find(source_ip) == ip_scan_stats_.end()) {
        ip_scan_stats_[source_ip] = {{}, {}, now, now, 0, 0};
    }
    
    IPScanStats& stats = ip_scan_stats_[source_ip];
    stats.scanned_ports.insert(packet.dest_port);
    stats.target_ips.insert(packet.dest_ip);
    stats.last_scan = now;
    stats.total_packets++;
    
    if (is_syn_scan_packet(packet)) {
        stats.syn_packets++;
    }
    
    ScanAttempt attempt;
    attempt.source_ip = packet.source_ip;
    attempt.dest_ip = packet.dest_ip;
    attempt.dest_port = packet.dest_port;
    attempt.timestamp = now;
    attempt.is_syn_scan = is_syn_scan_packet(packet);
    
    recent_scans_.push_back(attempt);
    
    if (now - last_cleanup_ > std::chrono::seconds(30)) {
        cleanup_old_scans();
        last_cleanup_ = now;
    }
    
    return is_port_scan(source_ip, stats);
}

void PortScanDetector::reset() {
    std::lock_guard<std::mutex> lock(mutex_);
    ip_scan_stats_.clear();
    recent_scans_.clear();
    last_cleanup_ = std::chrono::system_clock::now();
    Logger::info("Port scan detector reset");
}

void PortScanDetector::set_min_ports(int min_ports) {
    min_ports_.store(min_ports);
}

void PortScanDetector::set_window_seconds(int window_seconds) {
    window_seconds_.store(window_seconds);
}

void PortScanDetector::set_threshold(double threshold) {
    threshold_.store(threshold);
}

int PortScanDetector::get_min_ports() const {
    return min_ports_.load();
}

int PortScanDetector::get_window_seconds() const {
    return window_seconds_.load();
}

double PortScanDetector::get_threshold() const {
    return threshold_.load();
}

std::vector<std::string> PortScanDetector::get_scanning_ips() const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::vector<std::string> scanning_ips;
    for (const auto& pair : ip_scan_stats_) {
        if (is_port_scan(pair.first, pair.second)) {
            scanning_ips.push_back(pair.first);
        }
    }
    
    return scanning_ips;
}

std::map<std::string, std::set<uint16_t>> PortScanDetector::get_scanned_ports() const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::map<std::string, std::set<uint16_t>> scanned_ports;
    for (const auto& pair : ip_scan_stats_) {
        scanned_ports[pair.first] = pair.second.scanned_ports;
    }
    
    return scanned_ports;
}

void PortScanDetector::cleanup_old_scans() {
    auto now = std::chrono::system_clock::now();
    auto cutoff_time = now - std::chrono::seconds(window_seconds_.load());
    
    auto it = ip_scan_stats_.begin();
    while (it != ip_scan_stats_.end()) {
        if (it->second.last_scan < cutoff_time) {
            it = ip_scan_stats_.erase(it);
        } else {
            ++it;
        }
    }
    
    recent_scans_.erase(
        std::remove_if(recent_scans_.begin(), recent_scans_.end(),
            [cutoff_time](const ScanAttempt& attempt) {
                return attempt.timestamp < cutoff_time;
            }),
        recent_scans_.end());
}

bool PortScanDetector::is_port_scan(const std::string& ip, const IPScanStats& stats) {
    if (stats.scanned_ports.size() < static_cast<size_t>(min_ports_.load())) {
        return false;
    }
    
    double scan_rate = calculate_scan_rate(ip, stats);
    double entropy = calculate_scan_entropy(stats.scanned_ports);
    
    bool high_scan_rate = scan_rate > threshold_.load();
    bool high_entropy = entropy > 0.8;
    bool many_targets = stats.target_ips.size() > 1;
    bool syn_scan_ratio = static_cast<double>(stats.syn_packets) / stats.total_packets > 0.8;
    
    return high_scan_rate || (high_entropy && many_targets) || syn_scan_ratio;
}

bool PortScanDetector::is_syn_scan_packet(const PacketInfo& packet) {
    return packet.protocol == "TCP" && packet.dest_port != 0;
}

bool PortScanDetector::is_connect_scan_packet(const PacketInfo& packet) {
    return packet.protocol == "TCP" && packet.dest_port != 0;
}

double PortScanDetector::calculate_scan_entropy(const std::set<uint16_t>& ports) {
    if (ports.empty()) {
        return 0.0;
    }
    
    std::map<uint16_t, int> port_counts;
    for (uint16_t port : ports) {
        port_counts[port]++;
    }
    
    double entropy = 0.0;
    double total = static_cast<double>(ports.size());
    
    for (const auto& pair : port_counts) {
        double probability = static_cast<double>(pair.second) / total;
        if (probability > 0.0) {
            entropy -= probability * std::log2(probability);
        }
    }
    
    return entropy;
}

double PortScanDetector::calculate_scan_rate(const std::string& ip, const IPScanStats& stats) {
    auto duration = std::chrono::duration_cast<std::chrono::seconds>(
        stats.last_scan - stats.first_scan).count();
    
    if (duration == 0) {
        return static_cast<double>(stats.scanned_ports.size());
    }
    
    return static_cast<double>(stats.scanned_ports.size()) / duration;
}

}

