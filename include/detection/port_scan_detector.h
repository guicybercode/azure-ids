#pragma once

#include "common/types.h"
#include <string>
#include <map>
#include <set>
#include <chrono>
#include <atomic>
#include <mutex>

namespace AzureIDS {

class PortScanDetector {
public:
    PortScanDetector();
    ~PortScanDetector();

    void initialize(int min_ports, int window_seconds, double threshold);
    bool analyze_packet(const PacketInfo& packet);
    void reset();

    void set_min_ports(int min_ports);
    void set_window_seconds(int window_seconds);
    void set_threshold(double threshold);

    int get_min_ports() const;
    int get_window_seconds() const;
    double get_threshold() const;

    std::vector<std::string> get_scanning_ips() const;
    std::map<std::string, std::set<uint16_t>> get_scanned_ports() const;

private:
    struct ScanAttempt {
        std::string source_ip;
        std::string dest_ip;
        uint16_t dest_port;
        std::chrono::system_clock::time_point timestamp;
        bool is_syn_scan;
    };

    struct IPScanStats {
        std::set<uint16_t> scanned_ports;
        std::set<std::string> target_ips;
        std::chrono::system_clock::time_point first_scan;
        std::chrono::system_clock::time_point last_scan;
        int syn_packets;
        int total_packets;
    };

    void cleanup_old_scans();
    bool is_port_scan(const std::string& ip, const IPScanStats& stats);
    bool is_syn_scan_packet(const PacketInfo& packet);
    bool is_connect_scan_packet(const PacketInfo& packet);
    double calculate_scan_entropy(const std::set<uint16_t>& ports);
    double calculate_scan_rate(const std::string& ip, const IPScanStats& stats);

    std::map<std::string, IPScanStats> ip_scan_stats_;
    std::vector<ScanAttempt> recent_scans_;
    
    std::atomic<int> min_ports_;
    std::atomic<int> window_seconds_;
    std::atomic<double> threshold_;
    
    mutable std::mutex mutex_;
    std::chrono::system_clock::time_point last_cleanup_;
};

}

