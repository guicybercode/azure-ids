#pragma once

#include "common/types.h"
#include <string>
#include <map>
#include <chrono>
#include <atomic>
#include <mutex>

namespace AzureIDS {

class DDoSDetector {
public:
    DDoSDetector();
    ~DDoSDetector();

    void initialize(double threshold, int window_size_seconds);
    bool analyze_packet(const PacketInfo& packet);
    void reset();

    void set_threshold(double threshold);
    void set_window_size(int window_size_seconds);
    void set_max_connections_per_ip(int max_connections);

    double get_threshold() const;
    int get_window_size() const;
    int get_max_connections_per_ip() const;

    std::vector<std::string> get_suspicious_ips() const;
    std::map<std::string, int> get_connection_counts() const;

private:
    struct IPStats {
        int packet_count;
        int connection_count;
        std::chrono::system_clock::time_point first_seen;
        std::chrono::system_clock::time_point last_seen;
    };

    void cleanup_old_entries();
    bool is_ddos_attack(const std::string& ip, const IPStats& stats);
    double calculate_packet_rate(const std::string& ip);
    double calculate_connection_rate(const std::string& ip);

    std::map<std::string, IPStats> ip_stats_;
    std::atomic<double> threshold_;
    std::atomic<int> window_size_seconds_;
    std::atomic<int> max_connections_per_ip_;
    
    mutable std::mutex mutex_;
    std::chrono::system_clock::time_point last_cleanup_;
};

}

