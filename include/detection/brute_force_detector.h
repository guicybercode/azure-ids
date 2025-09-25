#pragma once

#include "common/types.h"
#include <string>
#include <map>
#include <set>
#include <chrono>
#include <atomic>
#include <mutex>

namespace AzureIDS {

class BruteForceDetector {
public:
    BruteForceDetector();
    ~BruteForceDetector();

    void initialize(int max_attempts, int window_minutes, int lockout_minutes);
    bool analyze_packet(const PacketInfo& packet);
    void reset();

    void set_max_attempts(int max_attempts);
    void set_window_minutes(int window_minutes);
    void set_lockout_minutes(int lockout_minutes);

    int get_max_attempts() const;
    int get_window_minutes() const;
    int get_lockout_minutes() const;

    std::vector<std::string> get_locked_ips() const;
    std::map<std::string, int> get_attempt_counts() const;

private:
    struct LoginAttempt {
        std::string source_ip;
        std::string dest_ip;
        uint16_t dest_port;
        std::chrono::system_clock::time_point timestamp;
        bool successful;
    };

    struct IPAttempts {
        int attempt_count;
        std::chrono::system_clock::time_point first_attempt;
        std::chrono::system_clock::time_point last_attempt;
        std::chrono::system_clock::time_point lockout_until;
        bool is_locked;
    };

    void cleanup_old_attempts();
    bool is_brute_force_attempt(const PacketInfo& packet);
    bool is_locked_ip(const std::string& ip);
    void lock_ip(const std::string& ip);
    bool is_authentication_packet(const PacketInfo& packet);

    std::map<std::string, IPAttempts> ip_attempts_;
    std::set<std::string> locked_ips_;
    std::vector<LoginAttempt> recent_attempts_;
    
    std::atomic<int> max_attempts_;
    std::atomic<int> window_minutes_;
    std::atomic<int> lockout_minutes_;
    
    mutable std::mutex mutex_;
    std::chrono::system_clock::time_point last_cleanup_;
    
    static const std::set<uint16_t> AUTH_PORTS;
    static const std::set<std::string> AUTH_PROTOCOLS;
};

}

