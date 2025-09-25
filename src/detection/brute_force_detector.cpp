#include "detection/brute_force_detector.h"
#include "utils/logger.h"
#include <algorithm>
#include <chrono>

namespace AzureIDS {

const std::set<uint16_t> BruteForceDetector::AUTH_PORTS = {22, 23, 21, 25, 110, 143, 993, 995, 3389, 5432, 3306, 1433};
const std::set<std::string> BruteForceDetector::AUTH_PROTOCOLS = {"SSH", "FTP", "SMTP", "POP3", "IMAP", "RDP"};

BruteForceDetector::BruteForceDetector()
    : max_attempts_(5)
    , window_minutes_(15)
    , lockout_minutes_(30)
    , last_cleanup_(std::chrono::system_clock::now()) {
}

BruteForceDetector::~BruteForceDetector() = default;

void BruteForceDetector::initialize(int max_attempts, int window_minutes, int lockout_minutes) {
    max_attempts_.store(max_attempts);
    window_minutes_.store(window_minutes);
    lockout_minutes_.store(lockout_minutes);
    
    std::lock_guard<std::mutex> lock(mutex_);
    ip_attempts_.clear();
    locked_ips_.clear();
    recent_attempts_.clear();
    last_cleanup_ = std::chrono::system_clock::now();
    
    Logger::info("Brute force detector initialized - max attempts: " + std::to_string(max_attempts) + 
                ", window: " + std::to_string(window_minutes) + "m, lockout: " + std::to_string(lockout_minutes) + "m");
}

bool BruteForceDetector::analyze_packet(const PacketInfo& packet) {
    if (!is_authentication_packet(packet)) {
        return false;
    }
    
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto now = std::chrono::system_clock::now();
    std::string source_ip = packet.source_ip;
    
    if (is_locked_ip(source_ip)) {
        return true;
    }
    
    if (ip_attempts_.find(source_ip) == ip_attempts_.end()) {
        ip_attempts_[source_ip] = {0, now, now, now, false};
    }
    
    IPAttempts& attempts = ip_attempts_[source_ip];
    attempts.attempt_count++;
    attempts.last_attempt = now;
    
    LoginAttempt attempt;
    attempt.source_ip = packet.source_ip;
    attempt.dest_ip = packet.dest_ip;
    attempt.dest_port = packet.dest_port;
    attempt.timestamp = now;
    attempt.successful = false;
    
    recent_attempts_.push_back(attempt);
    
    if (now - last_cleanup_ > std::chrono::minutes(5)) {
        cleanup_old_attempts();
        last_cleanup_ = now;
    }
    
    if (attempts.attempt_count >= max_attempts_.load()) {
        lock_ip(source_ip);
        Logger::warn("IP " + source_ip + " locked due to brute force attempts");
        return true;
    }
    
    return false;
}

void BruteForceDetector::reset() {
    std::lock_guard<std::mutex> lock(mutex_);
    ip_attempts_.clear();
    locked_ips_.clear();
    recent_attempts_.clear();
    last_cleanup_ = std::chrono::system_clock::now();
    Logger::info("Brute force detector reset");
}

void BruteForceDetector::set_max_attempts(int max_attempts) {
    max_attempts_.store(max_attempts);
}

void BruteForceDetector::set_window_minutes(int window_minutes) {
    window_minutes_.store(window_minutes);
}

void BruteForceDetector::set_lockout_minutes(int lockout_minutes) {
    lockout_minutes_.store(lockout_minutes);
}

int BruteForceDetector::get_max_attempts() const {
    return max_attempts_.load();
}

int BruteForceDetector::get_window_minutes() const {
    return window_minutes_.load();
}

int BruteForceDetector::get_lockout_minutes() const {
    return lockout_minutes_.load();
}

std::vector<std::string> BruteForceDetector::get_locked_ips() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return std::vector<std::string>(locked_ips_.begin(), locked_ips_.end());
}

std::map<std::string, int> BruteForceDetector::get_attempt_counts() const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::map<std::string, int> attempt_counts;
    for (const auto& pair : ip_attempts_) {
        attempt_counts[pair.first] = pair.second.attempt_count;
    }
    
    return attempt_counts;
}

void BruteForceDetector::cleanup_old_attempts() {
    auto now = std::chrono::system_clock::now();
    auto cutoff_time = now - std::chrono::minutes(window_minutes_.load());
    
    auto it = ip_attempts_.begin();
    while (it != ip_attempts_.end()) {
        if (it->second.last_attempt < cutoff_time) {
            locked_ips_.erase(it->first);
            it = ip_attempts_.erase(it);
        } else {
            ++it;
        }
    }
    
    recent_attempts_.erase(
        std::remove_if(recent_attempts_.begin(), recent_attempts_.end(),
            [cutoff_time](const LoginAttempt& attempt) {
                return attempt.timestamp < cutoff_time;
            }),
        recent_attempts_.end());
}

bool BruteForceDetector::is_brute_force_attempt(const PacketInfo& packet) {
    return is_authentication_packet(packet);
}

bool BruteForceDetector::is_locked_ip(const std::string& ip) {
    auto it = ip_attempts_.find(ip);
    if (it == ip_attempts_.end()) {
        return false;
    }
    
    auto now = std::chrono::system_clock::now();
    if (it->second.is_locked && now < it->second.lockout_until) {
        return true;
    } else if (it->second.is_locked && now >= it->second.lockout_until) {
        it->second.is_locked = false;
        locked_ips_.erase(ip);
        return false;
    }
    
    return false;
}

void BruteForceDetector::lock_ip(const std::string& ip) {
    auto it = ip_attempts_.find(ip);
    if (it != ip_attempts_.end()) {
        it->second.is_locked = true;
        it->second.lockout_until = std::chrono::system_clock::now() + 
                                  std::chrono::minutes(lockout_minutes_.load());
        locked_ips_.insert(ip);
    }
}

bool BruteForceDetector::is_authentication_packet(const PacketInfo& packet) {
    if (AUTH_PORTS.find(packet.dest_port) != AUTH_PORTS.end()) {
        return true;
    }
    
    if (packet.dest_port == 22 && packet.protocol == "TCP") {
        return true;
    }
    
    if (packet.dest_port == 3389 && packet.protocol == "TCP") {
        return true;
    }
    
    return false;
}

}

