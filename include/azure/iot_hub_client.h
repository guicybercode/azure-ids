#pragma once

#include "common/types.h"
#include <string>
#include <memory>
#include <thread>
#include <atomic>
#include <mutex>
#include <queue>

namespace AzureIDS {

class IoTHubClient {
public:
    IoTHubClient();
    ~IoTHubClient();

    bool initialize(const std::string& connection_string);
    void shutdown();

    bool send_telemetry(const std::string& device_id, const std::string& data);
    bool send_alert(const ThreatAlert& alert);
    bool send_flow_data(const NetworkFlow& flow);

    void set_connection_string(const std::string& connection_string);
    std::string get_connection_string() const;

    bool is_connected() const;
    std::string get_last_error() const;

    void set_retry_count(int retry_count);
    void set_timeout(int timeout_ms);

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
    
    std::atomic<bool> initialized_;
    std::atomic<bool> connected_;
    std::string last_error_;
    std::string connection_string_;
    
    int retry_count_;
    int timeout_ms_;
    
    mutable std::mutex mutex_;
    std::thread worker_thread_;
    std::queue<std::string> message_queue_;
    std::condition_variable cv_;
    std::atomic<bool> should_stop_;
    
    void worker_loop();
    bool send_message_internal(const std::string& message);
};

}

