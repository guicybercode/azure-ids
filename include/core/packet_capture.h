#pragma once

#include "common/types.h"
#include <pcap.h>
#include <thread>
#include <atomic>
#include <mutex>
#include <condition_variable>

namespace AzureIDS {

class PacketCapture {
public:
    PacketCapture();
    ~PacketCapture();

    bool initialize(const std::string& interface_name);
    void start_capture();
    void stop_capture();
    bool is_capturing() const;

    void set_packet_callback(PacketCallback callback);
    void set_promiscuous_mode(bool enabled);
    void set_buffer_size(int buffer_size);
    void set_timeout(int timeout_ms);

    std::string get_interface_name() const;
    std::string get_last_error() const;

private:
    void capture_loop();
    PacketInfo parse_packet(const struct pcap_pkthdr* header, const u_char* packet);
    std::string get_protocol_name(int protocol);
    std::string format_mac_address(const u_char* mac);

    pcap_t* pcap_handle_;
    std::string interface_name_;
    std::string last_error_;
    
    std::atomic<bool> capturing_;
    std::atomic<bool> should_stop_;
    std::thread capture_thread_;
    
    PacketCallback packet_callback_;
    bool promiscuous_mode_;
    int buffer_size_;
    int timeout_ms_;
    
    mutable std::mutex mutex_;
    std::condition_variable cv_;
};

}

