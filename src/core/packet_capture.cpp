#include "core/packet_capture.h"
#include "common/constants.h"
#include "utils/logger.h"
#include <iostream>
#include <sstream>
#include <iomanip>

namespace AzureIDS {

PacketCapture::PacketCapture()
    : pcap_handle_(nullptr)
    , capturing_(false)
    , should_stop_(false)
    , promiscuous_mode_(true)
    , buffer_size_(DEFAULT_PACKET_BUFFER_SIZE)
    , timeout_ms_(1000) {
}

PacketCapture::~PacketCapture() {
    stop_capture();
    if (pcap_handle_) {
        pcap_close(pcap_handle_);
    }
}

bool PacketCapture::initialize(const std::string& interface_name) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    interface_name_ = interface_name;
    char errbuf[PCAP_ERRBUF_SIZE];
    
    pcap_handle_ = pcap_open_live(interface_name.c_str(), buffer_size_, 
                                 promiscuous_mode_ ? 1 : 0, timeout_ms_, errbuf);
    
    if (!pcap_handle_) {
        last_error_ = std::string(errbuf);
        Logger::error("Failed to initialize packet capture: " + last_error_);
        return false;
    }
    
    if (pcap_datalink(pcap_handle_) != DLT_EN10MB) {
        last_error_ = "Interface does not support Ethernet";
        Logger::error(last_error_);
        pcap_close(pcap_handle_);
        pcap_handle_ = nullptr;
        return false;
    }
    
    Logger::info("Packet capture initialized on interface: " + interface_name);
    return true;
}

void PacketCapture::start_capture() {
    if (capturing_.load()) {
        Logger::warn("Packet capture already running");
        return;
    }
    
    if (!pcap_handle_) {
        Logger::error("Packet capture not initialized");
        return;
    }
    
    should_stop_.store(false);
    capturing_.store(true);
    capture_thread_ = std::thread(&PacketCapture::capture_loop, this);
    
    Logger::info("Packet capture started");
}

void PacketCapture::stop_capture() {
    if (!capturing_.load()) {
        return;
    }
    
    should_stop_.store(true);
    cv_.notify_all();
    
    if (capture_thread_.joinable()) {
        capture_thread_.join();
    }
    
    capturing_.store(false);
    Logger::info("Packet capture stopped");
}

bool PacketCapture::is_capturing() const {
    return capturing_.load();
}

void PacketCapture::set_packet_callback(PacketCallback callback) {
    std::lock_guard<std::mutex> lock(mutex_);
    packet_callback_ = callback;
}

void PacketCapture::set_promiscuous_mode(bool enabled) {
    std::lock_guard<std::mutex> lock(mutex_);
    promiscuous_mode_ = enabled;
}

void PacketCapture::set_buffer_size(int buffer_size) {
    std::lock_guard<std::mutex> lock(mutex_);
    buffer_size_ = buffer_size;
}

void PacketCapture::set_timeout(int timeout_ms) {
    std::lock_guard<std::mutex> lock(mutex_);
    timeout_ms_ = timeout_ms;
}

std::string PacketCapture::get_interface_name() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return interface_name_;
}

std::string PacketCapture::get_last_error() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return last_error_;
}

void PacketCapture::capture_loop() {
    struct pcap_pkthdr* header;
    const u_char* packet;
    int result;
    
    while (!should_stop_.load()) {
        result = pcap_next_ex(pcap_handle_, &header, &packet);
        
        if (result == 1) {
            PacketInfo packet_info = parse_packet(header, packet);
            if (packet_callback_) {
                packet_callback_(packet_info);
            }
        } else if (result == 0) {
            continue;
        } else if (result == -1) {
            Logger::error("Error reading packet: " + std::string(pcap_geterr(pcap_handle_)));
            break;
        } else if (result == -2) {
            Logger::info("End of capture file reached");
            break;
        }
    }
}

PacketInfo PacketCapture::parse_packet(const struct pcap_pkthdr* header, const u_char* packet) {
    PacketInfo info;
    info.timestamp = std::chrono::system_clock::now();
    info.packet_size = header->len;
    
    if (header->caplen < sizeof(struct ether_header)) {
        return info;
    }
    
    const struct ether_header* eth_header = reinterpret_cast<const struct ether_header*>(packet);
    const u_char* ip_packet = packet + sizeof(struct ether_header);
    
    if (header->caplen < sizeof(struct ether_header) + sizeof(struct ip)) {
        return info;
    }
    
    const struct ip* ip_header = reinterpret_cast<const struct ip*>(ip_packet);
    
    info.source_ip = std::to_string(ip_header->ip_src.s_addr & 0xFF) + "." +
                    std::to_string((ip_header->ip_src.s_addr >> 8) & 0xFF) + "." +
                    std::to_string((ip_header->ip_src.s_addr >> 16) & 0xFF) + "." +
                    std::to_string((ip_header->ip_src.s_addr >> 24) & 0xFF);
    
    info.dest_ip = std::to_string(ip_header->ip_dst.s_addr & 0xFF) + "." +
                  std::to_string((ip_header->ip_dst.s_addr >> 8) & 0xFF) + "." +
                  std::to_string((ip_header->ip_dst.s_addr >> 16) & 0xFF) + "." +
                  std::to_string((ip_header->ip_dst.s_addr >> 24) & 0xFF);
    
    info.protocol = get_protocol_name(ip_header->ip_p);
    
    if (ip_header->ip_p == IPPROTO_TCP || ip_header->ip_p == IPPROTO_UDP) {
        const struct tcphdr* tcp_header = reinterpret_cast<const struct tcphdr*>(ip_packet + (ip_header->ip_hl * 4));
        info.source_port = ntohs(tcp_header->th_sport);
        info.dest_port = ntohs(tcp_header->th_dport);
    }
    
    size_t payload_offset = sizeof(struct ether_header) + (ip_header->ip_hl * 4);
    if (ip_header->ip_p == IPPROTO_TCP) {
        const struct tcphdr* tcp_header = reinterpret_cast<const struct tcphdr*>(ip_packet + (ip_header->ip_hl * 4));
        payload_offset += (tcp_header->th_off * 4);
    }
    
    if (header->caplen > payload_offset) {
        size_t payload_size = header->caplen - payload_offset;
        info.payload.assign(packet + payload_offset, packet + payload_offset + payload_size);
    }
    
    return info;
}

std::string PacketCapture::get_protocol_name(int protocol) {
    switch (protocol) {
        case IPPROTO_TCP: return "TCP";
        case IPPROTO_UDP: return "UDP";
        case IPPROTO_ICMP: return "ICMP";
        case IPPROTO_IGMP: return "IGMP";
        default: return "UNKNOWN";
    }
}

std::string PacketCapture::format_mac_address(const u_char* mac) {
    std::ostringstream oss;
    for (int i = 0; i < 6; ++i) {
        if (i > 0) oss << ":";
        oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(mac[i]);
    }
    return oss.str();
}

}
