#include "core/packet_capture.h"
#include "core/ml_engine.h"
#include "detection/ddos_detector.h"
#include "detection/brute_force_detector.h"
#include "detection/port_scan_detector.h"
#include "azure/iot_hub_client.h"
#include "utils/logger.h"
#include "common/types.h"
#include <iostream>
#include <signal.h>
#include <thread>
#include <chrono>
#include <atomic>

using namespace AzureIDS;

std::atomic<bool> running(true);

void signal_handler(int signal) {
    if (signal == SIGINT || signal == SIGTERM) {
        std::cout << "\nShutting down Azure IDS..." << std::endl;
        running.store(false);
    }
}

void packet_handler(const PacketInfo& packet) {
    static DDoSDetector ddos_detector;
    static BruteForceDetector brute_force_detector;
    static PortScanDetector port_scan_detector;
    static MLEngine ml_engine;
    static IoTHubClient iot_client;
    
    static bool initialized = false;
    if (!initialized) {
        ddos_detector.initialize(100.0, 60, 50);
        brute_force_detector.initialize(5, 15, 30);
        port_scan_detector.initialize(10, 60, 0.7);
        ml_engine.initialize();
        iot_client.initialize("HostName=your-iot-hub.azure-devices.net;DeviceId=ids-device;SharedAccessKey=your-key");
        initialized = true;
    }
    
    bool threat_detected = false;
    std::string threat_type;
    
    if (ddos_detector.analyze_packet(packet)) {
        threat_detected = true;
        threat_type = "DDoS";
        Logger::warn("DDoS attack detected from " + packet.source_ip);
    }
    
    if (brute_force_detector.analyze_packet(packet)) {
        threat_detected = true;
        threat_type = "BruteForce";
        Logger::warn("Brute force attack detected from " + packet.source_ip);
    }
    
    if (port_scan_detector.analyze_packet(packet)) {
        threat_detected = true;
        threat_type = "PortScan";
        Logger::warn("Port scan detected from " + packet.source_ip);
    }
    
    double ml_score = ml_engine.analyze_packet(packet);
    if (ml_score > ml_engine.get_threshold()) {
        threat_detected = true;
        threat_type = "ML_Anomaly";
        Logger::warn("ML anomaly detected from " + packet.source_ip + " (score: " + std::to_string(ml_score) + ")");
    }
    
    if (threat_detected) {
        ThreatAlert alert;
        alert.alert_id = "ALERT_" + std::to_string(std::chrono::system_clock::now().time_since_epoch().count());
        alert.threat_type = threat_type;
        alert.severity = "HIGH";
        alert.source_ip = packet.source_ip;
        alert.description = "Threat detected: " + threat_type;
        alert.timestamp = std::chrono::system_clock::now();
        alert.metadata["dest_ip"] = packet.dest_ip;
        alert.metadata["dest_port"] = std::to_string(packet.dest_port);
        alert.metadata["protocol"] = packet.protocol;
        alert.metadata["ml_score"] = std::to_string(ml_score);
        
        iot_client.send_alert(alert);
    }
}

int main(int argc, char* argv[]) {
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    Logger::initialize();
    Logger::info("Azure IDS starting...");
    
    std::string interface_name = "eth0";
    if (argc > 1) {
        interface_name = argv[1];
    }
    
    PacketCapture packet_capture;
    
    if (!packet_capture.initialize(interface_name)) {
        Logger::error("Failed to initialize packet capture: " + packet_capture.get_last_error());
        return 1;
    }
    
    packet_capture.set_packet_callback(packet_handler);
    packet_capture.set_promiscuous_mode(true);
    packet_capture.set_buffer_size(65536);
    packet_capture.set_timeout(1000);
    
    Logger::info("Starting packet capture on interface: " + interface_name);
    packet_capture.start_capture();
    
    while (running.load()) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
    
    Logger::info("Stopping packet capture...");
    packet_capture.stop_capture();
    
    Logger::info("Azure IDS shutdown complete");
    Logger::shutdown();
    
    return 0;
}

