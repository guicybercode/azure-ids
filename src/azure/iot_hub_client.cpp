#include "azure/iot_hub_client.h"
#include "utils/logger.h"
#include "utils/crypto_utils.h"
#include <cpprest/http_client.h>
#include <cpprest/json.h>
#include <chrono>
#include <sstream>
#include <iomanip>

using namespace web;
using namespace web::http;
using namespace web::http::client;
using namespace web::json;

namespace AzureIDS {

class IoTHubClient::Impl {
public:
    std::unique_ptr<http_client> client_;
    std::string sas_token_;
    std::chrono::system_clock::time_point token_expiry_;
    
    bool generate_sas_token(const std::string& connection_string) {
        auto now = std::chrono::system_clock::now();
        auto expiry = now + std::chrono::hours(1);
        
        std::string resource_uri = "your-iot-hub.azure-devices.net";
        std::string device_id = "ids-device";
        std::string shared_access_key = "your-shared-access-key";
        
        std::string string_to_sign = resource_uri + "\n" + std::to_string(
            std::chrono::duration_cast<std::chrono::seconds>(expiry.time_since_epoch()).count());
        
        std::string signature = CryptoUtils::hmac_sha256(string_to_sign, shared_access_key);
        std::string encoded_signature = CryptoUtils::base64_encode(signature);
        
        sas_token_ = "SharedAccessSignature sr=" + resource_uri + 
                    "&sig=" + encoded_signature + 
                    "&se=" + std::to_string(std::chrono::duration_cast<std::chrono::seconds>(expiry.time_since_epoch()).count());
        
        token_expiry_ = expiry;
        return true;
    }
    
    bool is_token_valid() {
        return std::chrono::system_clock::now() < token_expiry_;
    }
};

IoTHubClient::IoTHubClient()
    : impl_(std::make_unique<Impl>())
    , initialized_(false)
    , connected_(false)
    , retry_count_(3)
    , timeout_ms_(30000)
    , should_stop_(false) {
}

IoTHubClient::~IoTHubClient() {
    shutdown();
}

bool IoTHubClient::initialize(const std::string& connection_string) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    if (initialized_.load()) {
        return true;
    }
    
    connection_string_ = connection_string;
    
    try {
        impl_->client_ = std::make_unique<http_client>(U(AZURE_IOT_HUB_ENDPOINT));
        
        if (!impl_->generate_sas_token(connection_string)) {
            last_error_ = "Failed to generate SAS token";
            Logger::error(last_error_);
            return false;
        }
        
        initialized_.store(true);
        connected_.store(true);
        
        should_stop_.store(false);
        worker_thread_ = std::thread(&IoTHubClient::worker_loop, this);
        
        Logger::info("IoT Hub client initialized");
        return true;
        
    } catch (const std::exception& e) {
        last_error_ = "Exception during initialization: " + std::string(e.what());
        Logger::error(last_error_);
        return false;
    }
}

void IoTHubClient::shutdown() {
    if (!initialized_.load()) {
        return;
    }
    
    should_stop_.store(true);
    cv_.notify_all();
    
    if (worker_thread_.joinable()) {
        worker_thread_.join();
    }
    
    initialized_.store(false);
    connected_.store(false);
    
    Logger::info("IoT Hub client shutdown");
}

bool IoTHubClient::send_telemetry(const std::string& device_id, const std::string& data) {
    if (!initialized_.load() || !connected_.load()) {
        return false;
    }
    
    try {
        json::value telemetry;
        telemetry[U("deviceId")] = json::value::string(device_id);
        telemetry[U("timestamp")] = json::value::string(
            std::to_string(std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::system_clock::now().time_since_epoch()).count()));
        telemetry[U("data")] = json::value::string(data);
        
        std::string message = telemetry.serialize();
        
        std::lock_guard<std::mutex> lock(mutex_);
        message_queue_.push(message);
        cv_.notify_one();
        
        return true;
        
    } catch (const std::exception& e) {
        last_error_ = "Exception sending telemetry: " + std::string(e.what());
        Logger::error(last_error_);
        return false;
    }
}

bool IoTHubClient::send_alert(const ThreatAlert& alert) {
    if (!initialized_.load() || !connected_.load()) {
        return false;
    }
    
    try {
        json::value alert_data;
        alert_data[U("alertId")] = json::value::string(alert.alert_id);
        alert_data[U("threatType")] = json::value::string(alert.threat_type);
        alert_data[U("severity")] = json::value::string(alert.severity);
        alert_data[U("sourceIp")] = json::value::string(alert.source_ip);
        alert_data[U("description")] = json::value::string(alert.description);
        alert_data[U("timestamp")] = json::value::string(
            std::to_string(std::chrono::duration_cast<std::chrono::milliseconds>(
                alert.timestamp.time_since_epoch()).count()));
        
        json::value metadata;
        for (const auto& pair : alert.metadata) {
            metadata[U(pair.first)] = json::value::string(pair.second);
        }
        alert_data[U("metadata")] = metadata;
        
        std::string message = alert_data.serialize();
        
        std::lock_guard<std::mutex> lock(mutex_);
        message_queue_.push(message);
        cv_.notify_one();
        
        return true;
        
    } catch (const std::exception& e) {
        last_error_ = "Exception sending alert: " + std::string(e.what());
        Logger::error(last_error_);
        return false;
    }
}

bool IoTHubClient::send_flow_data(const NetworkFlow& flow) {
    if (!initialized_.load() || !connected_.load()) {
        return false;
    }
    
    try {
        json::value flow_data;
        flow_data[U("flowId")] = json::value::string(flow.flow_id);
        flow_data[U("sourceIp")] = json::value::string(flow.source_ip);
        flow_data[U("destIp")] = json::value::string(flow.dest_ip);
        flow_data[U("sourcePort")] = json::value::number(flow.source_port);
        flow_data[U("destPort")] = json::value::number(flow.dest_port);
        flow_data[U("protocol")] = json::value::string(flow.protocol);
        flow_data[U("packetCount")] = json::value::number(flow.packet_count);
        flow_data[U("byteCount")] = json::value::number(flow.byte_count);
        flow_data[U("startTime")] = json::value::string(
            std::to_string(std::chrono::duration_cast<std::chrono::milliseconds>(
                flow.start_time.time_since_epoch()).count()));
        flow_data[U("lastSeen")] = json::value::string(
            std::to_string(std::chrono::duration_cast<std::chrono::milliseconds>(
                flow.last_seen.time_since_epoch()).count()));
        
        std::string message = flow_data.serialize();
        
        std::lock_guard<std::mutex> lock(mutex_);
        message_queue_.push(message);
        cv_.notify_one();
        
        return true;
        
    } catch (const std::exception& e) {
        last_error_ = "Exception sending flow data: " + std::string(e.what());
        Logger::error(last_error_);
        return false;
    }
}

void IoTHubClient::set_connection_string(const std::string& connection_string) {
    std::lock_guard<std::mutex> lock(mutex_);
    connection_string_ = connection_string;
}

std::string IoTHubClient::get_connection_string() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return connection_string_;
}

bool IoTHubClient::is_connected() const {
    return connected_.load();
}

std::string IoTHubClient::get_last_error() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return last_error_;
}

void IoTHubClient::set_retry_count(int retry_count) {
    retry_count_ = retry_count;
}

void IoTHubClient::set_timeout(int timeout_ms) {
    timeout_ms_ = timeout_ms;
}

void IoTHubClient::worker_loop() {
    while (!should_stop_.load()) {
        std::unique_lock<std::mutex> lock(mutex_);
        cv_.wait(lock, [this] { return !message_queue_.empty() || should_stop_.load(); });
        
        if (should_stop_.load()) {
            break;
        }
        
        if (!message_queue_.empty()) {
            std::string message = message_queue_.front();
            message_queue_.pop();
            lock.unlock();
            
            if (!send_message_internal(message)) {
                Logger::error("Failed to send message to IoT Hub");
            }
        }
    }
}

bool IoTHubClient::send_message_internal(const std::string& message) {
    try {
        if (!impl_->is_token_valid()) {
            if (!impl_->generate_sas_token(connection_string_)) {
                return false;
            }
        }
        
        http_request request(methods::POST);
        request.set_request_uri(U("/devices/ids-device/messages/events"));
        request.headers().add(U("Authorization"), U(impl_->sas_token_));
        request.headers().add(U("Content-Type"), U("application/json"));
        request.set_body(message);
        
        auto response = impl_->client_->request(request).get();
        
        if (response.status_code() == 204) {
            return true;
        } else {
            Logger::error("IoT Hub request failed with status: " + std::to_string(response.status_code()));
            return false;
        }
        
    } catch (const std::exception& e) {
        Logger::error("Exception in send_message_internal: " + std::string(e.what()));
        return false;
    }
}

}

