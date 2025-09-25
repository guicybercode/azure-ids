#include "utils/logger.h"
#include <iostream>
#include <iomanip>
#include <sstream>
#include <chrono>

namespace AzureIDS {

std::unique_ptr<std::ofstream> Logger::log_file_;
std::string Logger::log_level_ = "INFO";
std::mutex Logger::mutex_;
bool Logger::initialized_ = false;

void Logger::initialize(const std::string& log_file) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    if (initialized_) {
        return;
    }
    
    log_file_ = std::make_unique<std::ofstream>(log_file, std::ios::app);
    initialized_ = true;
    
    info("Logger initialized");
}

void Logger::shutdown() {
    std::lock_guard<std::mutex> lock(mutex_);
    
    if (log_file_) {
        log_file_->close();
        log_file_.reset();
    }
    
    initialized_ = false;
}

void Logger::info(const std::string& message) {
    log("INFO", message);
}

void Logger::warn(const std::string& message) {
    log("WARN", message);
}

void Logger::error(const std::string& message) {
    log("ERROR", message);
}

void Logger::debug(const std::string& message) {
    log("DEBUG", message);
}

void Logger::set_level(const std::string& level) {
    std::lock_guard<std::mutex> lock(mutex_);
    log_level_ = level;
}

std::string Logger::get_level() {
    std::lock_guard<std::mutex> lock(mutex_);
    return log_level_;
}

void Logger::log(const std::string& level, const std::string& message) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    if (!initialized_) {
        return;
    }
    
    std::string timestamp = get_timestamp();
    std::string log_entry = "[" + timestamp + "] [" + level + "] " + message;
    
    std::cout << log_entry << std::endl;
    
    if (log_file_) {
        *log_file_ << log_entry << std::endl;
        log_file_->flush();
    }
}

std::string Logger::get_timestamp() {
    auto now = std::chrono::system_clock::now();
    auto time_t = std::chrono::system_clock::to_time_t(now);
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        now.time_since_epoch()) % 1000;
    
    std::ostringstream oss;
    oss << std::put_time(std::localtime(&time_t), "%Y-%m-%d %H:%M:%S");
    oss << '.' << std::setfill('0') << std::setw(3) << ms.count();
    
    return oss.str();
}

}

