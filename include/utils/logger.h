#pragma once

#include <string>
#include <fstream>
#include <mutex>
#include <memory>

namespace AzureIDS {

class Logger {
public:
    static void initialize(const std::string& log_file = "azure_ids.log");
    static void shutdown();
    
    static void info(const std::string& message);
    static void warn(const std::string& message);
    static void error(const std::string& message);
    static void debug(const std::string& message);
    
    static void set_level(const std::string& level);
    static std::string get_level();

private:
    static void log(const std::string& level, const std::string& message);
    static std::string get_timestamp();
    
    static std::unique_ptr<std::ofstream> log_file_;
    static std::string log_level_;
    static std::mutex mutex_;
    static bool initialized_;
};

}

