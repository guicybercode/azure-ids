#pragma once

#include "common/types.h"
#include <vector>
#include <map>
#include <memory>
#include <thread>
#include <atomic>
#include <mutex>

namespace AzureIDS {

class MLEngine {
public:
    MLEngine();
    ~MLEngine();

    bool initialize();
    void shutdown();

    double analyze_packet(const PacketInfo& packet);
    double analyze_flow(const NetworkFlow& flow);
    MLFeatures extract_features(const std::vector<PacketInfo>& packets);
    
    void train_model(const std::vector<MLFeatures>& features, const std::vector<double>& labels);
    void load_model(const std::string& model_path);
    void save_model(const std::string& model_path);

    void set_threshold(double threshold);
    double get_threshold() const;

    std::vector<std::string> get_feature_names() const;
    std::map<std::string, double> get_model_metrics() const;

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
    
    std::atomic<bool> initialized_;
    std::atomic<double> threshold_;
    mutable std::mutex mutex_;
};

}

