#include "core/ml_engine.h"
#include "utils/logger.h"
#include <algorithm>
#include <numeric>
#include <cmath>
#include <random>

namespace AzureIDS {

class MLEngine::Impl {
public:
    std::vector<double> weights_;
    std::vector<double> biases_;
    std::vector<std::string> feature_names_;
    std::map<std::string, double> metrics_;
    
    std::random_device rd_;
    std::mt19937 gen_;
    std::uniform_real_distribution<> dis_;
    
    Impl() : gen_(rd_()), dis_(-1.0, 1.0) {
        feature_names_ = {
            "packet_rate", "byte_rate", "connection_duration",
            "port_entropy", "protocol_distribution", "payload_entropy"
        };
    }
    
    double sigmoid(double x) {
        return 1.0 / (1.0 + std::exp(-x));
    }
    
    double relu(double x) {
        return std::max(0.0, x);
    }
    
    double calculate_entropy(const std::vector<double>& values) {
        if (values.empty()) return 0.0;
        
        double sum = std::accumulate(values.begin(), values.end(), 0.0);
        if (sum == 0.0) return 0.0;
        
        double entropy = 0.0;
        for (double value : values) {
            if (value > 0.0) {
                double p = value / sum;
                entropy -= p * std::log2(p);
            }
        }
        return entropy;
    }
    
    void initialize_weights(size_t feature_count) {
        weights_.resize(feature_count);
        for (auto& weight : weights_) {
            weight = dis_(gen_);
        }
        biases_.resize(1);
        biases_[0] = dis_(gen_);
    }
    
    double predict(const std::vector<double>& features) {
        if (features.size() != weights_.size()) {
            return 0.0;
        }
        
        double sum = biases_[0];
        for (size_t i = 0; i < features.size(); ++i) {
            sum += features[i] * weights_[i];
        }
        
        return sigmoid(sum);
    }
    
    void train_epoch(const std::vector<std::vector<double>>& features, 
                    const std::vector<double>& labels, 
                    double learning_rate) {
        if (features.empty() || features.size() != labels.size()) {
            return;
        }
        
        size_t feature_count = features[0].size();
        if (weights_.size() != feature_count) {
            initialize_weights(feature_count);
        }
        
        std::vector<double> weight_gradients(weights_.size(), 0.0);
        double bias_gradient = 0.0;
        
        for (size_t i = 0; i < features.size(); ++i) {
            double prediction = predict(features[i]);
            double error = prediction - labels[i];
            
            for (size_t j = 0; j < weights_.size(); ++j) {
                weight_gradients[j] += error * features[i][j];
            }
            bias_gradient += error;
        }
        
        for (size_t i = 0; i < weights_.size(); ++i) {
            weights_[i] -= learning_rate * weight_gradients[i] / features.size();
        }
        biases_[0] -= learning_rate * bias_gradient / features.size();
    }
};

MLEngine::MLEngine() 
    : impl_(std::make_unique<Impl>())
    , initialized_(false)
    , threshold_(DEFAULT_THREAT_THRESHOLD) {
}

MLEngine::~MLEngine() = default;

bool MLEngine::initialize() {
    std::lock_guard<std::mutex> lock(mutex_);
    
    if (initialized_.load()) {
        return true;
    }
    
    impl_->initialize_weights(impl_->feature_names_.size());
    initialized_.store(true);
    
    Logger::info("ML Engine initialized with " + std::to_string(impl_->feature_names_.size()) + " features");
    return true;
}

void MLEngine::shutdown() {
    std::lock_guard<std::mutex> lock(mutex_);
    initialized_.store(false);
    Logger::info("ML Engine shutdown");
}

double MLEngine::analyze_packet(const PacketInfo& packet) {
    if (!initialized_.load()) {
        return 0.0;
    }
    
    std::vector<double> features = {
        static_cast<double>(packet.packet_size),
        static_cast<double>(packet.payload.size()),
        static_cast<double>(packet.source_port),
        static_cast<double>(packet.dest_port)
    };
    
    std::lock_guard<std::mutex> lock(mutex_);
    return impl_->predict(features);
}

double MLEngine::analyze_flow(const NetworkFlow& flow) {
    if (!initialized_.load()) {
        return 0.0;
    }
    
    auto duration = std::chrono::duration_cast<std::chrono::seconds>(
        flow.last_seen - flow.start_time).count();
    
    std::vector<double> features = {
        static_cast<double>(flow.packet_count) / std::max(1.0, static_cast<double>(duration)),
        static_cast<double>(flow.byte_count) / std::max(1.0, static_cast<double>(duration)),
        static_cast<double>(duration),
        static_cast<double>(flow.source_port),
        static_cast<double>(flow.dest_port)
    };
    
    std::lock_guard<std::mutex> lock(mutex_);
    return impl_->predict(features);
}

MLFeatures MLEngine::extract_features(const std::vector<PacketInfo>& packets) {
    MLFeatures features;
    
    if (packets.empty()) {
        return features;
    }
    
    auto start_time = packets.front().timestamp;
    auto end_time = packets.back().timestamp;
    auto duration = std::chrono::duration_cast<std::chrono::seconds>(end_time - start_time).count();
    
    if (duration == 0) duration = 1;
    
    std::vector<double> packet_sizes;
    std::vector<double> payload_sizes;
    std::vector<double> source_ports;
    std::vector<double> dest_ports;
    std::map<std::string, int> protocol_counts;
    
    for (const auto& packet : packets) {
        packet_sizes.push_back(static_cast<double>(packet.packet_size));
        payload_sizes.push_back(static_cast<double>(packet.payload.size()));
        source_ports.push_back(static_cast<double>(packet.source_port));
        dest_ports.push_back(static_cast<double>(packet.dest_port));
        protocol_counts[packet.protocol]++;
    }
    
    features.packet_rates = {static_cast<double>(packets.size()) / duration};
    features.byte_rates = {std::accumulate(packet_sizes.begin(), packet_sizes.end(), 0.0) / duration};
    features.connection_durations = {static_cast<double>(duration)};
    features.port_entropy = {impl_->calculate_entropy(source_ports)};
    
    std::vector<double> protocol_dist;
    for (const auto& pair : protocol_counts) {
        protocol_dist.push_back(static_cast<double>(pair.second));
    }
    features.protocol_distribution = protocol_dist;
    features.payload_entropy = {impl_->calculate_entropy(payload_sizes)};
    
    return features;
}

void MLEngine::train_model(const std::vector<MLFeatures>& features, const std::vector<double>& labels) {
    if (features.empty() || features.size() != labels.size()) {
        Logger::error("Invalid training data");
        return;
    }
    
    std::vector<std::vector<double>> feature_vectors;
    for (const auto& f : features) {
        std::vector<double> vector;
        vector.insert(vector.end(), f.packet_rates.begin(), f.packet_rates.end());
        vector.insert(vector.end(), f.byte_rates.begin(), f.byte_rates.end());
        vector.insert(vector.end(), f.connection_durations.begin(), f.connection_durations.end());
        vector.insert(vector.end(), f.port_entropy.begin(), f.port_entropy.end());
        vector.insert(vector.end(), f.protocol_distribution.begin(), f.protocol_distribution.end());
        vector.insert(vector.end(), f.payload_entropy.begin(), f.payload_entropy.end());
        feature_vectors.push_back(vector);
    }
    
    std::lock_guard<std::mutex> lock(mutex_);
    
    const int epochs = 100;
    const double learning_rate = 0.01;
    
    for (int epoch = 0; epoch < epochs; ++epoch) {
        impl_->train_epoch(feature_vectors, labels, learning_rate);
    }
    
    Logger::info("Model training completed with " + std::to_string(epochs) + " epochs");
}

void MLEngine::set_threshold(double threshold) {
    threshold_.store(threshold);
}

double MLEngine::get_threshold() const {
    return threshold_.load();
}

std::vector<std::string> MLEngine::get_feature_names() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return impl_->feature_names_;
}

std::map<std::string, double> MLEngine::get_model_metrics() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return impl_->metrics_;
}

void MLEngine::load_model(const std::string& model_path) {
    Logger::info("Loading model from: " + model_path);
}

void MLEngine::save_model(const std::string& model_path) {
    Logger::info("Saving model to: " + model_path);
}

}

