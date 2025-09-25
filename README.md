# Azure IDS - Advanced Cybersecurity Intrusion Detection System

A comprehensive C++ intrusion detection system (IDS) that integrates with Microsoft Azure services for real-time network monitoring, machine learning-based threat detection, and automated response capabilities.

## Features

### Core Capabilities
- **Real-time Packet Capture**: Uses libpcap for high-performance network traffic monitoring
- **Machine Learning Engine**: Custom ML algorithms for anomaly detection and threat classification
- **Multi-layered Threat Detection**:
  - DDoS attack detection with rate limiting and connection analysis
  - Brute force attack detection with IP lockout mechanisms
  - Port scanning detection with entropy analysis
  - IP reputation checking and blacklist management

### Azure Integration
- **Azure IoT Hub**: Real-time data ingestion and device management
- **Azure Functions**: Automated response triggers and serverless processing
- **Azure Key Vault**: Secure key management and credential storage
- **Azure Monitor**: Comprehensive logging and metrics collection
- **Azure Sentinel**: Security information and event management (SIEM)

### Security Features
- **Encryption**: OpenSSL-based cryptographic operations
- **Authentication**: Azure Active Directory integration
- **Secure Communication**: TLS/SSL for all Azure service communications
- **Automated Response**: Configurable threat response actions

## Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Network       │    │   Azure IDS     │    │   Azure Cloud   │
│   Interface     │───▶│   Core Engine   │───▶│   Services       │
└─────────────────┘    └─────────────────┘    └─────────────────┘
                              │
                              ▼
                       ┌─────────────────┐
                       │   Web Dashboard │
                       │   (Azure AD)    │
                       └─────────────────┘
```

## Prerequisites

### System Requirements
- Linux (Ubuntu 20.04+ recommended)
- GCC 7.0+ or Clang 6.0+
- CMake 3.16+
- Root privileges for packet capture

### Dependencies
```bash
# Ubuntu/Debian
sudo apt-get update
sudo apt-get install build-essential cmake pkg-config
sudo apt-get install libpcap-dev libssl-dev libboost-all-dev
sudo apt-get install libcpprest-dev

# CentOS/RHEL
sudo yum install gcc-c++ cmake pkgconfig
sudo yum install libpcap-devel openssl-devel boost-devel
sudo yum install cpprest-devel
```

## Installation

1. **Clone the repository**:
```bash
git clone https://github.com/your-org/azure-ids.git
cd azure-ids
```

2. **Configure Azure services**:
```bash
# Update configuration in include/common/constants.h
# Set your Azure service endpoints and credentials
```

3. **Build the project**:
```bash
mkdir build
cd build
cmake ..
make -j$(nproc)
```

4. **Install**:
```bash
sudo make install
```

## Configuration

### Azure Service Configuration

Update the constants in `include/common/constants.h`:

```cpp
const std::string AZURE_IOT_HUB_ENDPOINT = "https://your-iot-hub.azure-devices.net";
const std::string AZURE_TENANT_ID = "your-tenant-id";
const std::string AZURE_CLIENT_ID = "your-client-id";
const std::string AZURE_CLIENT_SECRET = "your-client-secret";
```

### Detection Parameters

Configure threat detection thresholds:

```cpp
// DDoS Detection
ddos_detector.initialize(100.0, 60, 50);  // threshold, window_seconds, max_connections

// Brute Force Detection  
brute_force_detector.initialize(5, 15, 30);  // max_attempts, window_minutes, lockout_minutes

// Port Scan Detection
port_scan_detector.initialize(10, 60, 0.7);  // min_ports, window_seconds, threshold
```

## Usage

### Basic Operation

```bash
# Run with default interface (eth0)
sudo ./AzureIDS

# Run with specific interface
sudo ./AzureIDS wlan0

# Run with custom configuration
sudo ./AzureIDS eth0 --config /path/to/config.json
```

### Command Line Options

```bash
./AzureIDS [interface] [options]

Options:
  --config FILE     Configuration file path
  --log-level LEVEL Set logging level (DEBUG, INFO, WARN, ERROR)
  --daemon          Run as daemon
  --help            Show help message
```

### Docker Deployment

```dockerfile
FROM ubuntu:20.04

RUN apt-get update && apt-get install -y \
    libpcap-dev libssl-dev libboost-all-dev \
    libcpprest-dev

COPY . /app
WORKDIR /app
RUN mkdir build && cd build && cmake .. && make

CMD ["./build/AzureIDS"]
```

## API Reference

### Core Classes

#### PacketCapture
```cpp
PacketCapture capture;
capture.initialize("eth0");
capture.set_packet_callback(packet_handler);
capture.start_capture();
```

#### MLEngine
```cpp
MLEngine ml_engine;
ml_engine.initialize();
double threat_score = ml_engine.analyze_packet(packet);
```

#### IoTHubClient
```cpp
IoTHubClient iot_client;
iot_client.initialize(connection_string);
iot_client.send_alert(threat_alert);
```

### Threat Detection

#### DDoS Detection
```cpp
DDoSDetector ddos_detector;
ddos_detector.initialize(100.0, 60, 50);
bool is_ddos = ddos_detector.analyze_packet(packet);
```

#### Brute Force Detection
```cpp
BruteForceDetector bf_detector;
bf_detector.initialize(5, 15, 30);
bool is_brute_force = bf_detector.analyze_packet(packet);
```

## Monitoring and Alerting

### Azure Monitor Integration

The system automatically sends metrics to Azure Monitor:

- **Network Traffic Metrics**: Packet rates, byte counts, protocol distribution
- **Threat Detection Metrics**: Alert counts, false positive rates, detection accuracy
- **System Performance**: CPU usage, memory consumption, processing latency

### Alert Types

1. **DDoS Alerts**: High packet rates, connection floods
2. **Brute Force Alerts**: Multiple failed authentication attempts
3. **Port Scan Alerts**: Systematic port probing
4. **ML Anomaly Alerts**: Unusual traffic patterns detected by ML models

### Response Actions

Configured automated responses:

- **Log Only**: Record threat for analysis
- **Block IP**: Automatically block suspicious IP addresses
- **Rate Limit**: Throttle traffic from suspicious sources
- **Quarantine**: Isolate compromised systems
- **Notify Admin**: Send alerts to security team

## Performance Optimization

### Tuning Parameters

```cpp
// Packet capture optimization
capture.set_buffer_size(65536);      // Increase buffer size
capture.set_timeout(1000);           // Set capture timeout

// ML engine optimization
ml_engine.set_threshold(0.7);        // Adjust detection threshold
ml_engine.set_window_size(100);      // Set analysis window
```

### System Requirements

- **Minimum**: 2 CPU cores, 4GB RAM, 10GB storage
- **Recommended**: 4+ CPU cores, 8GB+ RAM, SSD storage
- **Network**: Gigabit Ethernet for high-traffic environments

## Security Considerations

### Network Security
- Run with minimal required privileges
- Use dedicated network interfaces for monitoring
- Implement proper firewall rules
- Encrypt all communications with Azure services

### Data Protection
- All sensitive data encrypted at rest and in transit
- Secure key management through Azure Key Vault
- Regular security updates and patches
- Audit logging for all system activities

## Troubleshooting

### Common Issues

1. **Permission Denied**: Ensure running with root privileges
2. **Interface Not Found**: Check interface name and availability
3. **Azure Connection Failed**: Verify credentials and network connectivity
4. **High CPU Usage**: Adjust capture buffer size and ML parameters

### Debug Mode

```bash
# Enable debug logging
sudo ./AzureIDS eth0 --log-level DEBUG

# Check system logs
journalctl -u azure-ids -f
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Support

For support and questions:
- Create an issue on GitHub
- Check the documentation wiki
- Contact the development team

## Roadmap

- [ ] Web dashboard with real-time visualization
- [ ] Additional ML models and algorithms
- [ ] Integration with more Azure services
- [ ] Mobile app for monitoring
- [ ] Advanced threat hunting capabilities
- [ ] Machine learning model training pipeline
