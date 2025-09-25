#pragma once

#include <string>

namespace AzureIDS {

const std::string AZURE_IOT_HUB_ENDPOINT = "https://your-iot-hub.azure-devices.net";
const std::string AZURE_FUNCTIONS_ENDPOINT = "https://your-function-app.azurewebsites.net";
const std::string AZURE_KEY_VAULT_URL = "https://your-keyvault.vault.azure.net/";
const std::string AZURE_MONITOR_ENDPOINT = "https://your-workspace.monitor.azure.com";
const std::string AZURE_SENTINEL_ENDPOINT = "https://your-workspace.sentinel.azure.com";

const std::string AZURE_TENANT_ID = "your-tenant-id";
const std::string AZURE_CLIENT_ID = "your-client-id";
const std::string AZURE_CLIENT_SECRET = "your-client-secret";

const int DEFAULT_PACKET_BUFFER_SIZE = 65536;
const int DEFAULT_ML_WINDOW_SIZE = 100;
const int DEFAULT_THREAT_THRESHOLD = 0.7;

const std::string DASHBOARD_HOST = "0.0.0.0";
const int DASHBOARD_PORT = 8080;

const std::string LOG_LEVEL_INFO = "INFO";
const std::string LOG_LEVEL_WARN = "WARN";
const std::string LOG_LEVEL_ERROR = "ERROR";
const std::string LOG_LEVEL_DEBUG = "DEBUG";

}

