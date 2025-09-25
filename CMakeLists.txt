cmake_minimum_required(VERSION 3.16)
project(AzureIDS VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(PkgConfig REQUIRED)
find_package(OpenSSL REQUIRED)
find_package(Boost REQUIRED COMPONENTS system filesystem thread)

pkg_check_modules(LIBPCAP REQUIRED libpcap)

include_directories(${LIBPCAP_INCLUDE_DIRS})
link_directories(${LIBPCAP_LIBRARY_DIRS})

set(SOURCES
    src/main.cpp
    src/core/packet_capture.cpp
    src/core/ml_engine.cpp
    src/azure/iot_hub_client.cpp
    src/detection/ddos_detector.cpp
    src/detection/brute_force_detector.cpp
    src/detection/port_scan_detector.cpp
    src/utils/logger.cpp
    src/utils/crypto_utils.cpp
)

set(HEADERS
    include/core/packet_capture.h
    include/core/ml_engine.h
    include/azure/iot_hub_client.h
    include/detection/ddos_detector.h
    include/detection/brute_force_detector.h
    include/detection/port_scan_detector.h
    include/utils/logger.h
    include/utils/crypto_utils.h
    include/common/types.h
    include/common/constants.h
)

add_executable(${PROJECT_NAME} ${SOURCES} ${HEADERS})

target_link_libraries(${PROJECT_NAME}
    ${LIBPCAP_LIBRARIES}
    OpenSSL::SSL
    OpenSSL::Crypto
    ${Boost_LIBRARIES}
    pthread
    dl
)

target_include_directories(${PROJECT_NAME} PRIVATE include)

install(TARGETS ${PROJECT_NAME} DESTINATION bin)
