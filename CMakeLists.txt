cmake_minimum_required(VERSION 3.16)
project(pcap_test)

set(CMAKE_CXX_STANDARD 17)

add_executable(pcap_test pcap_test.cpp)
target_link_libraries(pcap_test -lpcap)