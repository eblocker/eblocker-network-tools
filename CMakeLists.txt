cmake_minimum_required(VERSION 3.5)
project(network_tools)

set(CMAKE_CXX_STANDARD 11)

add_executable(arp_read arp_read.c)
target_link_libraries(arp_read hiredis pcap)

add_executable(arp_write arp_write.c)
target_link_libraries(arp_write hiredis net)

add_executable(script_wrapper script_wrapper.c)

add_executable(dhcp_discover dhcp_discover.c)
target_link_libraries(dhcp_discover net pcap)