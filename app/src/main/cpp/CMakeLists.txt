cmake_minimum_required(VERSION 3.22.1)
project("devguard_native")

add_library(devguard_native SHARED devguard_native.cpp)

find_library(log-lib log)

target_link_libraries(devguard_native ${log-lib})
