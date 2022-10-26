cmake_minimum_required(VERSION 3.20)
project(Examples)
include(CTest)

find_library(POLYGONID polygonid-darwin-arm64 ../build)

add_executable(test test.c)
target_link_libraries(test PUBLIC ${POLYGONID})
add_test(NAME Test COMMAND test)
