cmake_minimum_required(VERSION 3.20)
project(Examples)
include(CTest)

find_library(POLYGONID polygonid-darwin-arm64 ../build)

add_executable(test1 test.c)
target_link_libraries(test1 PUBLIC ${POLYGONID})
add_test(NAME Test1 COMMAND test1)
