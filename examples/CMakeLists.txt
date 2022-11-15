cmake_minimum_required(VERSION 3.18)
project(Examples)
include(CTest)

find_library(POLYGONID polygonid-darwin-arm64 ../build)

add_executable(json_functions_tests json_functions_tests.c)
target_link_libraries(json_functions_tests PUBLIC ${POLYGONID})
target_link_options(json_functions_tests BEFORE PRIVATE "SHELL:-framework CoreFoundation")
add_test(NAME JsonFunctionsTests
    COMMAND json_functions_tests
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR})
