cmake_minimum_required(VERSION 3.20)
project(Examples)
include(CTest)

find_library(POLYGONID polygonid-darwin-arm64 ../build)

add_executable(auth_v2_inputs auth_v2_inputs.c)
target_link_libraries(auth_v2_inputs PUBLIC ${POLYGONID})
add_test(NAME AuthV2Inputs
    COMMAND auth_v2_inputs
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR})
