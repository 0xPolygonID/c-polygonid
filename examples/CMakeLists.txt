cmake_minimum_required(VERSION 3.18)

project(Examples)

include(CTest)
include(FetchContent)

if(APPLE)
	set(CMAKE_MACOSX_RPATH 1)
endif()

FetchContent_Declare(
  cJSON
  URL https://github.com/DaveGamble/cJSON/archive/refs/tags/v1.7.15.tar.gz
)

FetchContent_MakeAvailable(cJSON)

include_directories(${cJSON_SOURCE_DIR})

add_executable(json_functions_tests json_functions_tests.c ${cJSON_SOURCE_DIR}/cJSON.c)

find_library(POLYGONID polygonid-darwin-arm64 ../ios)

target_link_libraries(json_functions_tests PUBLIC ${POLYGONID})

if(APPLE)
	target_link_libraries(json_functions_tests PUBLIC
		"-framework CoreServices"
		"-framework Security"
		"-framework CoreFoundation")
endif()

add_test(NAME JsonFunctionsTests
    COMMAND json_functions_tests
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR})
