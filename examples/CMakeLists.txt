cmake_minimum_required(VERSION 3.18)

project(Examples)

include(CTest)

if(APPLE)
	set(CMAKE_MACOSX_RPATH 1)
endif()

## Begin cJSON

## Download and compile cJSON locally

# include(FetchContent)
# FetchContent_Declare(
#   cJSON
#   URL https://github.com/DaveGamble/cJSON/archive/refs/tags/v1.7.15.tar.gz
# )
# FetchContent_MakeAvailable(cJSON)
# include_directories(${cJSON_SOURCE_DIR})
# add_executable(json_functions_tests json_functions_tests.c ${cJSON_SOURCE_DIR}/cJSON.c)

## Compile with system installed cJSON

find_package(cJSON REQUIRED)
include_directories(${CJSON_INCLUDE_DIRS})
add_executable(json_functions_tests json_functions_tests.c)
target_link_libraries(json_functions_tests PUBLIC ${CJSON_LIBRARIES})

## End cJSON

string(TOLOWER ${CMAKE_SYSTEM_NAME} SYSTEM_NAME)
string(JOIN "-" LIB_ARCH "polygonid" ${SYSTEM_NAME} ${CMAKE_SYSTEM_PROCESSOR})
message(STATUS "Want go library: " ${LIB_ARCH})

## Debug: show all defined variables
# get_cmake_property(_variableNames VARIABLES)
# list (SORT _variableNames)
# foreach (_variableName ${_variableNames})
#     message(STATUS "${_variableName}=${${_variableName}}")
# endforeach()

find_library(POLYGONID ${LIB_ARCH} polygonid PATHS ../ios REQUIRED NO_DEFAULT_PATH)
message(STATUS "Go library path: " ${POLYGONID})

target_link_libraries(json_functions_tests PUBLIC ${POLYGONID})

if(APPLE)
	target_link_libraries(json_functions_tests PUBLIC
		"-framework CoreServices"
		"-framework Security"
		"-framework CoreFoundation")
else()
	find_package(Threads REQUIRED)
	target_link_libraries(json_functions_tests PRIVATE Threads::Threads)
endif()

add_test(NAME JsonFunctionsTests
    COMMAND json_functions_tests
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR})
