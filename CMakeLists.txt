cmake_minimum_required(VERSION 3.16)
project(VMProtectUnpacker LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)


# Get the current git commit hash
execute_process(
    COMMAND git rev-parse --short HEAD
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
    OUTPUT_VARIABLE GIT_COMMIT_HASH
    OUTPUT_STRIP_TRAILING_WHITESPACE
    ERROR_QUIET
)

if(NOT GIT_COMMIT_HASH)
    set(GIT_COMMIT_HASH "unknown")
endif()

add_compile_definitions(GIT_COMMIT_HASH="${GIT_COMMIT_HASH}")


# Capstone paths (optional)
include_directories("C:/Program Files/capstone/include")
link_directories("C:/Program Files/capstone/lib")

# Project includes
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)

# Find source files
file(GLOB_RECURSE SOURCES "src/*.cpp")
file(GLOB_RECURSE HEADERS "include/**/*.h")

message(STATUS "Sources found: ${SOURCES}")

if(NOT SOURCES)
    message(FATAL_ERROR "No source files found!")
endif()

# Add executable
add_executable(VMProtectUnpacker ${SOURCES} ${HEADERS})

# Link Capstone
target_link_libraries(VMProtectUnpacker capstone)
