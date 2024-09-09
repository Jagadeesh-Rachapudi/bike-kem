cmake_minimum_required(VERSION 3.0.0)
project(bike C)

# Set directories
set(INCLUDE_DIR ${PROJECT_SOURCE_DIR}/include)
set(SRC_DIR ${PROJECT_SOURCE_DIR}/src)
set(TESTS_DIR ${PROJECT_SOURCE_DIR}/tests)

# Include directories
include_directories(${INCLUDE_DIR})
include_directories(${INCLUDE_DIR}/internal)
include_directories(${SRC_DIR}/third_party_src)

# Include additional CMake scripts
include(cmake/arch.cmake)
include(cmake/compilation-flags.cmake)
include(cmake/clang-format.cmake)

# Add the BIKE library
add_library(${PROJECT_NAME} "")

# Add subdirectories for source files and tests
add_subdirectory(${SRC_DIR})

# Add your custom test file as a new executable
add_executable(bike-my-custom-test ${TESTS_DIR}/my_custom_test.c)

# Link the BIKE library to your custom test
target_link_libraries(bike-my-custom-test ${PROJECT_NAME})

# Optional: Link OpenSSL if the flag is set
if(LINK_OPENSSL)
  message(STATUS "Linking OpenSSL")
  find_package(OpenSSL REQUIRED)
  set(OPENSSL_USE_STATIC_LIBS TRUE)
  target_link_libraries(bike-my-custom-test OpenSSL::Crypto)
endif()

# Optional compilation flags for different build types
option(STANDALONE_IMPL "Build without OpenSSL" ON)
set(LEVEL 5)
