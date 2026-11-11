cmake_minimum_required(VERSION 3.22)

# The desktop client's native library.
#
# core-native already builds a shared `veil-c` target for Android; this target
# builds the same sources for the host, so a desktop build does not need the
# Android SDK or the NDK in the way. The result is what JNA loads.
project(veil_abi C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "" FORCE)
endif()

set(VEIL_SRC ${CMAKE_CURRENT_SOURCE_DIR}/../core-native/src/main/cpp)
set(MONOCYPHER_DIR ${VEIL_SRC}/third_party/monocypher)

add_library(monocypher_host STATIC
        ${MONOCYPHER_DIR}/monocypher.c
        ${MONOCYPHER_DIR}/monocypher-ed25519.c)
target_include_directories(monocypher_host PUBLIC ${MONOCYPHER_DIR})
target_compile_options(monocypher_host PRIVATE -w)

add_library(veilc SHARED
        ${VEIL_SRC}/veil/veil_c.cpp
        ${VEIL_SRC}/veil/crypto.cpp
        ${VEIL_SRC}/veil/keys.cpp
        ${VEIL_SRC}/veil/random.cpp
        ${VEIL_SRC}/veil/ratchet.cpp
    ${VEIL_SRC}/veil/group.cpp
        ${VEIL_SRC}/veil/engine.cpp)

target_include_directories(veilc PUBLIC ${VEIL_SRC})
target_link_libraries(veilc PRIVATE monocypher_host)

set_target_properties(veilc PROPERTIES
        CXX_VISIBILITY_PRESET hidden
        VISIBILITY_INLINES_HIDDEN ON
        # Where the desktop client's Gradle task looks for it.
        LIBRARY_OUTPUT_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/../build/abi"
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/../build/abi")

target_compile_definitions(veilc PRIVATE VEIL_C_BUILD_DLL)

if(MSVC)
    target_compile_options(veilc PRIVATE /W4)
else()
    target_compile_options(veilc PRIVATE -Wall -Wextra -Wno-unused-parameter)
endif()

if(WIN32)
    target_link_libraries(veilc PRIVATE bcrypt)
endif()