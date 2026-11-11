cmake_minimum_required(VERSION 3.22.1)
project(veil C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(VEIL_ROOT ${CMAKE_CURRENT_SOURCE_DIR})
set(MONOCYPHER_DIR ${VEIL_ROOT}/third_party/monocypher)

# Monocypher is plain C with its own warning habits; silence it rather than
# let its noise hide warnings in our own code.
add_library(monocypher STATIC
        ${MONOCYPHER_DIR}/monocypher.c
        ${MONOCYPHER_DIR}/monocypher-ed25519.c)
target_include_directories(monocypher PUBLIC ${MONOCYPHER_DIR})
target_compile_options(monocypher PRIVATE -w)

add_library(veil-core STATIC
        ${VEIL_ROOT}/veil/crypto.cpp
        ${VEIL_ROOT}/veil/keys.cpp
        ${VEIL_ROOT}/veil/random.cpp
        ${VEIL_ROOT}/veil/ratchet.cpp
        ${VEIL_ROOT}/veil/engine.cpp)
target_include_directories(veil-core PUBLIC ${VEIL_ROOT})
target_link_libraries(veil-core PUBLIC monocypher)
target_compile_options(veil-core PRIVATE
        -Wall -Wextra -Wno-unused-parameter -fvisibility=hidden)

# The shared object the JVM loads. Everything except the JNI entry points is
# hidden, so the exported symbol table stays tiny.
add_library(veil SHARED ${VEIL_ROOT}/jni/veil_jni.cpp)
target_link_libraries(veil PRIVATE veil-core)
set_target_properties(veil PROPERTIES
        CXX_VISIBILITY_PRESET hidden
        VISIBILITY_INLINES_HIDDEN ON)
target_link_options(veil PRIVATE -Wl,--exclude-libs,ALL)
