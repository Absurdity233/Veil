cmake_minimum_required(VERSION 3.22)
project(veil_host_tests C CXX)

# Host build of the protocol engine.
#
# The Android build compiles the same sources through the NDK toolchain; this
# target exists so the crypto can be exercised on a workstation with no device
# and no Android SDK in the way. It produces a single executable that runs
# every check and exits non-zero on failure, which is what CI wants.
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "" FORCE)
endif()

set(VEIL_SRC ${CMAKE_CURRENT_SOURCE_DIR}/../src/main/cpp)
set(MONOCYPHER_DIR ${VEIL_SRC}/third_party/monocypher)

add_library(monocypher_host STATIC
        ${MONOCYPHER_DIR}/monocypher.c
        ${MONOCYPHER_DIR}/monocypher-ed25519.c)
target_include_directories(monocypher_host PUBLIC ${MONOCYPHER_DIR})
# Monocypher is plain C with its own warning habits; silencing it keeps the
# warnings that matter visible.
target_compile_options(monocypher_host PRIVATE -w)

add_executable(veil_host_tests
        ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_core.cpp
        ${VEIL_SRC}/veil/crypto.cpp
        ${VEIL_SRC}/veil/keys.cpp
        ${VEIL_SRC}/veil/random.cpp
        ${VEIL_SRC}/veil/ratchet.cpp
        ${VEIL_SRC}/veil/engine.cpp)

target_include_directories(veil_host_tests PRIVATE ${VEIL_SRC})
target_link_libraries(veil_host_tests PRIVATE monocypher_host)

# Tests are where the compiler's opinion is cheapest to act on, so the warning
# set here is stricter than the library's own. MSVC spells these differently
# and rejects the GCC flags outright rather than ignoring them.
if(MSVC)
    target_compile_options(veil_host_tests PRIVATE /W4)
else()
    target_compile_options(veil_host_tests PRIVATE -Wall -Wextra -Wno-unused-parameter)
endif()

if(WIN32)
    target_link_libraries(veil_host_tests PRIVATE bcrypt)
endif()

enable_testing()
add_test(NAME veil_host_tests COMMAND veil_host_tests)

# The C ABI, tested the way the desktop and web clients use it: through the
# header, with the caller owning every buffer.
add_executable(veil_c_abi_tests
        ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_c_abi.cpp
        ${VEIL_SRC}/veil/veil_c.cpp
        ${VEIL_SRC}/veil/crypto.cpp
        ${VEIL_SRC}/veil/keys.cpp
        ${VEIL_SRC}/veil/random.cpp
        ${VEIL_SRC}/veil/ratchet.cpp
        ${VEIL_SRC}/veil/engine.cpp)

target_include_directories(veil_c_abi_tests PRIVATE ${VEIL_SRC})
target_link_libraries(veil_c_abi_tests PRIVATE monocypher_host)

if(MSVC)
    target_compile_options(veil_c_abi_tests PRIVATE /W4)
else()
    target_compile_options(veil_c_abi_tests PRIVATE -Wall -Wextra -Wno-unused-parameter)
endif()

if(WIN32)
    target_link_libraries(veil_c_abi_tests PRIVATE bcrypt)
endif()

add_test(NAME veil_c_abi_tests COMMAND veil_c_abi_tests)