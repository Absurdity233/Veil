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

# The protocol engine. No I/O, no platform calls beyond the CSPRNG, so the same
# sources build for Android, the desktop and wasm.
add_library(veil-core STATIC
        ${VEIL_ROOT}/veil/crypto.cpp
        ${VEIL_ROOT}/veil/keys.cpp
        ${VEIL_ROOT}/veil/random.cpp
        ${VEIL_ROOT}/veil/ratchet.cpp
        ${VEIL_ROOT}/veil/group.cpp
        ${VEIL_ROOT}/veil/engine.cpp)
target_include_directories(veil-core PUBLIC ${VEIL_ROOT})
target_link_libraries(veil-core PUBLIC monocypher)
target_compile_options(veil-core PRIVATE
        -Wall -Wextra -Wno-unused-parameter -fvisibility=hidden)

if(EMSCRIPTEN)
    # ----------------------------------------------------------------
    # WebAssembly build.
    #
    # The engine is compiled to a single .wasm plus a thin JS glue file.
    # Export list is explicit: only the C ABI is reachable from JavaScript,
    # so the module's attack surface is exactly the interface in veil_c.h.
    #
    # Entropy comes from the host through veil_set_random_source, because a
    # wasm module has no syscall and no /dev/urandom.
    # ----------------------------------------------------------------
    add_executable(veil.js ${VEIL_ROOT}/veil/veil_c.cpp ${VEIL_ROOT}/wasm/rng_bridge.cpp)
    target_link_libraries(veil.js PRIVATE veil-core)

    set_target_properties(veil.js PROPERTIES
            OUTPUT_NAME "veil"
            SUFFIX ".js"
            RUNTIME_OUTPUT_DIRECTORY "${VEIL_ROOT}/../../web/public/wasm")

    target_link_options(veil.js PRIVATE
            --no-entry
            -sMODULARIZE=1
            -sEXPORT_ES6=1
            -sEXPORT_NAME=createVeilModule
            -sENVIRONMENT=web,worker
            -sALLOW_MEMORY_GROWTH=1
            -sINITIAL_MEMORY=16MB
            -sSTACK_SIZE=1MB
            -sFILESYSTEM=0
            # No malloc/free across the boundary: every call writes into a
            # caller-provided buffer inside the wasm heap.
            -sEXPORTED_RUNTIME_METHODS=["HEAPU8","ccall"]
            -sEXPORTED_FUNCTIONS=["_veil_engine_new","_veil_engine_restore","_veil_engine_free",
                                  "_veil_identity_secrets","_veil_identity_public",
                                  "_veil_identity_binding","_veil_sign_challenge",
                                  "_veil_rotate_prekeys","_veil_export_prekey_set",
                                  "_veil_needs_prekey_refill","_veil_export_prekey_state",
                                  "_veil_import_prekey_state","_veil_measure_session",
                                  "_veil_measure_prekey_state","_veil_measure_peer_registry",
                                  "_veil_establish_outbound","_veil_session_state",
                                  "_veil_export_session","_veil_import_session",
                                  "_veil_drop_session","_veil_peer_identity",
                                  "_veil_export_peer_registry","_veil_import_peer_registry",
                                  "_veil_encrypt","_veil_decrypt","_veil_safety_number",
                                  "_veil_set_random_source","_veil_version",
                                  "_veil_install_web_rng","_veil_web_rng_ready",
                                  "_malloc","_free"]
            # A C ABI has no exceptions to catch; aborting on one keeps a
            # bug loud instead of turning it into a silent wasm trap.
            -sABORTING_MALLOC=1)

    # The RNG bridge: JavaScript calls this to install crypto.getRandomValues
    # as the engine's entropy source.
    target_sources(veil.js PRIVATE ${VEIL_ROOT}/wasm/rng_bridge.c)
    return()
endif()

# --------------------------------------------------------------------
# Native build (Android, desktop).
# --------------------------------------------------------------------

# The shared object the JVM loads. Everything except the JNI entry points is
# hidden, so the exported symbol table stays tiny.
add_library(veil SHARED ${VEIL_ROOT}/jni/veil_jni.cpp)
target_link_libraries(veil PRIVATE veil-core)
set_target_properties(veil PROPERTIES
        CXX_VISIBILITY_PRESET hidden
        VISIBILITY_INLINES_HIDDEN ON)
target_link_options(veil PRIVATE -Wl,--exclude-libs,ALL)

# The same engine behind the C ABI, for callers that are not the JVM: the
# desktop client reaches it through JNA, and the wasm build is a different
# target of the same sources.
add_library(veil-c SHARED ${VEIL_ROOT}/veil/veil_c.cpp)
target_link_libraries(veil-c PRIVATE veil-core)
set_target_properties(veil-c PROPERTIES
        OUTPUT_NAME "veilc"
        CXX_VISIBILITY_PRESET hidden
        VISIBILITY_INLINES_HIDDEN ON)
target_compile_definitions(veil-c PRIVATE VEIL_C_BUILD_DLL)
target_link_options(veil-c PRIVATE -Wl,--exclude-libs,ALL)