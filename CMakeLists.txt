cmake_minimum_required(VERSION 3.31)

# Target board selection. Adding a board means adding a branch here and a
# matching block in src/pins.h.
set(BOARD "pico" CACHE STRING "Target board: pico | rp2040-zero")
set_property(CACHE BOARD PROPERTY STRINGS pico rp2040-zero)

if(BOARD STREQUAL "pico")
    set(FIDELIO_BOARD_DEFINE FIDELIO_BOARD_PICO)
elseif(BOARD STREQUAL "rp2040-zero")
    set(FIDELIO_BOARD_DEFINE FIDELIO_BOARD_RP2040_ZERO)
else()
    message(FATAL_ERROR
        "Unknown BOARD '${BOARD}'. Supported values: pico, rp2040-zero.")
endif()

message(STATUS "Fidelio target board: ${BOARD} (${FIDELIO_BOARD_DEFINE})")

# TinyUSB's hw/bsp/rp2040/family.cmake, included via family_support.cmake
# below, reads BOARD too, but means something else by it: the name of a BSP
# directory under hw/bsp/rp2040/boards/. Shadow the cache entry with a normal
# variable holding the value it expects, which is also the one it would have
# defaulted to on its own. The cache entry keeps the Fidelio board name for
# ccmake/cmake-gui and for reconfiguration.
set(BOARD pico_sdk)

include(${CMAKE_CURRENT_SOURCE_DIR}/pico-sdk/lib/tinyusb/hw/bsp/family_support.cmake)


# gets PROJECT name for the example (e.g. <BOARD>-<DIR_NAME>)
family_get_project_name(PROJECT ${CMAKE_CURRENT_LIST_DIR})

project(${PROJECT})

# Checks this example is valid for the family and initializes the project
family_initialize_project(${PROJECT} ${CMAKE_CURRENT_LIST_DIR})

option(FIDELIO_BENCH "Build the wolfCrypt benchmark instead of the authenticator" OFF)
set(FIDELIO_BENCH_CLOCK_KHZ 48000 CACHE STRING "System clock for the benchmark build, kHz")
if(FIDELIO_BENCH)
    set(FIDELIO_MAIN_SRC ${CMAKE_CURRENT_SOURCE_DIR}/src/bench_main.c)
    message(STATUS "Fidelio: BENCHMARK build at ${FIDELIO_BENCH_CLOCK_KHZ} kHz")
else()
    set(FIDELIO_MAIN_SRC ${CMAKE_CURRENT_SOURCE_DIR}/src/fidelio.c)
endif()

add_executable(${PROJECT})

#target_compile_options(${PROJECT} PUBLIC
#    "-Wno-cast-qual"
#    "-Wno-sign-conversion"
#    "-Wno-fatal-errors"
#)
#
# Example source
target_sources(${PROJECT} PUBLIC
        ${FIDELIO_MAIN_SRC}
        ${CMAKE_CURRENT_SOURCE_DIR}/src/rand.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/puf_sram.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/flash_rt.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/cred_alg.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/alg_probe.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/cert.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/ctap2.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/fdo.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/u2f.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/indicator.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/usb_descriptors.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/sys_stubs.c
        ${CMAKE_CURRENT_SOURCE_DIR}/lib/wolfcose/src/wolfcose_cbor.c
        ${CMAKE_CURRENT_SOURCE_DIR}/lib/wolfcose/src/wolfcose.c
        ${CMAKE_CURRENT_SOURCE_DIR}/lib/wolfssl/wolfcrypt/src/asn.c
        ${CMAKE_CURRENT_SOURCE_DIR}/lib/wolfssl/wolfcrypt/src/wc_port.c
        ${CMAKE_CURRENT_SOURCE_DIR}/lib/wolfssl/wolfcrypt/src/wolfmath.c
        ${CMAKE_CURRENT_SOURCE_DIR}/lib/wolfssl/wolfcrypt/src/hash.c
        ${CMAKE_CURRENT_SOURCE_DIR}/lib/wolfssl/wolfcrypt/src/memory.c
        ${CMAKE_CURRENT_SOURCE_DIR}/lib/wolfssl/wolfcrypt/src/misc.c
        ${CMAKE_CURRENT_SOURCE_DIR}/lib/wolfssl/wolfcrypt/src/ecc.c
        ${CMAKE_CURRENT_SOURCE_DIR}/lib/wolfssl/wolfcrypt/src/hmac.c
        ${CMAKE_CURRENT_SOURCE_DIR}/lib/wolfssl/wolfcrypt/src/kdf.c
        ${CMAKE_CURRENT_SOURCE_DIR}/lib/wolfssl/wolfcrypt/src/puf.c
        ${CMAKE_CURRENT_SOURCE_DIR}/lib/wolfssl/wolfcrypt/src/logging.c
        ${CMAKE_CURRENT_SOURCE_DIR}/lib/wolfssl/wolfcrypt/src/error.c
        ${CMAKE_CURRENT_SOURCE_DIR}/lib/wolfssl/wolfcrypt/src/coding.c
        ${CMAKE_CURRENT_SOURCE_DIR}/lib/wolfssl/wolfcrypt/src/random.c
        ${CMAKE_CURRENT_SOURCE_DIR}/lib/wolfssl/wolfcrypt/src/aes.c
        ${CMAKE_CURRENT_SOURCE_DIR}/lib/wolfssl/wolfcrypt/src/sha256.c
        ${CMAKE_CURRENT_SOURCE_DIR}/lib/wolfssl/wolfcrypt/src/sha512.c
        ${CMAKE_CURRENT_SOURCE_DIR}/lib/wolfssl/wolfcrypt/src/ge_low_mem.c
        ${CMAKE_CURRENT_SOURCE_DIR}/lib/wolfssl/wolfcrypt/src/fe_low_mem.c
        ${CMAKE_CURRENT_SOURCE_DIR}/lib/wolfssl/wolfcrypt/src/ge_operations.c
        ${CMAKE_CURRENT_SOURCE_DIR}/lib/wolfssl/wolfcrypt/src/sp_int.c
        ${CMAKE_CURRENT_SOURCE_DIR}/lib/wolfssl/wolfcrypt/src/sp_armthumb.c
        ${CMAKE_CURRENT_SOURCE_DIR}/lib/wolfssl/wolfcrypt/src/sp_c32.c
        ${CMAKE_CURRENT_SOURCE_DIR}/lib/wolfssl/wolfcrypt/src/ed25519.c
        ${CMAKE_CURRENT_SOURCE_DIR}/lib/wolfssl/wolfcrypt/src/fe_operations.c
        ${CMAKE_CURRENT_SOURCE_DIR}/lib/wolfssl/wolfcrypt/src/sha3.c
        ${CMAKE_CURRENT_SOURCE_DIR}/lib/wolfssl/wolfcrypt/src/wc_mldsa.c
        )

# Example include
target_include_directories(${PROJECT} PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/src
        ${CMAKE_CURRENT_SOURCE_DIR}/lib/wolfssl
        ${CMAKE_CURRENT_SOURCE_DIR}/lib/wolfcose/include
        )

        target_compile_definitions( ${PROJECT} PUBLIC WOLFSSL_USER_SETTINGS)

# Measurement/feature hook: extra wolfSSL feature macros.
if(FIDELIO_EXTRA_DEFS)
    target_compile_definitions(${PROJECT} PUBLIC ${FIDELIO_EXTRA_DEFS})
endif()

# Build-sizing probe (see src/alg_probe.c). --undefined forces the linker to
# keep it, so the measurement reflects real code size rather than what
# --gc-sections would otherwise discard.
option(FIDELIO_ALG_PROBE "Force-link the algorithm sizing probe" OFF)
if(FIDELIO_ALG_PROBE)
    target_compile_definitions(${PROJECT} PUBLIC FIDELIO_ALG_PROBE)
    target_link_options(${PROJECT} PUBLIC -Wl,--undefined=fidelio_alg_probe)
endif()

# Board pinout selector consumed by src/pins.h
target_compile_definitions( ${PROJECT} PUBLIC ${FIDELIO_BOARD_DEFINE})

# wolfCOSE: Fidelio only needs the CBOR engine and COSE_Key serialisation.
# Trim away every COSE message type so none of the sign/encrypt/MAC code is
# linked in. WOLFCOSE_CBOR_ENCODE/DECODE and WOLFCOSE_KEY_ENCODE/DECODE stay
# on by default.
target_compile_definitions( ${PROJECT} PUBLIC
        WOLFCOSE_LEAN
        # LEAN turns the optional key types off; re-enable the ones whose
        # COSE_Key serialisation Fidelio needs for its credential algorithms.
        WOLFCOSE_ENABLE_EDDSA
        WOLFCOSE_ENABLE_MLDSA
        WOLFCOSE_NO_SIGN1
        WOLFCOSE_NO_ENCRYPT0
        WOLFCOSE_NO_MAC0
        WOLFCOSE_NO_SIGN
        WOLFCOSE_NO_ENCRYPT
        WOLFCOSE_NO_MAC
        )


        target_link_libraries(${PROJECT} PUBLIC pico_stdlib)
        # pico_multicore is deliberately not linked: core 1's stack lives in
        # SCRATCH_X, which is reserved for the SRAM PUF response.
        target_link_libraries(${PROJECT} PUBLIC hardware_adc)
        target_link_libraries(${PROJECT} PUBLIC hardware_flash)
        target_link_libraries(${PROJECT} PUBLIC hardware_pio)

# Configure compilation flags and libraries for the example... see the corresponding function
# in hw/bsp/FAMILY/family.cmake for details.
family_configure_device_example(${PROJECT})

# Use the Fidelio memory map, which reserves the SRAM PUF response region at
# the base of SCRATCH_X. Must come after family_configure_device_example(),
# which is what installs the SDK's default memmap.
pico_set_linker_script(${PROJECT} ${CMAKE_CURRENT_SOURCE_DIR}/src/memmap_fidelio.ld)

if(FIDELIO_BENCH)
    target_sources(${PROJECT} PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/lib/wolfssl/wolfcrypt/benchmark/benchmark.c)
    target_compile_definitions(${PROJECT} PUBLIC
        BENCH_EMBEDDED
        WOLFSSL_USER_CURRTIME
        NO_MAIN_DRIVER
        FIDELIO_BENCH_CLOCK_KHZ=${FIDELIO_BENCH_CLOCK_KHZ})
    # benchmark.c writes to a console this board does not have; capture it.
    set_source_files_properties(
        ${CMAKE_CURRENT_SOURCE_DIR}/lib/wolfssl/wolfcrypt/benchmark/benchmark.c
        PROPERTIES COMPILE_DEFINITIONS "printf=bench_printf")
endif()

# SRAM PUF bring-up diagnostic. Replaces the authenticator with a report on
# the health of this board's SRAM response, printed on UART0 (GP0/GP1,
# 115200 8N1). Use it to qualify a board before registering credentials
# against it; see the README. Never flash a diagnostic build for real use.
option(FIDELIO_PUF_DIAG "Build the SRAM PUF bring-up diagnostic" OFF)
if(FIDELIO_PUF_DIAG)
    target_compile_definitions(${PROJECT} PUBLIC FIDELIO_PUF_DIAG)
    pico_enable_stdio_uart(${PROJECT} 1)
    pico_enable_stdio_usb(${PROJECT} 0)
endif()
