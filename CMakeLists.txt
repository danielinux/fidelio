cmake_minimum_required(VERSION 3.31)

include(${CMAKE_CURRENT_SOURCE_DIR}/pico-sdk/lib/tinyusb/hw/bsp/family_support.cmake)


# gets PROJECT name for the example (e.g. <BOARD>-<DIR_NAME>)
family_get_project_name(PROJECT ${CMAKE_CURRENT_LIST_DIR})

project(${PROJECT})

# Checks this example is valid for the family and initializes the project
family_initialize_project(${PROJECT} ${CMAKE_CURRENT_LIST_DIR})

add_executable(${PROJECT})

#target_compile_options(${PROJECT} PUBLIC
#    "-Wno-cast-qual"
#    "-Wno-sign-conversion"
#    "-Wno-fatal-errors"
#)
#
# Example source
target_sources(${PROJECT} PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/src/fidelio.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/rand.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/puf_sram.c
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
        )

# Example include
target_include_directories(${PROJECT} PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/src
        ${CMAKE_CURRENT_SOURCE_DIR}/lib/wolfssl
        ${CMAKE_CURRENT_SOURCE_DIR}/lib/wolfcose/include
        )

        target_compile_definitions( ${PROJECT} PUBLIC WOLFSSL_USER_SETTINGS)

# wolfCOSE: Fidelio only needs the CBOR engine and COSE_Key serialisation.
# Trim away every COSE message type so none of the sign/encrypt/MAC code is
# linked in. WOLFCOSE_CBOR_ENCODE/DECODE and WOLFCOSE_KEY_ENCODE/DECODE stay
# on by default.
target_compile_definitions( ${PROJECT} PUBLIC
        WOLFCOSE_LEAN
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
