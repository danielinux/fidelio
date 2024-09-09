cmake_minimum_required(VERSION 3.5)

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
        ${CMAKE_CURRENT_SOURCE_DIR}/src/cert.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/u2f.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/led.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/usb_descriptors.c
        ${CMAKE_CURRENT_SOURCE_DIR}/lib/wolfssl/wolfcrypt/src/asn.c
        ${CMAKE_CURRENT_SOURCE_DIR}/lib/wolfssl/wolfcrypt/src/wc_port.c
        ${CMAKE_CURRENT_SOURCE_DIR}/lib/wolfssl/wolfcrypt/src/wolfmath.c
        ${CMAKE_CURRENT_SOURCE_DIR}/lib/wolfssl/wolfcrypt/src/hash.c
        ${CMAKE_CURRENT_SOURCE_DIR}/lib/wolfssl/wolfcrypt/src/memory.c
        ${CMAKE_CURRENT_SOURCE_DIR}/lib/wolfssl/wolfcrypt/src/misc.c
        ${CMAKE_CURRENT_SOURCE_DIR}/lib/wolfssl/wolfcrypt/src/ecc.c
        ${CMAKE_CURRENT_SOURCE_DIR}/lib/wolfssl/wolfcrypt/src/hmac.c
        ${CMAKE_CURRENT_SOURCE_DIR}/lib/wolfssl/wolfcrypt/src/coding.c
        ${CMAKE_CURRENT_SOURCE_DIR}/lib/wolfssl/wolfcrypt/src/random.c
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
        )

        target_compile_definitions(${PROJECT} PUBLIC WOLFSSL_USER_SETTINGS)
        target_compile_definitions(${PROJECT} PRIVATE CYW43_PIO_CLOCK_DIV_DYNAMIC=1)


        target_link_libraries(${PROJECT} PUBLIC pico_stdlib)
        target_link_libraries(${PROJECT} PUBLIC pico_multicore)
        target_link_libraries(${PROJECT} PUBLIC hardware_adc)
        target_link_libraries(${PROJECT} PUBLIC hardware_flash)
        target_link_libraries(${PROJECT} PUBLIC pico_unique_id)
        target_link_libraries(${PROJECT} PUBLIC tinyusb_device) 
        target_link_libraries(${PROJECT} PUBLIC tinyusb_board)
		
		# Configure compilation flags and libraries# Cater for Pico W
		if (PICO_CYW43_SUPPORTED)
			message("It's a Pico W.....")
			target_link_libraries(${PROJECT} PUBLIC pico_cyw43_arch_none hardware_clocks)
		endif()

        # Configure compilation flags and libraries for the example... see the corresponding function
        # in hw/bsp/FAMILY/family.cmake for details.
        # family_configure_device_example(${PROJECT}) // Not needed?
