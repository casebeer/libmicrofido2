#######################################
# General
cmake_minimum_required(VERSION 3.10)
include(CMakeDependentOption)

if(NOT DEFINED ESP_PLATFORM)
    project(libmicrofido2 C)
endif()

set(PRODUCT_NAME microfido2)

#######################################
# Options

set(_build_examples_default ON)
if(ESP_PLATFORM OR ZEPHYR)
    set(_build_examples_default OFF)
endif()
option(BUILD_EXAMPLES "Build example applications" ${_build_examples_default})

#######################################
# Compilation

set(libmicrofido2_release_flags -O3)
set(libmicrofido2_debug_flags -ggdb -O0)
string (REPLACE ";" " " libmicrofido2_debug_flags_str "${libmicrofido2_debug_flags}")
string (REPLACE ";" " " libmicrofido2_release_flags_str "${libmicrofido2_release_flags}")
set(CMAKE_C_FLAGS_RELEASE "${libmicrofido2_release_flags_str}")
set(CMAKE_C_FLAGS_DEBUG "${libmicrofido2_debug_flags_str}")

set(libmicrofido2_definitions
    -D_FIDO_INTERNAL
)

set(libmicrofido2_compile_options
    -std=gnu99
    -fstack-usage
    -ffunction-sections
    -fdata-sections
    -fshort-enums
    -Wall
)

file(GLOB SRC_FILES "src/*.c") # Load all files in src folder

set(libmicrofido2_include_dir
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

if(NOT DEFINED ESP_PLATFORM)
    include_directories(${libmicrofido2_include_dir})
    add_library(${PRODUCT_NAME} STATIC ${SRC_FILES})
endif()

if(NOT DEFINED ESP_PLATFORM)
    add_compile_options(
        ${libmicrofido2_compile_options}
    )

    add_definitions(
        ${libmicrofido2_definitions}
    )
endif()

set(libmicrofido2_external_lib_include_dirs
    ${CMAKE_CURRENT_SOURCE_DIR}/external/aes_gcm/include
    ${CMAKE_CURRENT_SOURCE_DIR}/external/cb0r/include
    ${CMAKE_CURRENT_SOURCE_DIR}/external/sha256/include
    ${CMAKE_CURRENT_SOURCE_DIR}/external/tinf/include
    ${CMAKE_CURRENT_SOURCE_DIR}/external/Monocypher/include
)

if(NOT DEFINED ESP_PLATFORM)
    include_directories(${libmicrofido2_external_lib_include_dirs})
endif()

#######################################
# ESP IDF

if(ESP_PLATFORM)
    idf_component_register(
        SRCS ${SRC_FILES}
        INCLUDE_DIRS ${libmicrofido2_include_dir}
        PRIV_INCLUDE_DIRS ${libmicrofido2_external_lib_include_dirs}
    )
    set(libmicrofido2_build_options ${libmicrofido2_compile_options} ${libmicrofido2_definitions} ${libmicrofido2_release_flags})
    target_compile_options(${COMPONENT_LIB} PRIVATE ${libmicrofido2_build_options})
    unset(libmicrofido2_build_options)
endif()

option(ENABLE_SOFTWARE_CRYPTO "disable building software cryptography algorithms" ON)

if(ESP_PLATFORM AND CONFIG_USE_HW_CRYPTO)
    # Disable s/w support for the specific algorithms we have ESP32 hardware support for when
    # h/w crypto is enabled.  We can't disable all s/w crypto since e.g. there is no hardware
    # support for Ed25519.
    set(USE_SOFTWARE_CRYPTO_AES_GCM_ENCRYPT OFF)
    set(USE_SOFTWARE_CRYPTO_AES_GCM_DECRYPT OFF)
    set(USE_SOFTWARE_CRYPTO_SHA256 OFF)
    set(USE_SOFTWARE_CRYPTO_SHA512 OFF)
endif()

cmake_dependent_option(USE_SOFTWARE_CRYPTO_AES_GCM_ENCRYPT "include software AES GCM encryption" ON "ENABLE_SOFTWARE_CRYPTO" OFF)
if(NOT USE_SOFTWARE_CRYPTO_AES_GCM_ENCRYPT)
    add_compile_definitions(NO_SOFTWARE_CRYPTO_AES_GCM_ENCRYPT)
endif()

cmake_dependent_option(USE_SOFTWARE_CRYPTO_AES_GCM_DECRYPT "include software AES GCM decryption" ON "ENABLE_SOFTWARE_CRYPTO" OFF)
if(NOT USE_SOFTWARE_CRYPTO_AES_GCM_DECRYPT)
    add_compile_definitions(NO_SOFTWARE_CRYPTO_AES_GCM_DECRYPT)
endif()

cmake_dependent_option(USE_SOFTWARE_CRYPTO_ED25519_SIGN "include software ed25519 signature generation" OFF "ENABLE_SOFTWARE_CRYPTO" OFF)
if(NOT USE_SOFTWARE_CRYPTO_ED25519_SIGN)
    add_compile_definitions(NO_SOFTWARE_CRYPTO_ED25519_SIGN)
endif()

cmake_dependent_option(USE_SOFTWARE_CRYPTO_ED25519_VERIFY "include software ed25519 signature verification" ON "ENABLE_SOFTWARE_CRYPTO" OFF)
if(NOT USE_SOFTWARE_CRYPTO_ED25519_VERIFY)
    add_compile_definitions(NO_SOFTWARE_CRYPTO_ED25519_VERIFY)
endif()

cmake_dependent_option(USE_SOFTWARE_CRYPTO_SHA256 "include software SHA256" ON "ENABLE_SOFTWARE_CRYPTO" OFF)
if(NOT USE_SOFTWARE_CRYPTO_SHA256)
    add_compile_definitions(NO_SOFTWARE_CRYPTO_SHA256)
endif()

cmake_dependent_option(USE_SOFTWARE_CRYPTO_SHA512 "include software SHA512" ON "ENABLE_SOFTWARE_CRYPTO" OFF)
if(NOT USE_SOFTWARE_CRYPTO_SHA512)
    add_compile_definitions(NO_SOFTWARE_CRYPTO_SHA512)
endif()

# TODO: This should also be disabled when not using software crypto.
cmake_dependent_option(USE_SOFTWARE_RNG "include software RNG" ON "ENABLE_SOFTWARE_CRYPTO" ON)
if(NOT USE_SOFTWARE_RNG)
    add_compile_definitions(NO_SOFTWARE_RNG)
endif()

#######################################
# External libraries

# Add AES GCM library
if(USE_SOFTWARE_CRYPTO_AES_GCM_ENCRYPT OR USE_SOFTWARE_CRYPTO_AES_GCM_DECRYPT)
    add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/external/aes_gcm)
    list(APPEND libmicrofido2_link_libs aes-gcm)
endif()

# Add cb0r library
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/external/cb0r)
list(APPEND libmicrofido2_link_libs cb0r)


# Add SHA256 library
if(USE_SOFTWARE_CRYPTO_SHA256)
    add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/external/sha256)
    list(APPEND libmicrofido2_link_libs sha256)
endif()

# Add tinf library
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/external/tinf)
list(APPEND libmicrofido2_link_libs tinf)

# Add Monocypher library
if (USE_SOFTWARE_CRYPTO_ED25519_SIGN OR USE_SOFTWARE_CRYPTO_ED25519_VERIFY)
    add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/external/Monocypher)
    target_compile_definitions(Monocypher PRIVATE PERIODICALLY_RESET_WATCHDOG)
    if(CMAKE_BUILD_TYPE STREQUAL "Debug")
        # Use -Os in debug build because otherwise it wouldn't fit on AVR.
        target_compile_options(Monocypher PRIVATE -Os)
    endif()
    list(APPEND libmicrofido2_link_libs Monocypher)
endif()

# Link the object libraries
if(${ESP_PLATFORM})
    target_link_libraries(${COMPONENT_LIB} PUBLIC ${libmicrofido2_link_libs})
else()
    target_link_libraries(${PRODUCT_NAME} PUBLIC ${libmicrofido2_link_libs})
endif()

#######################################
# Examples
if(BUILD_EXAMPLES)
    add_subdirectory(examples)
endif()
