cmake_minimum_required(VERSION 3.20)
project(diratlas VERSION 1.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_AUTOMOC OFF)

# Auto-incrementing build number
set(BUILD_FILE "${CMAKE_SOURCE_DIR}/build_number.txt")
if(EXISTS "${BUILD_FILE}")
    file(READ "${BUILD_FILE}" _bn)
    string(STRIP "${_bn}" _bn)
    math(EXPR _bn "${_bn} + 1")
else()
    set(_bn 1)
endif()
file(WRITE "${BUILD_FILE}" "${_bn}\n")
set(BUILD_NUMBER ${_bn})
message(STATUS "Build number: ${BUILD_NUMBER}")

# Build date
string(TIMESTAMP BUILD_DATE "%Y-%m-%d %H:%M:%S")
message(STATUS "Build date:   ${BUILD_DATE}")

set(LDAP_ROOT "" CACHE PATH "Root of local OpenLDAP installation")
set(LDAP_INCLUDE_DIR "" CACHE PATH "Path to OpenLDAP include dir (containing ldap.h)")
set(LDAP_LIB_DIR "" CACHE PATH "Path to OpenLDAP lib dir (containing libldap.so)")

if(LDAP_INCLUDE_DIR)
    set(_ldap_include_hint ${LDAP_INCLUDE_DIR})
elseif(LDAP_ROOT)
    set(_ldap_include_hint ${LDAP_ROOT}/include)
endif()

if(LDAP_LIB_DIR)
    set(_ldap_lib_hint ${LDAP_LIB_DIR})
elseif(LDAP_ROOT)
    set(_ldap_lib_hint ${LDAP_ROOT}/lib)
endif()

find_path(LDAP_INCLUDE ldap.h
    ${_ldap_include_hint}
    /usr/include /usr/local/include /opt/homebrew/include
)

if(NOT LDAP_INCLUDE)
    message(FATAL_ERROR "ldap.h not found. Set LDAP_INCLUDE_DIR or LDAP_ROOT.")
endif()

if(LDAP_LIB_DIR)
    if(EXISTS ${LDAP_LIB_DIR}/libldap.so)
        set(LDAP_LIB ${LDAP_LIB_DIR}/libldap.so)
    elseif(EXISTS ${LDAP_LIB_DIR}/libldap.so.2)
        set(LDAP_LIB ${LDAP_LIB_DIR}/libldap.so.2)
    elseif(EXISTS ${LDAP_LIB_DIR}/libldap.a)
        set(LDAP_LIB ${LDAP_LIB_DIR}/libldap.a)
    endif()
    if(EXISTS ${LDAP_LIB_DIR}/liblber.so)
        set(LBER_LIB ${LDAP_LIB_DIR}/liblber.so)
    elseif(EXISTS ${LDAP_LIB_DIR}/liblber.so.2)
        set(LBER_LIB ${LDAP_LIB_DIR}/liblber.so.2)
    elseif(EXISTS ${LDAP_LIB_DIR}/liblber.a)
        set(LBER_LIB ${LDAP_LIB_DIR}/liblber.a)
    endif()
else()
    find_library(LDAP_LIB NAMES ldap)
    find_library(LBER_LIB NAMES lber)
endif()

if(NOT LDAP_LIB OR NOT LBER_LIB)
    message(FATAL_ERROR "OpenLDAP libs not found. Set LDAP_LIB_DIR or LDAP_ROOT.")
endif()

find_library(SASL2_LIB sasl2)
find_path(SASL2_INCLUDE sasl/sasl.h)

message(STATUS "LDAP include: ${LDAP_INCLUDE}")
message(STATUS "LDAP lib:     ${LDAP_LIB}")

add_executable(diratlas
    src/main.cpp
    src/ldap_conn.cpp
    src/formats.cpp
    src/formats/time_format.cpp
    src/adidns/types.cpp
    src/adidns/formats.cpp
    src/sdl/types.cpp
    src/sdl/parse.cpp
    src/vars.cpp
    src/tui/app.cpp
    src/tui/tree.cpp
    src/tui/attrs.cpp
    src/ldaprc.cpp
)

target_include_directories(diratlas PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${LDAP_INCLUDE}
)

target_compile_definitions(diratlas PRIVATE
    BUILD_NUMBER=${BUILD_NUMBER}
    BUILD_DATE="${BUILD_DATE}"
    VERSION="${PROJECT_VERSION}"
)

target_link_libraries(diratlas PRIVATE
    ${LDAP_LIB}
    ${LBER_LIB}
    ncursesw
    pthread
)

if(SASL2_LIB AND SASL2_INCLUDE)
    target_include_directories(diratlas PRIVATE ${SASL2_INCLUDE})
    target_link_libraries(diratlas PRIVATE ${SASL2_LIB})
    message(STATUS "SASL: enabled (${SASL2_LIB})")
else()
    message(STATUS "SASL: disabled (libldap has built-in SASL)")
endif()

# Sanitizer options (use -DSANITIZER=<type> when running cmake)
# Available types: address, memory, thread, undefined, leak
# Example: cmake -DSANITIZER=address ..
set(SANITIZER "" CACHE STRING "Enable sanitizer (address, memory, thread, undefined, leak)")

if(SANITIZER)
    if(CMAKE_CXX_COMPILER_ID MATCHES "Clang|GNU")
        message(STATUS "Sanitizer: ${SANITIZER}")
    else()
        message(WARNING "Sanitizers only supported with Clang or GCC")
    endif()
endif()

target_compile_options(diratlas PRIVATE -Wall -Wextra)

# Apply sanitizer flags after regular compile options
if(SANITIZER)
    if(CMAKE_CXX_COMPILER_ID MATCHES "Clang|GNU")
        target_compile_options(diratlas PRIVATE -fsanitize=${SANITIZER})
        target_link_options(diratlas PRIVATE -fsanitize=${SANITIZER})
    endif()
endif()
