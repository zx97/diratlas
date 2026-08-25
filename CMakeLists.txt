cmake_minimum_required(VERSION 3.20)
project(diratlas VERSION 2.8.7 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_AUTOMOC OFF)

# Build number derived from git when available (deterministic, reproducible):
# commit count as the build number plus the short commit hash.
# Falls back to 0 / "nogit" when git is missing or the tree has no .git
# (e.g. a source copy), so the build never breaks without git.
find_package(Git QUIET)
set(BUILD_NUMBER 0)
set(BUILD_HASH "nogit")
if(GIT_FOUND AND EXISTS "${CMAKE_SOURCE_DIR}/.git")
    execute_process(COMMAND ${GIT_EXECUTABLE} rev-list --count HEAD
        WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
        OUTPUT_VARIABLE _git_count
        OUTPUT_STRIP_TRAILING_WHITESPACE
        RESULT_VARIABLE _git_count_rc
        ERROR_QUIET)
    execute_process(COMMAND ${GIT_EXECUTABLE} rev-parse --short HEAD
        WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
        OUTPUT_VARIABLE _git_hash
        OUTPUT_STRIP_TRAILING_WHITESPACE
        RESULT_VARIABLE _git_hash_rc
        ERROR_QUIET)
    # Only trust the output when git actually succeeded and returned a number.
    if(_git_count_rc EQUAL 0 AND _git_count MATCHES "^[0-9]+$")
        set(BUILD_NUMBER ${_git_count})
    endif()
    if(_git_hash_rc EQUAL 0 AND _git_hash)
        set(BUILD_HASH ${_git_hash})
    endif()
endif()
message(STATUS "Build number: ${BUILD_NUMBER}")
message(STATUS "Build hash:   ${BUILD_HASH}")

# Build date
string(TIMESTAMP BUILD_DATE "%Y-%m-%d %H:%M:%S")
message(STATUS "Build date:   ${BUILD_DATE}")

# Build host: capture at configure time, NOT at runtime.
# (gethostname() at runtime would return whichever machine currently runs
# the binary, not the one that compiled it.)
execute_process(COMMAND hostname
    OUTPUT_VARIABLE BUILD_HOSTNAME
    OUTPUT_STRIP_TRAILING_WHITESPACE
    ERROR_QUIET)
if(NOT BUILD_HOSTNAME)
    set(BUILD_HOSTNAME "unknown")
endif()
message(STATUS "Build host:   ${BUILD_HOSTNAME}")

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
    src/ldapcore/attrs.cpp
    src/ldapcore/attrdesc.cpp
    src/ldapcore/bytes.cpp
    src/ldapcore/dn.cpp
    src/ad/flags.cpp
    src/ad/format.cpp
    src/ad/guid.cpp
    src/ad/sid.cpp
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
    BUILD_HASH="${BUILD_HASH}"
    BUILD_DATE="${BUILD_DATE}"
    BUILD_HOSTNAME="${BUILD_HOSTNAME}"
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

# ── Unit tests (ctest) ──
enable_testing()

add_executable(test_dn
    tests/test_dn.cpp
    src/ldapcore/dn.cpp
)

target_include_directories(test_dn PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
)

target_compile_options(test_dn PRIVATE -Wall -Wextra)

add_test(NAME test_dn COMMAND test_dn)

add_executable(test_attrdesc
    tests/test_attrdesc.cpp
    src/ldapcore/attrdesc.cpp
)

target_include_directories(test_attrdesc PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
)

target_compile_options(test_attrdesc PRIVATE -Wall -Wextra)

add_test(NAME test_attrdesc COMMAND test_attrdesc)

add_executable(test_bytes
    tests/test_bytes.cpp
    src/ldapcore/bytes.cpp
)

target_include_directories(test_bytes PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
)

target_compile_options(test_bytes PRIVATE -Wall -Wextra)

add_test(NAME test_bytes COMMAND test_bytes)

add_executable(test_attrs
    tests/test_attrs.cpp
    src/ldapcore/attrs.cpp
    src/ldapcore/bytes.cpp
)

target_include_directories(test_attrs PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
)

target_compile_options(test_attrs PRIVATE -Wall -Wextra)

add_test(NAME test_attrs COMMAND test_attrs)
