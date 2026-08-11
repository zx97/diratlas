# DirAtlas

LDAP Directory Explorer — C++ port of [godap](https://github.com/Macmod/godap).

Copyright (c) 2025 Manuel FLURY — AGPL-3.0-or-later  
Originally based on godap (github.com/Macmod/godap) — MIT license

## Prerequisites

- C++20 compiler (GCC 11+, Clang 14+)
- CMake 3.20+
- OpenLDAP development headers (`ldap.h`, `libldap`, `liblber`)
- ncurses development headers

## Build

```sh
# if openldap-devel is installed system-wide
make clean && make

# if you compiled OpenLDAP yourself
make LDAP_ROOT=/path/to/openldap-prefix

# or with separate include/lib dirs
make LDAP_INCLUDE_DIR=/path/to/include LDAP_LIB_DIR=/path/to/lib
```

## Usage

```sh
./build/diratlas -H ldap://server:389 -D 'cn=admin,dc=example,dc=com' -w secret
./build/diratlas -H ldapi://%2fvar%2frun%2fslapd.sock
./build/diratlas -H ldap://server:11389 -Z -D 'cn=admin,dc=example,dc=com' -W

./build/diratlas doc          # full embedded documentation
./build/diratlas version
```
