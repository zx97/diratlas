.PHONY: all clean banner

BUILD_DIR := build
BANNER := ansi_banner.utf8

# When LDAP_ROOT / LDAP_INCLUDE_DIR / LDAP_LIB_DIR are not given on the
# command line, auto-detect a locally-compiled OpenLDAP (e.g. the symas
# build tree) before falling back to the system headers/libs.
LDAP_ARGS :=
ifdef LDAP_ROOT
    LDAP_ARGS += -DLDAP_ROOT=$(LDAP_ROOT)
else ifdef LDAP_INCLUDE_DIR
    LDAP_ARGS += -DLDAP_INCLUDE_DIR=$(LDAP_INCLUDE_DIR)
    ifdef LDAP_LIB_DIR
        LDAP_ARGS += -DLDAP_LIB_DIR=$(LDAP_LIB_DIR)
    endif
else
    _LDAP_INC := $(shell ls -d /home/manu/rpmbuild/BUILD/symas-openldap-*/include 2>/dev/null | head -1)
    _LDAP_LIB := /ec/local/server/symas/lib
    ifneq ($(_LDAP_INC),)
        LDAP_ARGS += -DLDAP_INCLUDE_DIR=$(_LDAP_INC) -DLDAP_LIB_DIR=$(_LDAP_LIB)
    endif
endif

all: banner $(BUILD_DIR)/Makefile
	$(MAKE) -C $(BUILD_DIR)

# Print the ANSI banner (256-color gradient logo).
banner:
	@printf "%b" "$$(cat $(BANNER))\n"

$(BUILD_DIR)/Makefile: CMakeLists.txt
	mkdir -p $(BUILD_DIR)
	cmake -S . -B $(BUILD_DIR) $(LDAP_ARGS)

clean:
	rm -rf $(BUILD_DIR)
