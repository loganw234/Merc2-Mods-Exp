# sdk.mk — include from a mod Makefile to build against the Mercs2 mod stdlib.
#
#   include ../../sdk/sdk.mk
#   $(CC) $(CFLAGS) $(M2_CFLAGS) -o mod.asi mod.c $(M2_SRCS) $(LDFLAGS)
#
# Paths resolve relative to the including Makefile's directory (via MAKEFILE_LIST),
# so a mod builds from its own folder without knowing the SDK's absolute location.

M2_SDK_DIR := $(patsubst %/,%,$(dir $(lastword $(MAKEFILE_LIST))))
M2_MINHOOK := $(M2_SDK_DIR)/minhook

M2_CFLAGS := -I$(M2_SDK_DIR)/m2 -I$(M2_MINHOOK)/include

M2_SRCS := \
	$(M2_SDK_DIR)/m2/m2_log.c \
	$(M2_SDK_DIR)/m2/m2_ini.c \
	$(M2_SDK_DIR)/m2/m2_hook.c \
	$(M2_SDK_DIR)/m2/m2_luastack.c \
	$(M2_SDK_DIR)/m2/m2_loghook.c \
	$(M2_SDK_DIR)/m2/m2_loadtrigger.c \
	$(M2_MINHOOK)/src/hook.c \
	$(M2_MINHOOK)/src/buffer.c \
	$(M2_MINHOOK)/src/trampoline.c \
	$(M2_MINHOOK)/src/hde/hde32.c
