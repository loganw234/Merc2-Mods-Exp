# Makefile for debug_overlay_DEV.asi — built against the Mercs2 mod stdlib.
#
# Pattern mirrors mods/quiet-freeplay-vo + the other mod-ports here.
#
# Prerequisites:
#   Windows: MSYS2 + mingw-w64-i686-gcc (+ MinGW d3dx9 headers)
#   Linux:   apt install gcc-mingw-w64-i686
#   macOS:   brew install mingw-w64

include ../../sdk/sdk.mk

CC_MINGW    = i686-w64-mingw32-gcc
ifeq ($(OS),Windows_NT)
    STRIP_MINGW = strip
else
    STRIP_MINGW = i686-w64-mingw32-strip
endif

TARGET      = debug_overlay_DEV.asi
SRC         = debug_overlay_DEV.c
CFLAGS      = -O2 -Wall -Wno-unused-function -Wno-unused-variable -static-libgcc -shared -Wl,--enable-stdcall-fixup $(M2_CFLAGS) $(EXTRA_CFLAGS)
LDFLAGS     = -ld3d9 -ld3dx9 -lws2_32 -lkernel32 -luser32

.PHONY: all clean mingw help

all: mingw

mingw: $(SRC)
	$(CC_MINGW) $(CFLAGS) -o $(TARGET) $(SRC) $(M2_SRCS) $(LDFLAGS)
	$(STRIP_MINGW) $(TARGET)
	@echo "Built: $(TARGET) ($$(wc -c < $(TARGET)) bytes)"
	@echo "Copy to: <game>/scripts/  (along with debug_overlay_DEV.ini)"

clean:
	rm -f $(TARGET) *.obj *.exp *.lib debug_overlay_DEV.log

help:
	@echo "make mingw   — Cross-compile with MinGW (default)"
	@echo "make clean   — Remove build artifacts"
