# =========== Theos Makefile لبناء UniversalHook.dylib (لنظام macOS) ===========
TARGET := macosx:clang:latest:15.0
INSTALL_TARGET_PROCESSES = SpringBoard

include $(THEOS)/makefiles/common.mk

LIBRARY_NAME = UniversalHook
UniversalHook_FILES = UniversalHook.mm
UniversalHook_FRAMEWORKS = Foundation AppKit
UniversalHook_LIBRARIES = dobby
UniversalHook_CFLAGS = -I./include -std=c++17 -O2
UniversalHook_LDFLAGS = -L./lib

include $(THEOS_MAKE_PATH)/library.mk

after-all::
	@echo "[+] UniversalHook.dylib built at: .theos/obj/UniversalHook.dylib"
	@cp .theos/obj/UniversalHook.dylib ./ 2>/dev/null || true
