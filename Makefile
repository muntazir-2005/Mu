# =========== Theos Makefile لبناء UniversalHook.dylib ===========
TARGET := iphone:clang:latest:15.0
INSTALL_TARGET_PROCESSES = SpringBoard

# نحن لا نبني tweak بل مكتبة dylib فقط
include $(THEOS)/makefiles/common.mk

# اسم المكتبة الناتجة
LIBRARY_NAME = UniversalHook

# ملفات المصدر
UniversalHook_FILES = UniversalHook.mm

# إطارات النظام المطلوبة
UniversalHook_FRAMEWORKS = Foundation AppKit

# مكتبات خاصة
UniversalHook_LIBRARIES = dobby

# مسارات البحث عن ملفات الرأس والمكتبات
UniversalHook_CFLAGS = -I./include -std=c++17 -O2
UniversalHook_LDFLAGS = -L./lib

# نوع الهدف: مكتبة ديناميكية
include $(THEOS_MAKE_PATH)/library.mk

# بعد البناء، انسخ المكتبة إلى المجلد الجذر (اختياري)
after-all::
	@echo "[+] UniversalHook.dylib built at: .theos/obj/UniversalHook.dylib"
	@cp .theos/obj/UniversalHook.dylib ./ 2>/dev/null || true
