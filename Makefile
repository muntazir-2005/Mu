# إعدادات البناء: استهداف أجهزة iOS/iPadOS بمعمارية arm64
TARGET := iphoneos:clang:latest:15.0
ARCHS = arm64
DEBUG = 0
FINALPACKAGE = 1

include $(THEOS)/makefiles/common.mk

# بناء كمكتبة dylib عادية لتكون جاهزة للحقن في الـ IPA
LIBRARY_NAME = iPadSpoofer

# ملفات الكود الخاصة بك
iPadSpoofer_FILES = Spoofer.m fishhook.c

# إعدادات المترجم
iPadSpoofer_CFLAGS = -fobjc-arc -I./include

# استخدام UIKit للآيباد بدلاً من AppKit
iPadSpoofer_FRAMEWORKS = Foundation UIKit

# ربط مكتبة Dobby الخاصة بـ iOS/arm64
iPadSpoofer_LDFLAGS = -L./lib -ldobby

include $(THEOS_MAKE_PATH)/library.mk
