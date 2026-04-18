ARCHS = arm64 arm64e
TARGET = iphone:clang:latest:14.0

INSTALL_TARGET_PROCESSES = SpringBoard

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = amarhook

amarhook_FILES = Tweak.xm
amarhook_CFLAGS = -fobjc-arc -Wno-unused-variable -I./include
amarhook_LDFLAGS = -L./lib -ldobby -lssl -lcrypto
amarhook_FRAMEWORKS = Foundation CoreFoundation Security LocalAuthentication IOKit

include $(THEOS_MAKE_PATH)/tweak.mk

after-install::
	install.exec "killall -9 SpringBoard"
