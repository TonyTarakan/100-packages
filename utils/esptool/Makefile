include $(TOPDIR)/rules.mk

PKG_NAME:=esptool
PKG_VERSION:=0
PKG_RELEASE:=1
PKG_BUILD_DIR:=$(BUILD_DIR)/esptool

PKG_MAINTAINER:=Vladimir Ovseychuk <vgovseychuk@gmail.com>

include $(INCLUDE_DIR)/package.mk

define Package/esptool
  SECTION:=utils
  CATEGORY:=Utilities
  TITLE:=ESP8266 firmware updater
endef

TARGET_CFLAGS += -I$(STAGING_DIR)/usr/include
TARGET_LDFLAGS += -L$(STAGING_DIR)/usr/lib

define Package/esptool/description
 ESP8266 firmware updater
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
endef

define Package/esptool/install
	$(INSTALL_DIR) $(1)/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/esptool $(1)/sbin/
endef

$(eval $(call BuildPackage,esptool))
