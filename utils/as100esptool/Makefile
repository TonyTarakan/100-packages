include $(TOPDIR)/rules.mk

PKG_NAME:=as100esptool
PKG_VERSION:=0
PKG_RELEASE:=1
PKG_BUILD_DIR:=$(BUILD_DIR)/as100esptool

include $(INCLUDE_DIR)/package.mk

define Package/as100esptool
  SECTION:=utils
  CATEGORY:=Utilities
  TITLE:=ESP8266 firmware updater
endef

TARGET_CFLAGS += -I$(STAGING_DIR)/usr/include
TARGET_LDFLAGS += -L$(STAGING_DIR)/usr/lib

define Package/as100esptool/description
 ESP8266 firmware updater
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
endef

define Package/as100esptool/install
	$(INSTALL_DIR) $(1)/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/esptool $(1)/sbin/as100esptool
endef

$(eval $(call BuildPackage,as100esptool))
