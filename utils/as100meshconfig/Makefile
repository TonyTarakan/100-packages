include $(TOPDIR)/rules.mk

PKG_NAME:=as100meshconfig
PKG_VERSION:=0
PKG_RELEASE:=1
PKG_BUILD_DIR:=$(BUILD_DIR)/as100meshconfig

PKG_MAINTAINER:=Vladimir Ovseychuk <vgovseychuk@gmail.com>

include $(INCLUDE_DIR)/package.mk

define Package/as100meshconfig
  SECTION:=utils
  CATEGORY:=Utilities
  TITLE:=ESP8266 mesh network manager for AS100GW
  DEPENDS:=+libuci 
endef

TARGET_CFLAGS += -I$(STAGING_DIR)/usr/include
TARGET_LDFLAGS += -L$(STAGING_DIR)/usr/lib

define Package/as100meshconfig/description
 ESP8266 mesh network manager
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
endef

define Package/as100meshconfig/install
	$(INSTALL_DIR) $(1)/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/meshconfig $(1)/sbin/
	$(INSTALL_DIR) $(1)/etc/config
	$(CP) ./files/meshconfig.config $(1)/etc/config/meshconfig
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/meshconfig.init $(1)/etc/init.d/meshconfig

endef

$(eval $(call BuildPackage,as100meshconfig))
