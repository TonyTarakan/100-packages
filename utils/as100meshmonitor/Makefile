include $(TOPDIR)/rules.mk

PKG_NAME:=as100meshmonitor
PKG_VERSION:=0
PKG_RELEASE:=1
PKG_BUILD_DIR:=$(BUILD_DIR)/as100meshmonitor

include $(INCLUDE_DIR)/package.mk

define Package/as100meshmonitor
  SECTION:=utils
  CATEGORY:=Utilities
  TITLE:=Mesh network utility for AS100 system
endef

TARGET_CFLAGS += -I$(STAGING_DIR)/usr/include
TARGET_LDFLAGS += -L$(STAGING_DIR)/usr/lib

define Package/as100meshmonitor/description
 Mesh network utility for AS100 system
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
endef

define Package/as100meshmonitor/install
	$(INSTALL_DIR) $(1)/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/meshmonitor $(1)/sbin/as100meshmonitor
endef

$(eval $(call BuildPackage,as100meshmonitor))
