include $(TOPDIR)/rules.mk

PKG_NAME:=as100vpn
PKG_VERSION:=0
PKG_RELEASE:=1
PKG_BUILD_DIR:=$(BUILD_DIR)/as100vpn

PKG_MAINTAINER:=Vladimir Ovseychuk <vgovseychuk@gmail.com>

include $(INCLUDE_DIR)/package.mk

define Package/as100vpn
  SECTION:=utils
  CATEGORY:=Utilities
  TITLE:=VPN client for AS100 system
  DEPENDS:=+libopenssl
endef

TARGET_CFLAGS += -I$(STAGING_DIR)/usr/include
TARGET_LDFLAGS += -L$(STAGING_DIR)/usr/lib

define Package/as100vpn/description
 VPN client for AS100 system
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/vpn/* $(PKG_BUILD_DIR)/
endef

define Build/Compile
	$(call Build/Compile/Default,client)
endef

define Package/as100vpn/install
	$(INSTALL_DIR) $(1)/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/vpn_client $(1)/sbin/as100vpn
endef

$(eval $(call BuildPackage,as100vpn))
