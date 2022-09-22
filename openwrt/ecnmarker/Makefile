include $(TOPDIR)/rules.mk
include $(INCLUDE_DIR)/kernel.mk

PKG_NAME:=ecnmarker
PKG_VERSION:=0.0.0
PKG_RELEASE:=1

PKG_BUILD_DEPENDS:=bpf-headers
PKG_FLAGS:=nonshared

include $(INCLUDE_DIR)/package.mk
include $(INCLUDE_DIR)/bpf.mk

define Package/ecnmarker
  CATEGORY:=Network
  DEPENDS:=+@KERNEL_BPF_EVENTS +libbpf +kmod-sched-bpf +tc-bpf +ucode-mod-ubus +ucode-mod-uci +ucrun
  SECTION:=network
  TITLE:=ecnmarker
endef

define Package/ecnmarker/description
  eBPF program to mark ECN-CE bits.
endef

define Package/ecnmarker/install
	$(INSTALL_DIR) $(1)/lib/ecnmarker $(1)/usr/sbin
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/ecnmarker-bpf.o $(1)/lib/ecnmarker
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/ecnmarker.uc $(1)/usr/sbin
	$(CP) $(PKG_BUILD_DIR)/files/* $(1)/
	chmod 755 $(1)/usr/sbin/ecnmarker.uc
endef

define Build/Compile
	$(call CompileBPF,$(PKG_BUILD_DIR)/ecnmarker-bpf.c)
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) $(CURDIR)/../../ecnmarker* $(PKG_BUILD_DIR)
	$(CP) $(CURDIR)/../../files/ $(PKG_BUILD_DIR)
endef

$(eval $(call BuildPackage,ecnmarker))
