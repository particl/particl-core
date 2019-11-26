package=libusb
$(package)_version=1.0.23
$(package)_download_path=https://github.com/libusb/libusb/archive/
$(package)_file_name=v$($(package)_version).tar.gz
$(package)_sha256_hash=02620708c4eea7e736240a623b0b156650c39bfa93a14bcfa5f3e05270313eba

define $(package)_set_vars
  $(package)_config_opts=--disable-shared --enable-udev
  $(package)_config_opts_linux=--with-pic
endef

define $(package)_preprocess_cmds
  cd $($(package)_build_subdir); ./bootstrap.sh
endef

define $(package)_config_cmds
  $($(package)_autoconf)
endef

define $(package)_build_cmds
  $(MAKE)
endef

define $(package)_stage_cmds
  $(MAKE) DESTDIR=$($(package)_staging_dir) install
endef
