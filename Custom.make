#
# $Id: Custom.make.example 45172 2012-09-27 11:39:54Z etxrab $
#

_CUSTOM_SUBDIRS_ = \
	bitcoin

_CUSTOM_EXTRA_DIST_ = \
	Custom.m4 \
	Custom.make

_CUSTOM_plugin_ldadd_ = \
	-dlopen plugins/bitcoin/bitcoin.la
