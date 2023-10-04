## Process this file with automake to produce Makefile.in

#SUBDIRS = po po intl src plugins
SUBDIRS = po po src plugins

EXTRA_DIST = m4/ChangeLog  autogen.sh HACKING INSTALL.w32 faq.html xchat.png \
		xchat.desktop xchat.spec config.h.w32 xchat.ico

icon_DATA = xchat.png
icondir = $(datadir)/pixmaps

util_DATA = xchat.desktop
utildir = $(datadir)/applications

ACLOCAL_AMFLAGS = -I m4
