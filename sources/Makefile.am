include $(top_srcdir)/build/modmake.rulesam
MODNAME=mod_xconf

mod_LTLIBRARIES = mod_xconf.la
mod_xconf_la_SOURCES  = mod_xconf.c commands.c playback.c utils.c cipher.c
mod_xconf_la_CFLAGS   = $(AM_CFLAGS) -I. -Wno-unused-variable -Wno-unused-function -Wno-unused-but-set-variable -Wno-unused-label -Wno-declaration-after-statement
#mod_xconf_la_CFLAGS   = $(AM_CFLAGS)
mod_xconf_la_LIBADD   = $(switch_builddir)/libfreeswitch.la
mod_xconf_la_LDFLAGS  = -avoid-version -module -no-undefined -shared

$(am_mod_xconf_la_OBJECTS):  mod_xconf.h cipher.h
