dnl Process this file with autoconf to produce a configure script.

AC_INIT([XChat],[2.8.8],[http://www.xchat.org/],[xchat])

AC_PREREQ([2.71])
AC_COPYRIGHT([Copyright (C) 1998-2010 Peter Zelezny])

AC_CONFIG_HEADERS([config.h])
AC_CONFIG_SRCDIR([configure.ac])

AM_INIT_AUTOMAKE([1.9 dist-bzip2 subdir-objects no-define])

AM_MAINTAINER_MODE
AC_PROG_CC
AM_PROG_CC_C_O
AC_PROG_CPP
AM_PROG_AS
AC_DISABLE_STATIC([])
LT_INIT

dnl -----------------------------------------------------------
dnl Language Support
dnl -----------------------------------------------------------
GETTEXT_PACKAGE=xchat
AC_SUBST(GETTEXT_PACKAGE)
AC_DEFINE_UNQUOTED(GETTEXT_PACKAGE,"$GETTEXT_PACKAGE",[Gettext package name])

ALL_LINGUAS="be ca cs de el es fi fr gl hu it ja kn ko lt mk nl pa pl pt ru sq sr sv th uk vi zh_CN zh_TW"
AM_GNU_GETTEXT_VERSION(0.20)
AM_GNU_GETTEXT([external])
#USE_INCLUDED_LIBINTL="no"
#AC_SUBST(USE_INCLUDED_LIBINTL)
#BUILD_INCLUDED_LIBINTL="no"
#AC_SUBST(BUILD_INCLUDED_LIBINTL)

dnl displaced from acconfig.h
AH_VERBATIM([OLD_PERL],[#undef OLD_PERL])
AH_VERBATIM([PREFIX],[#undef PREFIX])
AH_VERBATIM([XCHATLIBDIR],[#undef XCHATLIBDIR])
AH_VERBATIM([XCHATSHAREDIR],[#undef XCHATSHAREDIR])
AH_VERBATIM([SOCKS],[#undef SOCKS])
AH_VERBATIM([USE_MSPROXY],[#undef USE_MSPROXY])
dnl AH_VERBATIM([USE_GNOME],[#undef USE_GNOME])
AH_VERBATIM([USE_SHM],[#undef USE_SHM])
AH_VERBATIM([USE_GTKSPELL],[#undef USE_GTKSPELL])
AH_VERBATIM([USE_LIBSEXY],[#undef USE_LIBSEXY])
AH_VERBATIM([USE_IPV6],[#undef USE_IPV6])
AH_VERBATIM([USE_MMX],[#undef USE_MMX])
AH_VERBATIM([USE_OPENSSL],[#undef USE_OPENSSL])
AH_VERBATIM([USE_PLUGIN],[#undef USE_PLUGIN])
AH_VERBATIM([USE_XFT],[#undef USE_XFT])
AH_VERBATIM([USE_XLIB],[#undef USE_XLIB])
AH_VERBATIM([USE_SIGACTION],[#undef USE_SIGACTION])
AH_VERBATIM([USING_FREEBSD],[#undef USING_FREEBSD])
AH_VERBATIM([USING_LINUX],[#undef USING_LINUX])
AH_VERBATIM([socklen_t],[#undef socklen_t])
AH_VERBATIM([USE_DBUS],[#undef USE_DBUS])

AC_PATH_PROG(sedpath, sed)
if test "_$sedpath" = _; then
	AC_MSG_ERROR("Cannot find sed: I need it\!")
fi

AC_PATH_PROG(unamepath, uname)
if test "_$unamepath" = _; then
	system="unknown"
else
	AC_MSG_CHECKING(system type)
	system=`$unamepath -s`
	AC_MSG_RESULT($system)
	if test "$system" = "Linux"; then
		AC_DEFINE(USING_LINUX)
	fi
	if test "$system" = "FreeBSD"; then
		AC_DEFINE(USING_FREEBSD)
	fi
fi

dnl *********************************************************************
dnl ** configure switches ***********************************************
dnl *********************************************************************

AC_ARG_ENABLE(socks,
[  --enable-socks          link with SOCKS5 library (default: no)],
        socks=$enableval, socks=no)

AC_ARG_ENABLE(ipv6,
[  --enable-ipv6           enable IPv6 (default: no)],
        ipv6=$enableval, ipv6=no)

AC_ARG_ENABLE(xft,
[  --enable-xft            enable use of Xft directly (default: no)],
        xft=$enableval, xft=no)

AC_ARG_ENABLE(openssl,
[  --enable-openssl[=PATH]   enable use of openSSL],
        openssl=$enableval, openssl=yes)

AC_ARG_ENABLE(gtkfe,
[  --disable-gtkfe         disable building gtk frontend],
        gtkfe=$enableval, gtkfe=yes)

AC_ARG_ENABLE(textfe,
[  --enable-textfe         build the text frontend (default: no)],
        textfe=$enableval, textfe=no)

dnl AC_ARG_ENABLE(gnome,
dnl [  --disable-gnome         disable use of gnome],
dnl        gnome=$enableval, gnome=yes)

AC_ARG_ENABLE(xlib,
[  --disable-xlib          disable use of xlib (for non X11 systems)],
        xlib=$enableval, xlib=yes)

AC_ARG_ENABLE(python,
[  --disable-python        don't build the python plugin],
        python=$enableval, python=yes)

AC_ARG_ENABLE(perl,
[  --disable-perl          don't build the perl plugin],
        perl=$enableval, perl=yes)

AC_ARG_ENABLE(perl_old,
[  --disable-perl_old      no backwards compatibility for perl plugin],
        perl_old=$enableval, perl_old=yes)

AC_ARG_ENABLE(tcl,
[  --enable-tcl[=PATH]       directory with Tcl config file: tclConfig.sh],
        tcl=$enableval, tcl=yes)

AC_ARG_ENABLE(plugin,
[  --disable-plugin        disable plugin support],
        plugin=$enableval, plugin=yes)

AC_ARG_ENABLE(dbus,
[  --disable-dbus          disable DBUS support],
        dbus=$enableval, dbus=yes)

AC_ARG_ENABLE(mmx,
[  --disable-mmx           disable MMX assembly routines],
        mmx=$enableval, mmx=yes)

AC_ARG_ENABLE(shm,
[  --enable-shm            enable use of XShm for fast tinting (default: no)],
        shm=$enableval, shm=no)

AC_ARG_ENABLE(spell,
[  --enable-spell=type     enable spelling type: none static libsexy gtkspell],
		  spell=$enableval, spell=libsexy)

AC_ARG_ENABLE(ntlm,
[  --enable-ntlm           enable Microsoft's NTLM auth (libntlm) library support (default: no)],
	ntlm=$enableval, ntlm=no)

dnl *********************************************************************
dnl ** GLIB *************************************************************
dnl *********************************************************************

AM_PATH_GLIB_2_0(2.0.3, glib=yes, glib=no)
if test "$glib" = no; then
	AC_MSG_ERROR("Cannot find glib")
fi

COMMON_CFLAGS="$GLIB_CFLAGS"
COMMON_LIBS="$GLIB_LIBS"

dnl *********************************************************************
dnl ** GTK **************************************************************
dnl *********************************************************************

AM_PATH_GTK_2_0(2.10.0, havegtk=yes, havegtk=no)

if test "$havegtk" = no; then
	gtkfe=no
	echo
	echo Cannot find GTK\! Not building GTK FrontEnd.
	echo
fi

if test "$gtkfe" != yes; then
	gnome=no
	COMMON_LIBS="$GLIB_LIBS"
	COMMON_CFLAGS="$GLIB_CFLAGS"
fi

dnl *********************************************************************
dnl ** GNOME ************************************************************
dnl *********************************************************************

GUI_LIBS="$GUI_LIBS $GTK_LIBS"
GUI_CFLAGS="$GUI_CFLAGS $GTK_CFLAGS"

gnome=no
#if test "$gnome" = yes; then
#	AC_PATH_PROG(pkgconfigpath, pkg-config)
#	AC_MSG_CHECKING(Gnome2 compile flags)
#	GNOME_CFLAGS="`$pkgconfigpath libgnome-2.0 --cflags 2>/dev/null`"
#	if test "_$GNOME_CFLAGS" = _ ; then
#		gnome=no
#		AC_MSG_RESULT([Gnome not found, building without it.])
#	else
#		GNOME_VER="`$pkgconfigpath libgnome-2.0 --modversion`"
#		GUI_LIBS="$GUI_LIBS `$pkgconfigpath libgnome-2.0 --libs`"
#		GUI_CFLAGS="$GUI_CFLAGS $GNOME_CFLAGS"
#		AC_DEFINE(USE_GNOME)
#		AC_MSG_RESULT(ok)
#	fi
#fi

# GConf
AC_PATH_PROG(GCONFTOOL, gconftool-2, no)

dnl *********************************************************************
dnl ** XFT **************************************************************
dnl *********************************************************************

if test "$xft" = yes; then
	AC_PATH_PROG(pkgconfigpath, pkg-config)
	if $pkgconfigpath xft --exists; then
		GUI_CFLAGS="$GUI_CFLAGS `$pkgconfigpath xft --cflags`"
		GUI_LIBS="$GUI_LIBS `$pkgconfigpath xft --libs`"
	else
		xft=no
		oldCPPFLAGS=$CPPFLAGS
		CPPFLAGS="$CPPFLAGS $GTK_CFLAGS"
		AC_CHECK_HEADERS(X11/Xft/Xft.h, xft=yes)
		CPPFLAGS=$oldCPPFLAGS
	fi
	if test "$xft" = yes; then
		AC_DEFINE(USE_XFT)
	fi
fi

dnl *********************************************************************
dnl ** XLIB *************************************************************
dnl *********************************************************************

if test "$xlib" = yes; then
	AC_DEFINE(USE_XLIB)
	if test "$system" = "SunOS"; then
		LIBS="$LIBS -L/usr/openwin/lib -lX11"
	else
		AC_CHECK_LIB(X11, XSetWMHints)
	fi
else
	shm=no
fi

dnl *********************************************************************
dnl ** PERL *************************************************************
dnl *********************************************************************

if test "$perl" = yes; then
	AC_PATH_PROG(perlpath, perl)
	AC_MSG_CHECKING(for Perl compile flags)
	PERL_CFLAGS=`$perlpath -MExtUtils::Embed -e ccopts 2>/dev/null`
	if test "_$PERL_CFLAGS" = _ ; then
		AC_MSG_RESULT([not found, building without perl.])
		perl=no
	else
		PERL_LDFLAGS=`$perlpath -MExtUtils::Embed -e ldopts |$sedpath 's/-lgdbm //'`
		PERL_LDFLAGS=`echo $PERL_LDFLAGS |$sedpath 's/-ldb //'`
		PERL_LDFLAGS=`echo $PERL_LDFLAGS |$sedpath 's/-lndbm //'`
		if test "$system" = "Linux"; then
			PERL_LDFLAGS=`echo $PERL_LDFLAGS |$sedpath 's/-lnsl //'`
			PERL_LDFLAGS=`echo $PERL_LDFLAGS |$sedpath 's/-lposix //'`
		fi
		PERL_LDFLAGS=`echo $PERL_LDFLAGS |$sedpath 's/-lc //'`
		AC_MSG_RESULT(ok)

#		oldLIBS=$LIBS
#		LIBS="$LIBS $PERL_LDFLAGS"
#		AC_CHECK_FUNC(eval_pv)
#		AC_CHECK_FUNC(call_pv)
#		LIBS=$oldLIBS

		AC_MSG_CHECKING(for perl >= 5.8.0)
		PERL_VER=`$perlpath -e 'print $]>= 5.008?"yes":"no"'`
		if test "$PERL_VER" = "yes"; then
			AC_MSG_RESULT(yes)
			AC_MSG_CHECKING(if perl plugin will be backward compatible)
			if test "$perl_old" = "yes"; then
					  AC_MSG_RESULT(yes)
					  AC_DEFINE(OLD_PERL)
			else
					  AC_MSG_RESULT(no)
			fi
		else
			AC_MSG_RESULT(no)
			echo "perl version too old, building without perl."
			perl=no
		fi
	fi
fi

dnl *********************************************************************
dnl ** PYTHON ***********************************************************
dnl *********************************************************************

if test "$python" = yes; then
        AC_PATH_PROG(pythonpath, python2)
        if test "_$pythonpath" = _ ; then
                AC_PATH_PROG(pythonpath, python)
        fi
        if test "_$pythonpath" = _ ; then
                python=no
        else
                AC_MSG_CHECKING(Python version)
                changequote(<<, >>)dnl
                PY_VER=`$pythonpath -c 'import distutils.sysconfig; print(distutils.sysconfig.get_config_vars("VERSION")[0]);'`
                PY_LIB=`$pythonpath -c 'import distutils.sysconfig; print(distutils.sysconfig.get_python_lib(standard_lib=1));'`
                PY_INC=`$pythonpath -c 'import distutils.sysconfig; print(distutils.sysconfig.get_config_vars("INCLUDEPY")[0]);'`
                $pythonpath -c "import sys; map(int,sys.version[:3].split('.')) >= [2,2] or sys.exit(1)"
                changequote([, ])dnl
                AC_MSG_RESULT($PY_VER)
                if test "$?" != "1"; then
                        AC_MSG_CHECKING(Python compile flags)
                        PY_PREFIX=`$pythonpath -c 'import sys; print(sys.prefix)'`
                        PY_EXEC_PREFIX=`$pythonpath -c 'import sys; print(sys.exec_prefix)'`
                        if test -f $PY_INC/Python.h; then
                                PY_LIBS="-L$PY_LIB/config -lpython$PY_VER -lpthread -lutil"
                                PY_CFLAGS="-I$PY_INC"
                                AC_MSG_RESULT(ok)
                        else
                                python=no
                                AC_MSG_RESULT([Can't find Python.h])
                        fi
                else
                        echo "Python too old. Only 2.2 or above is supported."
                        python=no
                fi
        fi
fi

dnl *********************************************************************
dnl ** TCL **************************************************************
dnl *********************************************************************

AC_MSG_CHECKING(for location of tclConfig.sh)
dirs="$tcl /lib /usr/lib /usr/tcl/lib /usr/lib/tcl8.4 /usr/local/lib /usr/local/tcl-8.4/lib /usr/local/tcl/lib /opt/lib /usr/lib/tcl8.3"
found=0
if test "$tcl" != "no"; then
	tcl=no
	for try in $dirs; do
		if test -f $try/tclConfig.sh; then
			found=1
			. $try/tclConfig.sh
			TCL_LIBS="$TCL_LIB_SPEC $TCL_LIBS"
			TCL_CFLAGS="-I${TCL_PREFIX}/include $TCL_INCLUDE_SPEC"
			tcl=yes
			AC_MSG_RESULT($try/tclConfig.sh)
			break
		fi
	done
	if test "$found" -eq 0 ; then
		AC_MSG_RESULT([tclConfig.sh not found - use the --enable-tcl option])
	fi
fi

dnl *********************************************************************
dnl ** IPv6 *************************************************************
dnl *********************************************************************

dnl purely for Solaris
AC_CHECK_FUNC(select, ,
	AC_CHECK_LIB(socket, select, ,
		AC_CHECK_LIB(nsl, select, ,
			AC_CHECK_LIB(inet, select, ,
				AC_CHECK_LIB(cposix, select, ,
					AC_CHECK_LIB(net, select, ,
						AC_MSG_WARN(i can not find select.  you might need to help me)))))))
AC_CHECK_LIB(socket, select)

if test "$ipv6" = yes; then
	AC_CHECK_FUNCS(getaddrinfo, have_getaddrinfo=yes)
	AC_MSG_CHECKING(whether to enable IPv6 support)
	if test "$have_getaddrinfo" = yes; then
		AC_MSG_RESULT(yes)
		AC_DEFINE(USE_IPV6)
	else
		ipv6=no
		AC_MSG_RESULT(no)
	fi
fi

dnl *********************************************************************
dnl ** OPENSSL **********************************************************
dnl *********************************************************************

retry=no
if test "$openssl" != no; then
	AC_PATH_PROG(pkgconfigpath, pkg-config)
	AC_MSG_CHECKING(for openssl through pkg-config)
	if $pkgconfigpath openssl --exists; then
		CPPFLAGS="$CPPFLAGS `$pkgconfigpath openssl --cflags`"
		LIBS="$LIBS `$pkgconfigpath openssl --libs`"
		AC_DEFINE(USE_OPENSSL)
		AC_MSG_RESULT(yes)
		openssl=yes
	else
		AC_MSG_RESULT(no)
		retry=yes
	fi
fi

if test "$retry" = "yes"; then
	unset openssl_path ac_cv_lib_ssl_SSL_new ac_cv_header_openssl_ssl_h
	if test "$openssl" != yes; then
		openssl_path=$openssl
	fi
	openssl=no
	SAVED_LIBS=$LIBS
	LIBS="$LIBS -lcrypto"
	if test -n "$openssl_path"; then
		LIBS="-L$openssl_path/lib $LIBS"
	fi
	AC_CHECK_LIB(ssl, SSL_new, have_openssl=yes)
	LIBS=$SAVED_LIBS
	if test "$have_openssl" = yes; then
		SAVED_CPPFLAGS=$CPPFLAGS
		if test -n "$openssl_path"; then
			CPPFLAGS="-I$openssl_path/include $CPPFLAGS"
		fi
		AC_CHECK_HEADERS(openssl/ssl.h, have_openssl_h=yes)
		if test "$have_openssl_h" = yes; then
			openssl=yes
			AC_DEFINE(USE_OPENSSL)
			LIBS="$LIBS -lssl -lcrypto"
			if test -n "$openssl_path"; then
				LIBS="-L$openssl_path/lib $LIBS"
			fi
		else
			CPPFLAGS=$SAVED_CPPFLAGS
		fi
	fi
fi

dnl *********************************************************************
dnl ** PLUGIN ***********************************************************
dnl *********************************************************************

if test "$plugin" = yes; then
	AC_CHECK_FUNCS(dlopen, have_dl=yes)
	if test "$have_dl" != yes; then
		AC_CHECK_LIB(dl, dlopen, have_dl=yes)
		if test "$have_dl" = yes; then
			LIBS="$LIBS -ldl"
		fi
	fi
	if test "$have_dl" = yes; then
		AC_DEFINE(USE_PLUGIN)
		AC_PATH_PROG(pkgconfigpath, pkg-config)
		RDYNAMIC_FLAGS="`$pkgconfigpath gmodule-2.0 --libs`"
		LIBS="$LIBS $RDYNAMIC_FLAGS"
		if test "$LD" = ""; then
			VS="`ld --help | grep version-script 2> /dev/null`"
		else
			VS="`$LD --help | grep version-script 2> /dev/null`"
		fi
		if test "$VS" != ""; then
			GUI_LIBS="$GUI_LIBS -Wl,--version-script,\$(srcdir)/../version-script"
		fi
	else
		plugin=no
	fi
fi

dnl #######################################################################
dnl # Check for DBUS libraries
dnl #######################################################################

if test "x$dbus" = "xyes" ; then
	PKG_CHECK_MODULES(DBUS, [dbus-1 >= 0.60 dbus-glib-1 >= 0.60 gthread-2.0], dbus=yes, [
		AC_MSG_RESULT(no)
		dbus=no
	])
	AC_PATH_PROG(DBUS_BINDING_TOOL, dbus-binding-tool, no)
	AC_PATH_PROG(GLIB_GENMARSHAL, glib-genmarshal, no)
	if test "x$DBUS_BINDING_TOOL" = "xno" || test "x$GLIB_GENMARSHAL" = "xno" || test "x$dbus" = "xno" ; then
		dbus="no"
	else
		COMMON_LIBS="$COMMON_LIBS $DBUS_LIBS"
		COMMON_CFLAGS="$COMMON_CFLAGS $DBUS_CFLAGS"
		AC_DEFINE(USE_DBUS)
		AS_AC_EXPAND(DATADIR, $datadir)

		DBUS_SERVICES_DIR="$DATADIR/dbus-1/services"
		AC_SUBST(DBUS_SERVICES_DIR)
		AC_DEFINE_UNQUOTED(DBUS_SERVICES_DIR, "$DBUS_SERVICES_DIR", [Where services dir for DBUS is])
	fi
fi

dnl *********************************************************************
dnl ** SPELL ************************************************************
dnl *********************************************************************

if test "$spell" = "gtkspell" ; then
	PKG_CHECK_MODULES(GTKSPELL, gtkspell-2.0 >= 2.0.2, [], [
		AC_MSG_RESULT(no)
		spell=no
	])
	if test "$spell" != "no" ; then
		GUI_LIBS="$GUI_LIBS $GTKSPELL_LIBS"
		GUI_CFLAGS="$GUI_CFLAGS $GTKSPELL_CFLAGS"
		AC_DEFINE(USE_GTKSPELL)
	fi
fi

if test "$spell" = "libsexy" ; then
	PKG_CHECK_MODULES([LIBSEXY], [libsexy >= 0.1.8], libsexy=yes, AC_MSG_RESULT(no))
	if test "$libsexy" = "yes" ; then
		GUI_LIBS="$GUI_LIBS $LIBSEXY_LIBS"
		GUI_CFLAGS="$GUI_CFLAGS $LIBSEXY_CFLAGS"
		AC_DEFINE(USE_LIBSEXY)
	else
		dnl use builtin static one
		spell="static"
	fi
fi

if test "$spell" = "static" ; then
	AC_DEFINE(USE_LIBSEXY)
fi

dnl *********************************************************************
dnl ** CONDITIONALS *****************************************************
dnl *********************************************************************

AM_CONDITIONAL(USE_OPENSSL, test "x$openssl" = "xyes")
AM_CONDITIONAL(USE_LIBSEXY, test "x$spell" = "xstatic")
AM_CONDITIONAL(DO_TEXT, test "x$textfe" = "xyes")
AM_CONDITIONAL(DO_GTK, test "x$gtkfe" = "xyes")
AM_CONDITIONAL(DO_PERL, test "x$perl" = "xyes")
AM_CONDITIONAL(DO_PYTHON, test "x$python" = "xyes")
AM_CONDITIONAL(DO_TCL, test "x$tcl" = "xyes")
AM_CONDITIONAL(DO_PLUGIN, test "x$plugin" = "xyes")
AM_CONDITIONAL(USE_DBUS, test "x$dbus" = "xyes")
AM_CONDITIONAL(DO_GCONF, test "x$GCONFTOOL" != "xno")

dnl *********************************************************************
dnl ** SOCKS5 ***********************************************************
dnl *********************************************************************

if test "$socks" = yes; then
	socks=no
	AC_CHECK_LIB(socks5, SOCKSconnect, have_socks=yes)
	if test "$have_socks" = yes; then
		AC_CHECK_HEADERS(socks.h, have_socks_h=yes)
		if test "$have_socks_h" = yes; then
			socks=yes
			AC_DEFINE(SOCKS)
			LIBS="$LIBS -lsocks5"
		fi
	fi
fi

dnl *********************************************************************
dnl ** MS PROXY *********************************************************
dnl *********************************************************************

have_ntlm="no"
if test "x$ntlm" = "xyes" ; then
	have_ntlm="no"
	AC_CHECK_LIB(ntlm, ntlm_smb_encrypt, have_ntlm=yes)
	if test "$have_ntlm" = yes; then
		LIBS="$LIBS -lntlm"
		AC_DEFINE(USE_MSPROXY)
	fi
fi

dnl *********************************************************************
dnl ** XShm *************************************************************
dnl *********************************************************************

if test "$shm" = yes; then
	oldl=$LIBS
	oldc=$CPPFLAGS
	LIBS="$LIBS `$pkgconfigpath --libs-only-L xft`"
	CPPFLAGS="$CPPFLAGS `$pkgconfigpath --cflags-only-I xft`"
	shm=no
	AC_CHECK_LIB(Xext, XShmAttach, shm=yes)
	if test "$shm" = yes; then
		shm=no
		AC_CHECK_HEADERS(sys/ipc.h, shm=yes)
		if test "$shm" = yes; then
			shm=no
			AC_CHECK_HEADERS(sys/shm.h, shm=yes)
		fi
	fi

	LIBS=$oldl
	if test "$shm" = yes; then
		GUI_LIBS="$GUI_LIBS `$pkgconfigpath --libs-only-L xft` -lX11 -lXext"
		AC_DEFINE(USE_SHM)
	else
		CPPFLAGS=$oldc
	fi
fi

dnl *********************************************************************
dnl ** MMX **************************************************************
dnl *********************************************************************

dnl we don't need mmx on *this* machine, just i386, because
dnl it's checked at runtime.
if test "$mmx" = "yes"; then
	case $host_cpu in
    i386|i486|i586|i686|i786|k6|k7)
    mmx=yes
        ;;
     *)
    mmx=no
	esac
	if test "$system" = "OpenBSD"; then
		dnl openbsd fails because mmx_cmod doesn't prefix its symbols with underscore.
		dnl xtext.o: Undefined symbol `_shade_ximage_15_mmx' referenced from text segment
		mmx=no
	fi
	if test "$mmx" = "yes"; then
		AC_DEFINE(USE_MMX)
	fi
fi

AM_CONDITIONAL(USE_MMX, test "$mmx" = "yes")

dnl *********************************************************************
dnl ** GCC FLAGS ********************************************************
dnl *********************************************************************

dnl Only use -Wall and -pipe if we have gcc
if test "x$GCC" = "xyes"; then
	if test -z "`echo "$CFLAGS" | grep "\-Wall" 2> /dev/null`" ; then
		CFLAGS="$CFLAGS -Wall"
	fi
	if test "$system" = "Linux" -o "$system" = "FreeBSD"; then
		if test -z "`echo "$CFLAGS" | grep "\-pipe" 2> /dev/null`" ; then
			CFLAGS="$CFLAGS -pipe"
		fi
	fi
	if test -z "`echo "$CFLAGS" | grep "\-g " 2> /dev/null`" ; then
		CFLAGS="$CFLAGS -g"
	fi
fi

dnl does this compiler support -Wno-pointer-sign ?
AC_MSG_CHECKING([if gcc accepts -Wno-pointer-sign ])

safe_CFLAGS=$CFLAGS
CFLAGS="-Wno-pointer-sign"

AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[]], [[
int main () { return 0 ; }
]])],[
no_pointer_sign=yes
AC_MSG_RESULT([yes])
],[
no_pointer_sign=no
AC_MSG_RESULT([no])
])
CFLAGS=$safe_CFLAGS

if test x$no_pointer_sign = xyes; then
	CFLAGS="$CFLAGS -Wno-pointer-sign"
fi

dnl does this compiler support -funsigned-char ?
AC_MSG_CHECKING([if gcc accepts -funsigned-char ])

safe_CFLAGS=$CFLAGS
CFLAGS="-funsigned-char"

AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[]], [[
int main () { return 0 ; }
]])],[
unsigned_char=yes
AC_MSG_RESULT([yes])
],[
unsigned_char=no
AC_MSG_RESULT([no])
])
CFLAGS=$safe_CFLAGS

if test x$unsigned_char = xyes; then
	CFLAGS="$CFLAGS -funsigned-char"
fi

dnl *********************************************************************
dnl ** FUNCTIONS/LIBS/CFLAGS ********************************************
dnl *********************************************************************

AC_MSG_CHECKING(for modern sigaction)
dnl libc5 on linux and FreeBSD 3.x doesn't have siginfo_t
dnl and the sa_sigation field.
AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[#include <signal.h>]], [[struct sigaction act;
	 siginfo_t *si;
	 act.sa_sigaction = 0;]])],[
		AC_MSG_RESULT(yes)
		AC_DEFINE(USE_SIGACTION) 
	],[AC_MSG_RESULT(no)])

AC_PATH_PROG(gdkpixbufcsourcepath, gdk-pixbuf-csource)
AC_SUBST(gdkpixbufcsourcepath)
if test "$gtkfe" != no -a "_$gdkpixbufcsourcepath" = _; then
	AC_MSG_ERROR("Cannot find gdk-pixbuf-csource: Install GTK+ 2.0\!")
fi

dnl if we don't have this, use g_snprintf instead
AC_CHECK_FUNCS(snprintf vsnprintf memrchr strtoull)

AC_CHECK_FUNC(gethostbyname, ,
	AC_CHECK_LIB(resolv, gethostbyname, ,
		AC_CHECK_LIB(nsl, gethostbyname)))

AC_CHECK_FUNC(gethostname, , AC_CHECK_LIB(nsl, gethostname))

dnl necessary for IRIX
AC_CHECK_HEADERS(strings.h)

dnl Check for type in sys/socket.h - from Squid source (GPL)
AC_CACHE_CHECK(for socklen_t, ac_cv_type_socklen_t, [
AC_EGREP_CPP([socklen_t[^a-zA-Z_0-9]], [#include <sys/types.h>
#include <sys/socket.h>
#if STDC_HEADERS
#include <stdlib.h>
#include <stddef.h>
#endif],
ac_cv_type_socklen_t=yes,
ac_cv_type_socklen_t=no)
])
if test $ac_cv_type_socklen_t = no; then
	AC_DEFINE(socklen_t, int)
fi

dnl Mac OS X and Darwin use lookupd, which caches DNS queries by default
AC_EGREP_CPP(lookupd, dnl
[#if (defined(__APPLE__) && defined(__MACH__))
	lookupd
#endif], AC_DEFINE([LOOKUPD],1,[Define to 1 if the system uses lookupd]))

dnl freebsd needs this
LIBS="$LIBS $INTLLIBS"
CFLAGS="$CFLAGS $CPPFLAGS"

GUI_LIBS="$GUI_LIBS $COMMON_LIBS"

dnl make these visible to all Makefiles
AC_SUBST(GUI_LIBS)
AC_SUBST(GUI_CFLAGS)
AC_SUBST(COMMON_LIBS)
AC_SUBST(COMMON_CFLAGS)
AC_SUBST(PERL_CFLAGS)
AC_SUBST(PERL_LDFLAGS)
AC_SUBST(PY_CFLAGS)
AC_SUBST(PY_LIBS)
AC_SUBST(TCL_LIBS)
AC_SUBST(TCL_CFLAGS)
AC_SUBST(DBUS_CFLAGS)
AC_SUBST(DBUS_LIBS)


PLUGIN_INCLUDES='-I$(top_srcdir)/plugins'
AC_SUBST(PLUGIN_INCLUDES)

dnl for plugin.c and pixmaps.c
test "x$prefix" = xNONE && prefix="$ac_default_prefix"
test "x$exec_prefix" = xNONE && exec_prefix="$prefix"

AC_DEFINE_UNQUOTED(PREFIX, "${prefix}")

XCHATLIBDIR=`eval echo ${libdir}/xchat`
AC_DEFINE_UNQUOTED(XCHATLIBDIR, "$XCHATLIBDIR")

XCHATSHAREDIR=`eval echo ${datadir}`
AC_DEFINE_UNQUOTED(XCHATSHAREDIR, "$XCHATSHAREDIR")

dnl for plugins/xxx/Makefile.am
xchatlibdir=${libdir}/xchat
AC_SUBST(xchatlibdir)

#AC_CONFIG_FILES([ po/Makefile.in
#intl/Makefile
AC_CONFIG_FILES([ Makefile
src/Makefile
src/common/Makefile
src/common/dbus/Makefile
src/fe-text/Makefile
src/fe-gtk/Makefile
src/pixmaps/Makefile
plugins/Makefile
plugins/python/Makefile
plugins/perl/Makefile
plugins/tcl/Makefile
po/Makefile.in
])
AC_OUTPUT

echo
echo xchat $VERSION
echo
echo Building GTK+ Interface .... : $gtkfe
echo Building TEXT Interface .... : $textfe
echo
echo PLUGINS: Perl: $perl Python: $python TCL: $tcl
echo
echo mmx tinting ......... : $mmx\	spelling .............. : $spell
echo XShm tinting ........ : $shm\	plugin interface ...... : $plugin
if test "$xft" = no; then
  echo text backend ........ : pango\	nls/gettext ........... : $USE_NLS
else
  echo text backend ........ : xft\	nls/gettext ........... : $USE_NLS
fi
echo openssl support ..... : $openssl\	ipv6 support .......... : $ipv6
echo dbus support ........ : $dbus\	msproxy ntlm \(ISA\) .... : $have_ntlm
echo
echo The binary will be installed in $prefix/bin
echo

if test "$gtkfe" = no; then
	echo Warning: The GTK \(GUI\) frontend will not be built.
	echo
fi

if test "$spell" = "gtkspell"; then
	echo Warning: GTK SPELL is not the recommended spelling library.
	echo
fi

echo configure complete, now type \'make\' and pray.
echo
