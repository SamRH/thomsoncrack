AC_INIT([thomsoncrack], [1.1], [hegarty.sam@gmail.com])
AM_INIT_AUTOMAKE([-Wall foreign])
AC_PROG_CC_C99
AC_CONFIG_HEADERS([config.h])
AC_CHECK_LIB([pthread], [pthread_create], [], AC_MSG_ERROR([libpthread not found]))
AC_CHECK_LIB([crypto], [SHA1], [], AC_MSG_ERROR([libcrypto not found]))
AC_CONFIG_FILES([
 Makefile
 src/Makefile
])
AC_OUTPUT
