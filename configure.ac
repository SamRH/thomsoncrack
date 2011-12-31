AC_INIT([thomsoncrack], [1.6], [hegarty.sam@gmail.com])
AM_INIT_AUTOMAKE([-Wall foreign])
AC_PROG_CC_C99
AC_CONFIG_HEADERS([config.h])

AC_ARG_ENABLE([static-executable],
    AS_HELP_STRING([--enable-static-executable], [Build executable with libraries statically linked]))

AS_IF([test "x$enable_static_executable" = "xyes"], [
    AC_CHECK_LIB([z], [deflate], [], AC_MSG_ERROR([z library not found]))
    AC_CHECK_LIB([dl], [dlopen], [], AC_MSG_ERROR([dl library not found]))
    LDFLAGS="${LDFLAGS} --static"
])

AC_CHECK_LIB([pthread], [pthread_create], [], AC_MSG_ERROR([pthread library not found]))
AC_CHECK_HEADER([pthread.h], [], AC_MSG_ERROR([header pthread.h not found]), [AC_INCLUDES_DEFAULT])

AC_CHECK_LIB([crypto], [SHA1], [], AC_MSG_ERROR([crypto library not found]))
AC_CHECK_HEADER([openssl/sha.h], [], AC_MSG_ERROR([header openssl/sha.h not found]), [AC_INCLUDES_DEFAULT])

AC_CONFIG_FILES([
   Makefile
   src/Makefile
])

AC_OUTPUT
