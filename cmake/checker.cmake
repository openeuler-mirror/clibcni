# check depends library and headers
find_package(PkgConfig)

macro(_CHECK)
if (${ARGV0} STREQUAL "${ARGV1}")
	message("error: can not find " ${ARGV2} " program")
	set(CHECKER_RESULT 1)
else()
	message("--  found " ${ARGV2} " --- works")
endif()
endmacro()


# check iSula libutils
pkg_check_modules(PC_ISULA_LIBUTILS REQUIRED "lcr")
find_path(ISULA_LIBUTILS_INCLUDE_DIR isula_libutils/log.h
	HINTS ${PC_ISULA_LIBUTILS_INCLUDEDIR} ${PC_ISULA_LIBUTILS_INCLUDE_DIRS})
_CHECK(ISULA_LIBUTILS_INCLUDE_DIR "ISULA_LIBUTILS_INCLUDE_DIR-NOTFOUND" "isula_libutils/log.h")

find_library(ISULA_LIBUTILS_LIBRARY isula_libutils
	HINTS ${PC_ISULA_LIBUTILS_LIBDIR} ${PC_ISULA_LIBUTILS_LIBRARY_DIRS})
_CHECK(ISULA_LIBUTILS_LIBRARY "ISULA_LIBUTILS_LIBRARY-NOTFOUND" "libisula_libutils.so")

if (ENABLE_TESTS STREQUAL "ON")
	pkg_check_modules(PC_CHECK REQUIRED "check>=0.9.12")
	if (NOT PC_CHECK_FOUND)
		message("error: can not find check>=0.9.12")
		set(CHECKER_RESULT 1)
	endif()
endif()
