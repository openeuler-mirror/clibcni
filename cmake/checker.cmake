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

#check python
find_program(CMD_PYTHON python)
_CHECK(CMD_PYTHON "CMD_PYTHON-NOTFOUND" "python")

# check securec
find_path(LIBSECUREC_INCLUDE_DIR securec.h)
_CHECK(LIBSECUREC_INCLUDE_DIR "LIBSECUREC_INCLUDE_DIR-NOTFOUND" "securec.h")

find_library(LIBSECUREC_LIBRARY securec)
_CHECK(LIBSECUREC_LIBRARY "LIBSECUREC_LIBRARY-NOTFOUND" "libsecurec.so")

# check libyajl
pkg_check_modules(PC_LIBYAJL REQUIRED "yajl>=2")
if (NOT PC_LIBYAJL_FOUND)
	message("error: can not find yajl>=2")
	set(CHECKER_RESULT 1)
endif()
find_path(LIBYAJL_INCLUDE_DIR yajl/yajl_tree.h
	HINTS ${PC_LIBYAJL_INCLUDEDIR} ${PC_LIBYAJL_INCLUDE_DIRS})
_CHECK(LIBYAJL_INCLUDE_DIR "LIBYAJL_INCLUDE_DIR-NOTFOUND" "yajl/yajl_tree.h")

find_library(LIBYAJL_LIBRARY yajl
	HINTS ${PC_LIBYAJL_LIBDIR} ${PC_LIBYAJL_LIBRARY_DIRS})
_CHECK(LIBYAJL_LIBRARY "LIBYAJL_LIBRARY-NOTFOUND" "libyajl.so")

if (ENABLE_TESTS STREQUAL "ON")
	pkg_check_modules(PC_CHECK REQUIRED "check>=0.9.12")
	if (NOT PC_CHECK_FOUND)
		message("error: can not find check>=0.9.12")
		set(CHECKER_RESULT 1)
	endif()
endif()
