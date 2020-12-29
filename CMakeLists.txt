cmake_minimum_required (VERSION 2.8)
project (clibcni)

option(VERSION "set clibcni version" ON)
if (VERSION STREQUAL "ON")
	set(CLIBCNI_VERSION "2.0.4")
endif()

option(DEBUG "set clibcni gcc option" ON)
if (DEBUG STREQUAL "ON")
    add_definitions("-g -o2")
endif()

option(GCOV "set clibcni gcov option" OFF)
if (GCOV STREQUAL "ON")
    set(CLIBCNI_GCOV "ON")
endif()

# check depends libs and headers
include(cmake/checker.cmake)
if (CHECKER_RESULT)
	return()
endif()

set(CMAKE_C_FLAGS "-fPIC -fstack-protector-all -D_FORTIFY_SOURCE=2 -O2 -Wall -Werror")
set(CMAKE_SHARED_LINKER_FLAGS "-Wl,-E -Wl,-z,relro -Wl,-z,now -Wl,-z,noexecstack -Wtrampolines -fPIE -pie -shared -pthread")
if ("${CMAKE_C_COMPILER_ID}" STREQUAL "Clang")
    set(CMAKE_SHARED_LINKER_FLAGS "-Wl,-E -Wl,-z,relro -Wl,-z,now -Wl,-z,noexecstack -Wtrampolines -fPIE -shared -pthread")
endif()

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -D__FILENAME__='\"$(subst ${CMAKE_SOURCE_DIR}/,,$(abspath $<))\"'")

configure_file(
	"${CMAKE_CURRENT_SOURCE_DIR}/config.h.in"
	"${CMAKE_BINARY_DIR}/conf/config.h"
)

configure_file(
	"${CMAKE_CURRENT_SOURCE_DIR}/clibcni.pc.in"
	"${CMAKE_BINARY_DIR}/conf/clibcni.pc"
)

# build which type of clibcni library
option(USESHARED "set type of libclibcni, default is shared" ON)
if (USESHARED STREQUAL "ON")
	set(LIBTYPE "SHARED")
	message("--  Build shared library")
else ()
	set(LIBTYPE "STATIC")
	message("--  Build static library")
endif()

if (LIB_INSTALL_DIR)
  set(LIB_INSTALL_DIR_DEFAULT ${LIB_INSTALL_DIR})
else()
  set(LIB_INSTALL_DIR_DEFAULT "lib")
endif()

add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/src)

# install all files
install(FILES ${CMAKE_BINARY_DIR}/conf/clibcni.pc
	DESTINATION ${LIB_INSTALL_DIR_DEFAULT}/pkgconfig PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ GROUP_WRITE)
install(FILES src/types/types.h DESTINATION include/clibcni)
install(FILES src/version/version.h DESTINATION include/clibcni)
install(FILES src/api.h DESTINATION include/clibcni)
