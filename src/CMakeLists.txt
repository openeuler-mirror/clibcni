# generate .c and .h files for json
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/json)

# get libclibcni source files
aux_source_directory(${CMAKE_BINARY_DIR}/json generatesrcs)
message("--  Get generate srcs: " ${generatesrcs})
aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR}/json/schema/src commonjsonsrcs)
message("--  Get common json srcs: " ${commonjsonsrcs})

aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR} topsrcs)
message("--  Get top srcs: " ${topsrcs})

add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/version)
message("--  Get version srcs: " ${VERSION_SRCS})

add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/types)
message("--  Get types srcs: " ${TYPE_SRCS})

add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/invoke)
message("--  Get invoke srcs: " ${INVOKE_SRCS})

# set libclibcni library
add_library(clibcni ${LIBTYPE} ${topsrcs} ${VERSION_SRCS} ${TYPE_SRCS} ${INVOKE_SRCS} ${commonjsonsrcs} ${generatesrcs})

# set include dirs
target_include_directories(clibcni
		PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}
		PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/version/
		PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/types/
		PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/invoke/
		PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/json
		PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/json/schema/src
		PUBLIC ${CMAKE_BINARY_DIR}/json
		PUBLIC ${CMAKE_BINARY_DIR}/conf
		)

# set liblcr compile flags
if (CLIBCNI_GCOV)
    set(CMAKE_C_FLAGS_DEBUG "-Wall -fprofile-arcs -ftest-coverage")
    message("------compile with gcov-------------")
    message("-----CFLAGS: " ${CMAKE_C_FLAGS_DEBUG})
    message("------------------------------------")
    target_link_libraries(clibcni -lgcov)
endif()

target_link_libraries(clibcni -lyajl -lsecurec)

# install all files
install(TARGETS clibcni
	LIBRARY DESTINATION ${LIB_INSTALL_DIR_DEFAULT} PERMISSIONS OWNER_READ OWNER_EXECUTE GROUP_READ GROUP_EXECUTE)
