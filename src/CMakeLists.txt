aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR} topsrcs)
message("--  Get top srcs: " ${topsrcs})

add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/version)
message("--  Get version srcs: " ${VERSION_SRCS})

add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/types)
message("--  Get types srcs: " ${TYPE_SRCS})

add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/invoke)
message("--  Get invoke srcs: " ${INVOKE_SRCS})

# set libclibcni library
add_library(clibcni ${LIBTYPE} ${topsrcs} ${VERSION_SRCS} ${TYPE_SRCS} ${INVOKE_SRCS})

# set include dirs
target_include_directories(clibcni
    PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}
    PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/version/
    PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/types/
    PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/invoke/
    PUBLIC ${CMAKE_BINARY_DIR}/conf
    PUBLIC ${ISULA_LIBUTILS_INCLUDE_DIR}
    )

# set liblcr compile flags
if (CLIBCNI_GCOV)
    set(CMAKE_C_FLAGS_DEBUG "-Wall -fprofile-arcs -ftest-coverage")
    message("------compile with gcov-------------")
    message("-----CFLAGS: " ${CMAKE_C_FLAGS_DEBUG})
    message("------------------------------------")
    target_link_libraries(clibcni -lgcov)
endif()

target_link_libraries(clibcni ${ISULA_LIBUTILS_LIBRARY})

# install all files
install(TARGETS clibcni
	LIBRARY DESTINATION ${LIB_INSTALL_DIR_DEFAULT} PERMISSIONS OWNER_READ OWNER_EXECUTE GROUP_READ GROUP_EXECUTE)
