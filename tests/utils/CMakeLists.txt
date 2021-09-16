# get current directory sources files
aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR} local_cutils_srcs)

set(TESTS_UTILS_SRCS
    ${local_cutils_srcs}
    PARENT_SCOPE
    )
