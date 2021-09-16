enable_testing()
find_package(GTest REQUIRED)

set(CMAKE_C_COMPILER "g++" CACHE PATH "c compiler")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++0x")

include_directories(
    ${GTEST_INCLUDE_DIR}
    PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}
    PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/utils
    PUBLIC ${CMAKE_SOURCE_DIR}/src
    PUBLIC ${CMAKE_SOURCE_DIR}/src/version/
    PUBLIC ${CMAKE_SOURCE_DIR}/src/types/
    PUBLIC ${CMAKE_SOURCE_DIR}/src/invoke/
    PUBLIC ${CMAKE_SOURCE_DIR}/src/json
    PUBLIC ${CMAKE_SOURCE_DIR}/src/json/schema/src
    PUBLIC ${CMAKE_BINARY_DIR}/json
    PUBLIC ${CMAKE_BINARY_DIR}/conf
    )

add_subdirectory(utils)

macro(_DEFINE_NEW_TEST)
    add_executable(${ARGV0}
        ${TESTS_UTILS_SRCS}
        main.cpp
        ${ARGV0}.cpp
        )

    target_link_libraries(${ARGV0}
        clibcni
        gtest
        -lyajl
        pthread
        )

    add_test(
        NAME ${ARGV1}
        COMMAND ${ARGV0}
    )
endmacro()

# --------------- testcase add here -----------------
#   api testcase
_DEFINE_NEW_TEST(api_llt api_testcase)

# --------------- testcase add finish -----------------

