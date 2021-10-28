enable_testing()
find_package(GTest REQUIRED)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fPIC -std=c++11")

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
        --gtest_output=xml:${ARGV0}-Results.xml
    )
endmacro()


if (CLIBCNI_GCOV)
    add_custom_target(coverage
        COMMAND lcov --directory ./src --zerocounters --rc lcov_branch_coverage=1
        COMMAND lcov -c -i -d . -o coverage.base --rc lcov_branch_coverage=1
        COMMAND ctest
        COMMAND lcov --directory ./src --capture --output-file coverage.info --rc lcov_branch_coverage=1
        COMMAND lcov -a coverage.base -a coverage.info --output-file coverage.total --rc lcov_branch_coverage=1
        COMMAND lcov --remove coverage.total '/usr/*' -o coverage.total --rc lcov_branch_coverage=1
        COMMAND lcov --remove coverage.total --output-file ${PROJECT_BINARY_DIR}/coverage.info.cleaned --rc lcov_branch_coverage=1
        COMMAND genhtml -o coverage ${PROJECT_BINARY_DIR}/coverage.info.cleaned --branch-coverage --rc lcov_branch_coverage=1
        COMMAND ${CMAKE_COMMAND} -E remove coverage.base coverage.total ${PROJECT_BINARY_DIR}/coverage.info.cleaned

        WORKING_DIRECTORY ${PROJECT_BINARY_DIR}
        COMMENT "generating report..."
    )

    add_custom_command(TARGET coverage POST_BUILD
        COMMAND ;
        COMMENT "open coverage/index.html in browser to view the coverage analysis report."
    )
endif()

# --------------- testcase add here -----------------
#   api testcase
_DEFINE_NEW_TEST(api_llt api_testcase)

# --------------- testcase add finish -----------------

