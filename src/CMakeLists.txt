cmake_policy(SET CMP0048 NEW)
project("Simple Network Fuzzer - SNF" VERSION 0.1.0)
cmake_minimum_required(VERSION 3.13.0)

add_compile_options(-Wall -Wextra -pedantic)

set(TARGET_GROUP production CACHE STRING "Group to build")

add_subdirectory(global)
add_subdirectory(modules)
add_subdirectory(external)
add_subdirectory(external/Unity)

if(TARGET_GROUP STREQUAL production)
    add_subdirectory(main)
elseif(TARGET_GROUP STREQUAL test)
    include(CTest)
    add_subdirectory(tests)
else()
    message(FATAL_ERROR "Given TARGET_GROUP unknown")
endif()
