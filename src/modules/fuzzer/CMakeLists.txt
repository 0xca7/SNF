add_library(fuzzer STATIC
    fuzzer.c
)

target_include_directories(fuzzer PUBLIC
    ${CMAKE_CURRENT_LIST_DIR}
)

target_link_libraries(fuzzer
    #global_cfg
)

