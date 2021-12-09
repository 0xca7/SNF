add_library(generator STATIC
    generator.c
)

target_include_directories(generator PUBLIC
    ${CMAKE_CURRENT_LIST_DIR}
)

target_link_libraries(generator
    #global_cfg
    util
)

