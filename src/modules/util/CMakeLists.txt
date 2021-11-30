add_library(util STATIC
    util.c
)

target_include_directories(util PUBLIC
    ${CMAKE_CURRENT_LIST_DIR}
)

target_link_libraries(util
    #global_cfg
)

