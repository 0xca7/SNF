add_library(networking STATIC
    networking.c
)

target_include_directories(networking PUBLIC
    ${CMAKE_CURRENT_LIST_DIR}
)

target_link_libraries(networking
    #global_cfg
    util
)

