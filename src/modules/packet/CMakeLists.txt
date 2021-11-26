add_library(packet STATIC
    packet.c
)

target_include_directories(packet PUBLIC
    ${CMAKE_CURRENT_LIST_DIR}
)

target_link_libraries(packet
    #global_cfg
)

