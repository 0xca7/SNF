add_executable(module_packet_app
    module_packet.c
)

target_link_libraries(module_packet_app
    packet
    Unity
)

add_test(module_packet_test module_packet_app)
