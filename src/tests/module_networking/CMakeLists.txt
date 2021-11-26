add_executable(module_networking_app
    module_networking.c
)

target_link_libraries(module_networking_app
    networking
    Unity
)

add_test(module_networking_test module_networking_app)
