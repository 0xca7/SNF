add_executable(module_util_app
    module_util.c
)

target_link_libraries(module_util_app
    util
    Unity
)

add_test(module_util_test module_util_app)
