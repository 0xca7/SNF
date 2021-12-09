add_executable(module_generator_app
    module_generator.c
)

target_link_libraries(module_generator_app
    generator
    Unity
)

add_test(module_generator_test module_generator_app)
