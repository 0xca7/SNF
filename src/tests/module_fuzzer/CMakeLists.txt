add_executable(module_fuzzer_app
    module_fuzzer.c
)

target_link_libraries(module_fuzzer_app
    fuzzer
    Unity
)

add_test(module_fuzzer_test module_fuzzer_app)

