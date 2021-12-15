add_executable(snf
    main.c
)

target_link_libraries(snf
    # add modules here
    global_cfg
    packet
    generator
    networking
)

