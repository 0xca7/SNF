add_library(global_cfg STATIC)
target_sources(global_cfg PUBLIC inc/global_cfg.h)
set_target_properties(global_cfg PROPERTIES LINKER_LANGUAGE CXX)

target_include_directories(global_cfg PUBLIC
    inc/
)
