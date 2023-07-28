add_executable(injector injector.cpp)

target_include_directories(injector PRIVATE "${PROJECT_SOURCE_DIR}/common")
target_link_libraries(injector PRIVATE Boost::boost Boost::program_options Boost::filesystem)
