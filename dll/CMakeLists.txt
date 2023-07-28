add_library(dll SHARED dll.cpp)

target_include_directories(dll PRIVATE ${DETOURS_INCLUDE_DIRS})
target_link_libraries(dll PRIVATE ${DETOURS_LIBRARY})
