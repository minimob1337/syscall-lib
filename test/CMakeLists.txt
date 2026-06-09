add_executable(syscall_test main.cpp)
target_link_libraries(syscall_test PRIVATE syscall)
set_target_properties(syscall_test PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
)
