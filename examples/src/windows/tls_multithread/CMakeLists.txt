cmake_minimum_required(VERSION 3.10)
project(x8664_tls_multithread C)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)

add_executable(x8664_tls_multithread main.c)

if(MINGW)
    target_compile_options(x8664_tls_multithread PRIVATE
        -Os
        -fno-asynchronous-unwind-tables
        -fno-ident
        -fno-stack-protector
    )

    target_link_options(x8664_tls_multithread PRIVATE
        -nostdlib
        -eEntryPoint
        -s
        -Wl,--gc-sections
    )

    target_link_libraries(x8664_tls_multithread PRIVATE kernel32 user32)
endif()