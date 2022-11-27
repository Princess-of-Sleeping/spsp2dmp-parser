cmake_minimum_required(VERSION 3.0)

project(spsp2dmp-parser C)

set(CMAKE_C_COMPILE_FEATURES "${CMAKE_C_FLAGS} -Wunused-result -Wl,-q -Wall -O3 -fno-inline -fno-builtin")

include_directories(
 ./include/
)

add_executable(${PROJECT_NAME}
  src/main.c
)

target_link_libraries(${PROJECT_NAME}
  crypto
  z
)
