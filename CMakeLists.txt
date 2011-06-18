cmake_minimum_required(VERSION 2.8)
project(ThomsonCrack C)

add_executable(thomsoncrack thomsoncrack.c)

include_directories(${CMAKE_CURRENT_SOURCE_DIR})

if(CMAKE_COMPILER_IS_GNUCC)
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -pedantic -std=c99")
endif()

find_library(PTHREAD pthread)
find_library(CRYPTO crypto)
target_link_libraries(thomsoncrack ${PTHREAD} ${CRYPTO})


