cmake_minimum_required(VERSION 3.10)
project(tlssw)

find_package(OpenSSL 1.1.1 REQUIRED)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fvisibility=hidden")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -pedantic -Wall -Wextra -Wcast-align -Wcast-qual -Wctor-dtor-privacy -Wdisabled-optimization -Wformat=2 -Winit-self -Wmissing-declarations -Wmissing-include-dirs -Wold-style-cast -Woverloaded-virtual -Wredundant-decls -Wsign-conversion -Wsign-promo -Wstrict-overflow=5 -Wswitch-default -Wundef -Wno-unused -Wno-type-limits")
set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -Wl,--no-undefined")

if(CMAKE_COMPILER_IS_GNUCXX)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wnoexcept -Wstrict-null-sentinel -Wlogical-op")
endif()

add_library(${PROJECT_NAME} STATIC src/${PROJECT_NAME}.cpp)

set_property(TARGET ${PROJECT_NAME}
             PROPERTY PUBLIC_HEADER
             src/${PROJECT_NAME}/${PROJECT_NAME}.h)
target_include_directories(${PROJECT_NAME} PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(${PROJECT_NAME} PRIVATE OpenSSL::SSL)
target_compile_features(${PROJECT_NAME} PUBLIC cxx_std_17)

add_executable(example_tls_server example/tls_server.cpp)
target_link_libraries(example_tls_server PRIVATE ${PROJECT_NAME})

add_executable(example_tls_client example/tls_client.cpp)
target_link_libraries(example_tls_client PRIVATE ${PROJECT_NAME})
