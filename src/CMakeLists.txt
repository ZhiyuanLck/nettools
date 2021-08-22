add_executable(ping ping.cpp)
target_link_libraries(ping PRIVATE fmt::fmt-header-only PRIVATE ${Boost_LIBRARIES})
