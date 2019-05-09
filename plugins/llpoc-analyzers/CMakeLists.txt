project(llpoc-analyzers-plugin)

cmake_minimum_required(VERSION 2.6.3)

if ( NOT ZEEK_DIST )
    message(FATAL_ERROR "ZEEK_DIST not set")
endif ()

set(CMAKE_MODULE_PATH ${ZEEK_DIST}/cmake)
message(${CMAKE_MODULE_PATH})

file(GLOB_RECURSE PROTO_SRCS src/protocols/*.cc)

include(ZeekPlugin)

zeek_plugin_begin(LLPOC Analyzers)
zeek_plugin_cc(src/Plugin.cc)
zeek_plugin_cc(${PROTO_SRCS})
zeek_plugin_end()
