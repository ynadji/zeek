zeek_add_plugin(
    Zeek AsciiReader
    SOURCES Ascii.cc Plugin.cc
    BIFS ascii.bif
    LINK_LIBS ${ZLIB_LIBRARY})
