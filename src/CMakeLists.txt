# Bring in the headers and sources
include_directories(../include)
file(GLOB_RECURSE SOURCES "*.c")

# Generate the shared library from the sources
add_library(utilc-crypto SHARED ${SOURCES})

# Compile with math library
target_link_libraries(utilc-crypto m)

# Install system-wide
install(TARGETS utilc-crypto DESTINATION /usr/lib)
