#Compile the example executable
add_executable(utilc-crypto-example utilc-crypto-example.c)
include_directories(../include/)
target_link_libraries(utilc-crypto-example utilc-crypto)
