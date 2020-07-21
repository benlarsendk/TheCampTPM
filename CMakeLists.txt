cmake_minimum_required(VERSION 3.10)
project(TheCampCode)

set(CMAKE_CXX_STANDARD 14)

include_directories(.)
add_definitions(-DTPM_POSIX) # Use DTPM_WINDOWS if you're on windows
add_definitions(-DVERBOSE)
include_directories(/opt/ibmtss/utils)


add_executable(TheCampCode
        Antivirus.txt
        CMakeLists.txt
        cryptoutils.c
        database.txt
        defines.h
        helperFunctions.h
        main.cpp
        NetworkManager.cpp
        NetworkManager.h
        PCRSelection.h
        TpmManager.cpp
        TpmManager.h
        tss_includes.h)
find_package(OpenSSL REQUIRED)
include_directories(${OPENSSL_INCLUDE_DIR})
target_link_libraries(TheCampCode ibmtss ${OPENSSL_LIBRARIES})