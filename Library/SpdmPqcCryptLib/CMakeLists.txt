cmake_minimum_required(VERSION 2.6)

INCLUDE_DIRECTORIES(${PROJECT_SOURCE_DIR}/Library/SpdmPqcCryptLib
                    ${PROJECT_SOURCE_DIR}/Include
                    ${PROJECT_SOURCE_DIR}/Include/Hal
                    ${PROJECT_SOURCE_DIR}/Include/Hal/${ARCH}
)

SET(src_SpdmPqcCryptLib
    SpdmPqcCryptLib.c
)

ADD_LIBRARY(SpdmPqcCryptLib STATIC ${src_SpdmPqcCryptLib})
