cmake_minimum_required(VERSION 2.6)

INCLUDE_DIRECTORIES(${PROJECT_SOURCE_DIR}/OsStub/PqcCryptLibOqs
                    ${PROJECT_SOURCE_DIR}/Include
                    ${PROJECT_SOURCE_DIR}/Include/Hal
                    ${PROJECT_SOURCE_DIR}/Include/Hal/${ARCH}
                    ${PROJECT_SOURCE_DIR}/oqs/include
)

SET(src_PqcCryptLibOqs
    PqcCryptLibOqs.c
)

ADD_LIBRARY(PqcCryptLibOqs STATIC ${src_PqcCryptLibOqs})
