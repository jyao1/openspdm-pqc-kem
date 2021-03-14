cmake_minimum_required(VERSION 2.6)

INCLUDE_DIRECTORIES(${PROJECT_SOURCE_DIR}/UnitTest/TestPqcCryptLib
                    ${PROJECT_SOURCE_DIR}/Include
                    ${PROJECT_SOURCE_DIR}/Include/Hal 
                    ${PROJECT_SOURCE_DIR}/Include/Hal/${ARCH}
                    ${PROJECT_SOURCE_DIR}/OsStub/Include                
)

SET(src_TestPqcCryptLib
    PqcCryptest.c
    SigVerify.c
    KemVerify.c
    OsSupport.c
)

SET(TestPqcCryptLib_LIBRARY
    BaseMemoryLib 
    DebugLib 
    RngLib
    PqcCryptLibOqs
    MemoryAllocationLib
)

ADD_EXECUTABLE(TestPqcCryptLib ${src_TestPqcCryptLib})
TARGET_LINK_LIBRARIES(TestPqcCryptLib ${TestPqcCryptLib_LIBRARY})

