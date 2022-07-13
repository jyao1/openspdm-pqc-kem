cmake_minimum_required(VERSION 2.6)

INCLUDE_DIRECTORIES(${LIBSPDM_DIR}/unit_test/test_pqc_crypt
                    ${LIBSPDM_DIR}/include
                    ${LIBSPDM_DIR}/include/hal 
                    ${LIBSPDM_DIR}/include/hal/${ARCH}
                    ${LIBSPDM_DIR}/os_stub/include
)

SET(src_test_pqc_crypt
    test_pqc_crypt.c
    sig_verify.c
    hybrid_sig_verify.c
    kem_verify.c
    os_support.c
    perf.c
)

SET(test_pqc_crypt_LIBRARY
    memlib 
    debuglib_null
    ${CRYPTO}lib
    rnglib
    cryptlib_${CRYPTO}
    pqc_crypt_lib_oqs
    malloclib
    oqs
    cmockalib
)

ADD_EXECUTABLE(test_pqc_crypt ${src_test_pqc_crypt})
TARGET_LINK_LIBRARIES(test_pqc_crypt ${test_pqc_crypt_LIBRARY})

