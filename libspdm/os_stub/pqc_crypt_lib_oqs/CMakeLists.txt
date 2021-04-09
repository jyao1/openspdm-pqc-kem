cmake_minimum_required(VERSION 2.6)

INCLUDE_DIRECTORIES(${LIBSPDM_DIR}/os_stub/pqc_crypt_lib_oqs
                    ${LIBSPDM_DIR}/include
                    ${LIBSPDM_DIR}/include/hal
                    ${LIBSPDM_DIR}/include/hal/${ARCH}
                    ${LIBOQS_DIR}/include
)

SET(src_pqc_crypt_lib_oqs
    pqc_crypt_lib_oqs.c
)

ADD_LIBRARY(pqc_crypt_lib_oqs STATIC ${src_pqc_crypt_lib_oqs})
