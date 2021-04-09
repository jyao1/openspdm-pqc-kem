cmake_minimum_required(VERSION 2.6)

INCLUDE_DIRECTORIES(${LIBSPDM_DIR}/Library/spdm_pqc_crypt_lib
                    ${LIBSPDM_DIR}/include
                    ${LIBSPDM_DIR}/include/hal
                    ${LIBSPDM_DIR}/include/hal/${ARCH}
)

SET(src_spdm_pqc_crypt_lib
    spdm_pqc_crypt_lib.c
)

ADD_LIBRARY(spdm_pqc_crypt_lib STATIC ${src_spdm_pqc_crypt_lib})
