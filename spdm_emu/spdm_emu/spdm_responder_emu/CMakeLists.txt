cmake_minimum_required(VERSION 2.6)

INCLUDE_DIRECTORIES(${PROJECT_SOURCE_DIR}/spdm_emu/spdm_responder_emu
                    ${PROJECT_SOURCE_DIR}/spdm_emu/spdm_emu_common
                    ${LIBSPDM_DIR}/os_stub/spdm_device_secret_lib
                    ${LIBSPDM_DIR}/include
                    ${LIBSPDM_DIR}/include/hal
                    ${LIBSPDM_DIR}/include/hal/${ARCH}
                    ${LIBSPDM_DIR}/os_stub/include
)

SET(src_spdm_responder_emu
    spdm_responder.c
    spdm_responder_session.c
    spdm_responder_emu.c
    ${PROJECT_SOURCE_DIR}/spdm_emu/spdm_emu_common/spdm_emu.c
    ${PROJECT_SOURCE_DIR}/spdm_emu/spdm_emu_common/command.c
    ${PROJECT_SOURCE_DIR}/spdm_emu/spdm_emu_common/key.c
    ${PROJECT_SOURCE_DIR}/spdm_emu/spdm_emu_common/nv_storage.c
    ${PROJECT_SOURCE_DIR}/spdm_emu/spdm_emu_common/pcap.c
    ${PROJECT_SOURCE_DIR}/spdm_emu/spdm_emu_common/support.c
    ${PROJECT_SOURCE_DIR}/spdm_emu/spdm_emu_common/perf.c
)

SET(spdm_responder_emu_LIBRARY
    memlib
    debuglib_null
    spdm_responder_lib
    spdm_common_lib
    ${CRYPTO}lib
    rnglib
    cryptlib_${CRYPTO}
    pqc_crypt_lib_oqs
    oqs
    malloclib
    spdm_crypt_lib
    spdm_pqc_crypt_lib
    spdm_secured_message_lib
    spdm_transport_mctp_lib
    spdm_transport_pcidoe_lib
    spdm_device_secret_lib
)

if((TOOLCHAIN STREQUAL "KLEE") OR (TOOLCHAIN STREQUAL "CBMC"))
    ADD_EXECUTABLE(spdm_responder_emu
                   ${src_spdm_responder_emu}
                   $<TARGET_OBJECTS:memlib>
                   $<TARGET_OBJECTS:debuglib_null>
                   $<TARGET_OBJECTS:spdm_responder_lib>
                   $<TARGET_OBJECTS:spdm_common_lib>
                   $<TARGET_OBJECTS:${CRYPTO}lib>
                   $<TARGET_OBJECTS:rnglib>
                   $<TARGET_OBJECTS:cryptlib_${CRYPTO}>
                   $<TARGET_OBJECTS:malloclib>
                   $<TARGET_OBJECTS:spdm_crypt_lib>
                   $<TARGET_OBJECTS:spdm_secured_message_lib>
                   $<TARGET_OBJECTS:spdm_transport_mctp_lib>
                   $<TARGET_OBJECTS:spdm_transport_pcidoe_lib>
                   $<TARGET_OBJECTS:spdm_device_secret_lib>
    )
else()
    ADD_EXECUTABLE(spdm_responder_emu ${src_spdm_responder_emu})
    TARGET_LINK_LIBRARIES(spdm_responder_emu ${spdm_responder_emu_LIBRARY})
endif()
