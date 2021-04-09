1) The keys can be generated with openspdm - test_pqc_crypt - test function.

2) The keys can be generated with liboqs - "liboqs$ build/tests/test_sig_mem <pqc_alg> 0", then copied from "build/mem-benchmark".

=================
test_sig_mem algname operation (0,1,2)
    0 means generate keys.
    1 means sign message.
    2 means verify message.
=================

