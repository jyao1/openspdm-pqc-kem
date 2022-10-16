# build oqs library

This is required to generate oqs library to build libspdm.

1. Refer to https://github.com/open-quantum-safe/liboqs

2. Follow the step by step to build

```
mkdir build && cd build
cmake -GNinja [-DCMAKE_BUILD_TYPE=Release] ..
ninja
```

3. The output is at `lib` and `include`

# build oqs enabled openssl binary

This is required to generate openssl tool for hybrid certificate.

1. Refer to https://github.com/open-quantum-safe/openssl

2. Follow the step by step to build

* To build the oqs lib:
```
git clone --branch main https://github.com/open-quantum-safe/liboqs.git
cd liboqs
mkdir build
cd build
cmake -GNinja -DCMAKE_INSTALL_PREFIX=..\..\oqs [-DCMAKE_BUILD_TYPE=Release] ..
ninja
ninja install
```

* To build openssl:
```
perl Configure [debug-]VC-[WIN32|WIN64A] no-shared [no-asm] --prefix=<OPENSSL_PATH>\build
nmake
nmake install
```

3. The output is at `build`

4. Follow libspdm/unit_test/sample_key/readme.txt to generate keys.
