# SampleMbedCrypto — SGX Fix Summary

## The Problem

Modern Intel SGX SDK (v2.14+) removed the bundled `libsgx_mbedcrypto.a` and stopped shipping
mbedTLS headers. The sample was written for older SDK versions and fails out of the box with:

1. Compiler error: `mbedtls/aes.h: No such file or directory`
2. Linker error: `cannot find -lsgx_mbedcrypto`

## The Solution

Build mbedTLS 3.6.x from source with SGX-compatible compiler flags, disable OS features
that don't exist inside an enclave, and add an entropy bridge using SGX's RDRAND instruction.

---

## Files Changed / Created

### `Makefile` (modified)

Three changes:

1. **Added mbedTLS include path** so the compiler finds the headers:
   ```makefile
   Enclave_Include_Paths := ... -Imbedtls-src/include
   ```

2. **Added `-L.`** to the linker flags so it finds our locally-built `libsgx_mbedcrypto.a`:
   ```makefile
   -L$(SGX_LIBRARY_PATH) -L. \
   ```

3. **Added entropy bridge** as a C source file compiled into the enclave, and wired up
   the mbedTLS library build as a dependency:
   ```makefile
   Enclave_C_Files := Enclave/mbedtls_sgx_entropy.c
   Enclave_C_Objects := $(Enclave_C_Files:.c=.o)

   libsgx_mbedcrypto.a:
       @$(MAKE) -f Makefile.mbedtls

   $(Enclave_Name): Enclave/Enclave_t.o $(Enclave_Cpp_Objects) $(Enclave_C_Objects) libsgx_mbedcrypto.a
   ```

---

### `Makefile.mbedtls` (created)

Builds `libsgx_mbedcrypto.a` from mbedTLS source with SGX-compatible flags.

Key flags used (matching the enclave's compiler flags):
- `-nostdinc` — do not use system headers; use only SGX tlibc and mbedTLS headers
- `-fPIC -fpie` — position-independent code, required for enclave memory layout
- `-fstack-protector` — required for enclave security
- `-fvisibility=hidden` — enclave symbols must not be exported

```makefile
CFLAGS := -m64 -O2 \
          -nostdinc -fvisibility=hidden -fpie -fstack-protector -fPIC \
          -I$(MBEDTLS_DIR)/include \
          -I$(SGX_SDK)/include \
          -I$(SGX_SDK)/include/tlibc
```

---

### `Enclave/mbedtls_sgx_entropy.c` (created)

mbedTLS needs a source of random bytes to seed its RNG (used by ECDSA key generation).
Inside an enclave there is no `/dev/urandom`, so we implement `mbedtls_hardware_poll()`
using SGX's `sgx_read_rand()`, which invokes the CPU's RDRAND instruction:

```c
int mbedtls_hardware_poll(void *data,
                          unsigned char *output,
                          size_t len,
                          size_t *olen)
{
    (void)data;
    sgx_status_t ret = sgx_read_rand(output, len);
    if (ret != SGX_SUCCESS)
        return -1;
    *olen = len;
    return 0;
}
```

---

### `mbedtls-src/include/mbedtls/mbedtls_config.h` (modified)

The original config enables all features including ones that assume a full OS environment.
We disabled features that are incompatible with SGX and enabled hardware entropy.

A backup of the original config is saved as `mbedtls_config.h.original`.

| Config Flag | Change | Reason |
|---|---|---|
| `MBEDTLS_FS_IO` | disabled | No filesystem inside SGX |
| `MBEDTLS_NET_C` | disabled | No networking (no `sys/socket.h`) inside SGX |
| `MBEDTLS_TIMING_C` | disabled | No OS timing / `signal.h` inside SGX |
| `MBEDTLS_HAVE_TIME` | disabled | No system clock inside SGX |
| `MBEDTLS_HAVE_TIME_DATE` | disabled | No system clock inside SGX |
| `MBEDTLS_NO_PLATFORM_ENTROPY` | **enabled** | No `/dev/urandom` inside SGX |
| `MBEDTLS_ENTROPY_HARDWARE_ALT` | **enabled** | Use our `mbedtls_hardware_poll` (RDRAND) |
| `MBEDTLS_SELF_TEST` | disabled | Self-test code calls `puts`/`rand` not in SGX tlibc |
| `MBEDTLS_PSA_ITS_FILE_C` | disabled | Requires `MBEDTLS_FS_IO` |
| `MBEDTLS_PSA_CRYPTO_STORAGE_C` | disabled | Requires filesystem or ITS |

---

## How to Build and Run

```bash
# Build (simulation mode — no real SGX hardware required)
make SGX_MODE=SIM

# Run
LD_LIBRARY_PATH=/opt/intel/sgxsdk/lib64 ./app
```

## Expected Output

```
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
SHA256 PASSED
AES-CTR PASSED
  . Seeding the random number generator... ok
  . Generating key pair... ok (key size: 192 bits)
  . Computing message hash... ok
  . Signing message hash... ok (signature length = 56)
  . Preparing verification context... ok
  . Verifying signature... ok
ECDSA PASSED
Info: MbedCrypto Sample completed.
Info: All test passed.
```

## Why This Works

mbedTLS is plain C code — it is not inherently incompatible with SGX. The SGX SDK simply
stopped bundling a pre-compiled version. By compiling mbedTLS ourselves with SGX's compiler
flags and headers, and disabling features that assume OS services (filesystem, networking,
system clock, OS entropy), we get a library that runs correctly inside the enclave's
isolated execution environment.
