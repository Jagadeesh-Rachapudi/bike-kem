Additional implementation of Lean-BIKE (Bit Flipping Key Encapsulation) 
------------------------------------------------------------------

This package is an "Additional Optimized" implementation
of a IND-CPA secure version of Key Encapsulation Mechanism (KEM) [BIKE](https://bikesuite.org),
intended to be used only with ephemeral keys. This version of BIKE was presented at the NIST 5th PQC Standardization Conference (April 10-12, 2024): [A lean BIKE KEM design for ephemeral key agreement](https://csrc.nist.gov/csrc/media/Events/2024/fifth-pqc-standardization-conference/documents/papers/a-lean-bike-kem.pdf).

It is developed and maintained solely by the DGK team that consists of
Nir Drucker, Shay Gueron, and Dusan Kostic.

BIKE is a KEM submission to the [Post-Quantum Cryptography Standardization project](https://csrc.nist.gov/projects/post-quantum-cryptography/post-quantum-cryptography-standardization). At this point in time, NIST is considering BIKE as a fourth round candidate in the PQC Standardization process ([link](https://csrc.nist.gov/News/2022/pqc-candidates-to-be-standardized-and-round-4)).

The official BIKE website is: https://bikesuite.org. 

The package includes implementations for several CPU architectures.
In particular, it can be compiled for a 64-bit ARM and for x86 processors.
ARM architectures are supported by a fully portable implementation written in C.
When the code is compiled for x86 processors, the resulting binary contains
the following implementations:
- Fully portable
- Optimized for AVX2 and AVX512 instruction sets 
- Optimized for CPUs that support PCLMULQDQ, and the latest Intel
  vector-PCLMULQDQ instruction.

When the package is used on an x86 CPU, it automatically (in runtime) detects 
the CPU capabilities and runs the fastest available code path, based on the
detected capabilities. The fully portable version, which is built by default,
requires OpenSSL. The library can also be compiled in a "stand-alone" mode,
without OpenSSL, but only for a processor that supports AES-NI and AVX
instructions. This mode can be enabled by a compilation flag described below.

The package includes testing and it uses the KAT generation utilities provided
by NIST.

All the functionalities in the package are implemented in constant-time,
which means that: 
- No branch depends on a secret piece of information; 
- All the memory access patters are independent of secret information.

The optimizations in this package use, among other techniques, algorithms
presented in the following papers:
- Nir Drucker, Shay Gueron, 
  "A Toolbox for Software Optimization of QC-MDPC Code-Based Cryptosystems."
  Journal of Cryptographic Engineering, January 2019, 1–17
  https://doi.org/10.1007/s13389-018-00200-4.

- Chou, T.: QcBits: Constant-Time Small-Key Code-Based Cryptography. In: 
  Gier-lichs, B., Poschmann, A.Y. (eds.) Cryptographic Hardware and
  Embedded Systems– CHES 2016. pp. 280–300. Springer Berlin Heidelberg, 
  Berlin, Heidelberg (2016)

- Guimarães, Antonio, Diego F Aranha, and Edson Borin. 2019.
  “Optimized Implementation of QC-MDPC Code-Based Cryptography.”
  Concurrency and Computation: Practice and Experience 31 (18):
  e5089. https://doi.org/10.1002/cpe.5089.

The GF2X inversion in this package is based on:
- Nir Drucker, Shay Gueron, Dusan Kostic, Fast polynomial inversion for post quantum QC-MDPC cryptography, Information and Computation, 2021, 104799, ISSN 0890-5401, https://doi.org/10.1016/j.ic.2021.104799.

The definition and the analysis of the constant-time BGF decoder used in this package is given in:
- Drucker N., Gueron S., Kostic D. (2020) On Constant-Time QC-MDPC Decoders with Negligible Failure Rate. In: Baldi M., Persichetti E., Santini P. (eds) Code-Based Cryptography. CBCrypto 2020. Lecture Notes in Computer Science, vol 12087. Springer, Cham. https://doi.org/10.1007/978-3-030-54074-6_4
- Drucker N., Gueron S., Kostic D. (2020) QC-MDPC Decoders with Several Shades of Gray. In: Ding J., Tillich JP. (eds) Post-Quantum Cryptography. PQCrypto 2020. Lecture Notes in Computer Science, vol 12100. Springer, Cham. https://doi.org/10.1007/978-3-030-44223-1_3

The code contains additional versions that can be enabled by the following
flags: BIND_PK_AND_M and USE_SHA3_AND_SHAKE. The flags can be turned on
individually or both at the same time.

Flag BIND_PK_AND_M enables binding of the public key and the message when
generating the ciphertext in encapsulation. This security measure was
proposed in:
- Drucker N., Gueron S., Kostic D. (2021) Binding BIKE Errors to a Key Pair. In: Dolev S., Margalit O., Pinkas B., Schwarzmann A. (eds) Cyber Security Cryptography and Machine Learning. CSCML 2021. Lecture Notes in Computer Science, vol 12716. Springer, Cham. https://doi.org/10.1007/978-3-030-78086-9_21

Flag USE_SHA3_AND_SHAKE turns on the version of BIKE which uses SHA3 algorithm
as a hash function (wherever a hash function is needed) and SHAKE based PRF.
This modification was proposed by the BIKE team in https://bikesuite.org/files/v4.2/BIKE_Spec.2021.07.26.1.pdf.

License
-------
This project is licensed under the Apache-2.0 License.

Dependencies
------------
This package requires
- CMake 3 and above
- An installation of OpenSSL for the KAT testing

BUILD
-----

To build the directory first create a working directory
```
mkdir build
cd build
```

Then, run CMake and compile
```
cmake -DCMAKE_BUILD_TYPE=Release ..
make
```

By default the package is compiled with parameters defined for NIST security
Level-1 (64-bit quantum security). The default compilation options require
OpenSSL to be available on the system. The "stand-alone" compilation, which can
be enabled by a flag, assumes that AES_NI and POPCNT instructions are available.

Additional compilation flags:
 - USE_NIST_RAND            - Using the DRBG of NIST and generate the KATs.
 - STANDALONE_IMPL          - Stand-alone implementation that doesn't depend on
                              any external library.
 - OPENSSL_DIR              - Set the path of the OpenSSL include/lib
                              directories (required only if OpenSSL is not
                              installed in usual directories).
 - FIXED_SEED               - Using a fixed seed, for debug purposes.
 - RDTSC                    - Benchmark the algorithm (results in CPU cycles).
 - VERBOSE                  - Add verbose (level: 1-4 default: 1).
 - NUM_OF_TESTS             - Set the number of tests (keygen/encaps/decaps)
                              to run (default: 1).
 - LEVEL                    - Security level 1, 3, or 5.
 - ASAN/TSAN/MSAN/UBSAN     - Enable the associated clang sanitizer.
 
To clean - remove the `build` directory. Note that a "clean" is required prior
to compilation with modified flags.

To format (`clang-format-9` or above is required):

`make format`

To use clang-tidy (`clang-tidy-9` is required):

```
CC=clang-9 cmake -DCMAKE_C_CLANG_TIDY="clang-tidy-9;--fix-errors;--format-style=file" ..
make
```

Before committing code, please test it using
`tests/run_tests.sh 0`
This will run all the sanitizers.

The package was compiled and tested with clang (version 10.0.0) in 64-bit mode,
on a Linux (Ubuntu 20.04) on Intel Xeon (x86) and Graviton 2 (ARM) processors.
The x86 tests are done with Intel SDE which can emulate any Intel CPU.
Compilation on other platforms may require some adjustments.

KATs
----
The KATs are located in the `tests/kats/` directory.

Performance
----
The performance of Lean-BIKE is given in Tables 1 and 2 of (A lean BIKE KEM design for ephemeral key agreement)[https://csrc.nist.gov/csrc/media/Events/2024/fifth-pqc-standardization-conference/documents/papers/a-lean-bike-kem.pdf)]

Sampling fixed-weight vectors
------------------

Rejection sampling (until BIKE Spec v4.2)
------------------
The rejection sampling design and implementation that was used (until [Spec v4.2](https://bikesuite.org/files/v4.2/BIKE_Spec.2021.07.26.1.pdf)) is described in the document entitled ["Isochronous implementation of the errors-vector generation of BIKE"](https://github.com/awslabs/bike-kem/blob/master/BIKE_Rejection_Sampling.pdf). That document explains our response to the paper [Don't reject this: Key-recovery timing attacks due to rejection-sampling in HQC and BIKE](https://doi.org/10.46586/tches.v2022.i3.223-263) by Qian Guo et al, which is implemented here (since June 2022).
