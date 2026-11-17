# Hardened Safe String Library (`safestringlib-hardened-c`)

> **Maintained, Hardened Drop-in Fork of Intel's Archived Safe String Library**  
> *Audited and Remediated via DecodeIQ CodeTruth Engine*

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Standards: MISRA-C / CERT-C](https://img.shields.io/badge/Standard-CERT--C%20EXP33--C-brightgreen.svg)]()
[![Status: Maintained](https://img.shields.io/badge/Status-Maintained%20Fork-orange.svg)]()

---

## 🛡️ Why This Fork Exists

On **July 20, 2024**, Intel officially archived `intel/safestringlib` with the notice:
> *"Intel will not provide or guarantee development of or support for this project, including but not limited to, maintenance, bug fixes, new releases or updates. Patches to this project are no longer accepted by Intel. If you have an ongoing need to use this project... please create your own fork of the project."*

`safestringlib` was designed by Intel's Security Center of Excellence (SeCoE) as the reference C11 Annex K implementation providing bounds-checked alternatives to banned legacy C functions (`strcpy`, `strcat`, `memcpy`, `memmove`, `sprintf`) under Secure Development Lifecycle (SDL) guidelines.

However, a deterministic AST audit using **DecodeIQ CodeTruth** revealed that Intel's original codebase contained **86 CERT-C EXP33-C uninitialized stack variable violations** across 37 translation units in `safeclib/` (including `memcpy_s.c`, `strcpy_s.c`, `strcat_s.c`, and `memmove_s.c`).

Leaving stack variables uninitialized allows modern optimizing compilers (GCC 12+, Clang 15+, MSVC 19.35+ with `-O2/-O3`) to assume undefined behavior, discard defensive checks, or leak residual stack data across function calls.

---

## 🔧 What Was Fixed

* **86 CERT-C EXP33 Violations Remediated:** Every scalar and pointer declaration across 37 files in `safeclib/` has been explicitly initialized (`= NULL;`, `= 0;`).
* **100% ABI and API Compatibility:** Exact drop-in replacement for `intel/safestringlib`. No headers or linkage interfaces were altered.
* **Deterministic Remediation:** 0 heuristic guesswork, 0 LLM hallucinations — generated via syntax-tree analysis.
* **Full Audit Report:** Read the complete forensic breakdown in [`SAFESTRINGLIB_HARDENING_FORENSIC_REPORT.md`](SAFESTRINGLIB_HARDENING_FORENSIC_REPORT.md).

---

## 🚀 Building & Integration

### With CMake:
```bash
mkdir build && cd build
cmake ..
cmake --build .
```

### Direct Compilation:
Include the header files in your build:
```bash
gcc -Iinclude -c safeclib/*.c
```

---

## 📜 License
This library is licensed under the original MIT Open Source License. See [LICENSE](LICENSE) for details.
