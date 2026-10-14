#pragma once

#include <stddef.h>
#include <stdint.h>

// Explicit wiping of secrets (entropy, mnemonic, seed, keys) held in RAM.
// Pure C++ with no Arduino dependency so it can be unit-tested on the host.

namespace es {
namespace security {

// Overwrites len bytes at ptr with zeros. Writes go through a volatile pointer
// so the compiler cannot drop them as dead stores, even when the buffer is
// about to go out of scope. The empty asm with a "memory" clobber is a compiler
// barrier that also keeps link-time optimization from eliding the loop.
inline void secureMemzero(void* ptr, size_t len) {
    if (ptr == nullptr) {
        return;
    }
    volatile uint8_t* p = static_cast<volatile uint8_t*>(ptr);
    while (len--) {
        *p++ = 0;
    }
#if defined(__GNUC__)
    __asm__ __volatile__("" : : "r"(ptr) : "memory");
#endif
}

}  // namespace security
}  // namespace es
