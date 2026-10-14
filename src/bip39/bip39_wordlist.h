#pragma once

#include <stddef.h>

// Official BIP-39 English wordlist (2048 words, "abandon" .. "zoo").
// Pure C++ with no Arduino dependency.

namespace es {
namespace bip39 {

constexpr size_t kWordlistSize = 2048;
constexpr size_t kMaxWordLength = 8;  // longest English BIP-39 word

// Returns the word at index, or nullptr if index >= kWordlistSize.
const char* getWord(size_t index);

// Returns the index of word in the list, or -1 if it is not a BIP-39 word.
// Exact, case-sensitive match (the list is all lowercase). Binary search, so
// lookup time depends on the word; acceptable for this educational prototype.
int findWordIndex(const char* word);

}  // namespace bip39
}  // namespace es
