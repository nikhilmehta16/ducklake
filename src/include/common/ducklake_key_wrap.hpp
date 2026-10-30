//===----------------------------------------------------------------------===//
//                         DuckDB
//
// common/ducklake_key_wrap.hpp
//
//
//===----------------------------------------------------------------------===//

#pragma once

#include "duckdb/common/common.hpp"
#include "duckdb/common/crypto/crypto_provider.hpp"

namespace duckdb {

class EncryptionUtil;

class DuckLakeKeyWrap {
public:
	static constexpr idx_t KEK_SIZE = 32;
	static constexpr idx_t IV_SIZE = 12;
	static constexpr idx_t TAG_SIZE = 16;
	// Binary magic: \x00 D L K \x01 — null byte prevents collision with raw DEK bytes or base64 strings
	static constexpr const char MAGIC[] = "\x00" "DLK" "\x01";
	static constexpr idx_t MAGIC_SIZE = 5;

	//! Derive a 32-byte KEK from user input. 64-hex-char input taken as raw key, otherwise SHA-256.
	static string DeriveKEK(const string &passphrase);
	//! Wrap a raw DEK with a KEK. Returns binary: MAGIC || iv || ciphertext || tag.
	//! If kek is empty, returns the raw DEK unchanged.
	static string Wrap(EncryptionUtil &util, const string &kek, const string &raw_dek);
	//! Unwrap a potentially wrapped DEK. Detects MAGIC prefix → unwrap; otherwise returns as-is (legacy).
	static string Unwrap(EncryptionUtil &util, const string &kek, const string &maybe_wrapped);
	//! Check if a value has the wrapped magic prefix.
	static bool IsWrapped(const string &value);
};

} // namespace duckdb
