#pragma once

#include "duckdb/common/common.hpp"
#include "duckdb/common/encryption_state.hpp"

namespace duckdb {

class DuckLakeKeyWrap {
public:
	static constexpr const char *PREFIX = "kek1:";
	static constexpr idx_t KEK_SIZE = 32;
	static constexpr idx_t IV_SIZE = 12;
	static constexpr idx_t TAG_SIZE = 16;

	//! Derive a 32-byte KEK from a user passphrase (SHA-256). A 64-hex-char input is taken as the raw key.
	static string DeriveKEK(const string &passphrase);
	//! True if the stored value carries the wrapped-key prefix.
	static bool IsWrapped(const string &stored);
	//! Wrap a DEK for storage. Empty kek -> plain base64 (legacy behaviour).
	static string Encode(EncryptionUtil &util, const string &kek, const string &dek);
	//! Read a stored value back to a DEK. Wrapped values require kek; raw values never do.
	static string Decode(EncryptionUtil &util, const string &kek, const string &stored);
};

} // namespace duckdb
