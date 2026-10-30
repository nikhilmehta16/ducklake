#include "common/ducklake_key_wrap.hpp"

#include "duckdb/common/types/blob.hpp"
#include "duckdb/common/exception.hpp"
#include "duckdb/common/string_util.hpp"
#include "mbedtls_wrapper.hpp"
#include "duckdb/common/encryption_types.hpp"
#include <algorithm>
#include <cstring>

namespace duckdb {

constexpr idx_t DuckLakeKeyWrap::KEK_SIZE;
constexpr idx_t DuckLakeKeyWrap::IV_SIZE;
constexpr idx_t DuckLakeKeyWrap::TAG_SIZE;
constexpr idx_t DuckLakeKeyWrap::MAGIC_SIZE;

string DuckLakeKeyWrap::DeriveKEK(const string &passphrase) {
	if (passphrase.empty()) {
		throw InvalidInputException("KEY_ENCRYPTION_KEY must not be empty");
	}
	if (passphrase.size() == KEK_SIZE * 2 &&
	    std::all_of(passphrase.begin(), passphrase.end(),
	                [](char c) { return std::isxdigit(static_cast<unsigned char>(c)) != 0; })) {
		string raw;
		raw.resize(KEK_SIZE);
		for (idx_t i = 0; i < KEK_SIZE; i++) {
			raw[i] = static_cast<char>(std::stoi(passphrase.substr(i * 2, 2), nullptr, 16));
		}
		return raw;
	}
	string hash;
	hash.resize(duckdb_mbedtls::MbedTlsWrapper::SHA256_HASH_LENGTH_BYTES);
	duckdb_mbedtls::MbedTlsWrapper::ComputeSha256Hash(passphrase.data(), passphrase.size(), &hash[0]);
	return hash;
}

bool DuckLakeKeyWrap::IsWrapped(const string &value) {
	if (value.size() < MAGIC_SIZE) {
		return false;
	}
	return memcmp(value.data(), MAGIC, MAGIC_SIZE) == 0;
}

string DuckLakeKeyWrap::Wrap(EncryptionUtil &util, const string &kek, const string &raw_dek) {
	if (kek.empty()) {
		return raw_dek;
	}
	if (kek.size() != KEK_SIZE) {
		throw InternalException("DuckLake KEK must be %d bytes", KEK_SIZE);
	}
	auto aes = util.CreateEncryptionState(
	    make_uniq<EncryptionStateMetadata>(EncryptionTypes::GCM, KEK_SIZE, EncryptionTypes::NONE));

	// Output: MAGIC(5) || IV(12) || ciphertext(dek_len) || TAG(16)
	string out;
	out.resize(MAGIC_SIZE + IV_SIZE + raw_dek.size() + TAG_SIZE);
	memcpy(&out[0], MAGIC, MAGIC_SIZE);

	auto iv = data_ptr_cast(&out[MAGIC_SIZE]);
	auto ct = iv + IV_SIZE;
	auto tag = ct + raw_dek.size();

	aes->GenerateRandomData(iv, IV_SIZE);
	EncryptionNonce enc_nonce(EncryptionTypes::GCM);
	memcpy(enc_nonce.data(), iv, IV_SIZE);
	aes->InitializeEncryption(enc_nonce, const_data_ptr_cast(kek.data()));
	auto written = aes->Process(const_data_ptr_cast(raw_dek.data()), raw_dek.size(), ct, raw_dek.size());
	if (written != raw_dek.size()) {
		throw InternalException("DuckLake key wrap: AES-GCM wrote %d bytes, expected %d", written, raw_dek.size());
	}
	aes->Finalize(ct + written, 0, tag, TAG_SIZE);
	return out;
}

string DuckLakeKeyWrap::Unwrap(EncryptionUtil &util, const string &kek, const string &maybe_wrapped) {
	if (!IsWrapped(maybe_wrapped)) {
		return maybe_wrapped;
	}
	if (kek.empty()) {
		throw InvalidInputException(
		    "Encrypted catalog uses key wrapping — provide KEY_ENCRYPTION_KEY at ATTACH time");
	}
	if (maybe_wrapped.size() < MAGIC_SIZE + IV_SIZE + TAG_SIZE + 1) {
		throw InvalidInputException("DuckLake wrapped key is malformed");
	}
	auto dek_len = maybe_wrapped.size() - MAGIC_SIZE - IV_SIZE - TAG_SIZE;
	auto iv = const_data_ptr_cast(&maybe_wrapped[MAGIC_SIZE]);
	auto ct = iv + IV_SIZE;
	auto tag = ct + dek_len;

	auto aes = util.CreateEncryptionState(
	    make_uniq<EncryptionStateMetadata>(EncryptionTypes::GCM, KEK_SIZE, EncryptionTypes::NONE));
	EncryptionNonce dec_nonce(EncryptionTypes::GCM);
	memcpy(dec_nonce.data(), iv, IV_SIZE);
	aes->InitializeDecryption(dec_nonce, const_data_ptr_cast(kek.data()));

	string dek;
	dek.resize(dek_len);
	auto written = aes->Process(ct, dek_len, data_ptr_cast(&dek[0]), dek_len);
	if (written != dek_len) {
		throw InternalException("DuckLake key unwrap: AES-GCM wrote %d bytes, expected %d", written, dek_len);
	}
	string tag_copy(const_char_ptr_cast(tag), TAG_SIZE);
	try {
		aes->Finalize(data_ptr_cast(&dek[0]) + written, 0, data_ptr_cast(&tag_copy[0]), TAG_SIZE);
	} catch (std::exception &) {
		throw InvalidInputException("KEY_ENCRYPTION_KEY is incorrect — decryption failed (wrong key or corrupted data)");
	}
	return dek;
}

} // namespace duckdb
