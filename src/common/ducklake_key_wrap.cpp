#include "common/ducklake_key_wrap.hpp"

#include "duckdb/common/types/blob.hpp"
#include "duckdb/common/exception.hpp"
#include "duckdb/common/string_util.hpp"
#include "duckdb/common/crypto/md5.hpp"
#include "mbedtls_wrapper.hpp"

namespace duckdb {

string DuckLakeKeyWrap::DeriveKEK(const string &passphrase) {
	if (passphrase.empty()) {
		throw InvalidInputException("KEY_ENCRYPTION_KEY must not be empty");
	}
	// 64 hex chars = a raw 256-bit key supplied directly (e.g. from a KMS data key)
	if (passphrase.size() == KEK_SIZE * 2 &&
	    std::all_of(passphrase.begin(), passphrase.end(), [](char c) { return std::isxdigit(c) != 0; })) {
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

bool DuckLakeKeyWrap::IsWrapped(const string &stored) {
	return StringUtil::StartsWith(stored, PREFIX);
}

string DuckLakeKeyWrap::Encode(EncryptionUtil &util, const string &kek, const string &dek) {
	if (kek.empty()) {
		return Blob::ToBase64(string_t(dek));
	}
	if (kek.size() != KEK_SIZE) {
		throw InternalException("DuckLake KEK must be %d bytes", KEK_SIZE);
	}
	auto aes = util.CreateEncryptionState(EncryptionTypes::GCM, KEK_SIZE);
	// iv || ciphertext || tag
	string out;
	out.resize(IV_SIZE + dek.size() + TAG_SIZE);
	auto iv = data_ptr_cast(&out[0]);
	auto ct = iv + IV_SIZE;
	auto tag = ct + dek.size();
	aes->GenerateRandomData(iv, IV_SIZE);
	aes->InitializeEncryption(iv, IV_SIZE, const_data_ptr_cast(kek.data()), KEK_SIZE, nullptr, 0);
	auto written = aes->Process(const_data_ptr_cast(dek.data()), dek.size(), ct, dek.size());
	if (written != dek.size()) {
		throw InternalException("DuckLake key wrap: AES-GCM wrote %d bytes, expected %d", written, dek.size());
	}
	aes->Finalize(ct + written, 0, tag, TAG_SIZE);
	return string(PREFIX) + Blob::ToBase64(string_t(out));
}

string DuckLakeKeyWrap::Decode(EncryptionUtil &util, const string &kek, const string &stored) {
	if (!IsWrapped(stored)) {
		// legacy: raw base64 DEK
		return Blob::FromBase64(string_t(stored));
	}
	if (kek.empty()) {
		throw InvalidInputException(
		    "DuckLake data file keys in this catalog are wrapped - attach with KEY_ENCRYPTION_KEY to read them");
	}
	auto blob = Blob::FromBase64(string_t(stored.substr(strlen(PREFIX))));
	if (blob.size() < IV_SIZE + TAG_SIZE + 1) {
		throw InvalidInputException("DuckLake wrapped key is malformed");
	}
	auto dek_len = blob.size() - IV_SIZE - TAG_SIZE;
	auto iv = const_data_ptr_cast(blob.data());
	auto ct = iv + IV_SIZE;
	auto tag = ct + dek_len;
	auto aes = util.CreateEncryptionState(EncryptionTypes::GCM, KEK_SIZE);
	aes->InitializeDecryption(iv, IV_SIZE, const_data_ptr_cast(kek.data()), KEK_SIZE, nullptr, 0);
	string dek;
	dek.resize(dek_len);
	auto written = aes->Process(ct, dek_len, data_ptr_cast(&dek[0]), dek_len);
	if (written != dek_len) {
		throw InternalException("DuckLake key unwrap: AES-GCM wrote %d bytes, expected %d", written, dek_len);
	}
	// Finalize verifies the GCM tag and throws on mismatch (wrong KEK or tampered catalog)
	string tag_copy(const_char_ptr_cast(tag), TAG_SIZE);
	try {
		aes->Finalize(data_ptr_cast(&dek[0]) + written, 0, data_ptr_cast(&tag_copy[0]), TAG_SIZE);
	} catch (std::exception &) {
		throw InvalidInputException("DuckLake key unwrap failed: wrong KEY_ENCRYPTION_KEY or corrupt catalog entry");
	}
	return dek;
}

} // namespace duckdb
