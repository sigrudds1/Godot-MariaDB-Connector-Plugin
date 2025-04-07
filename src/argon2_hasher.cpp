// argon2_hasher.cpp
#include "argon2_hasher.hpp"
#include "argon2/argon2.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"

#include <godot_cpp/classes/global_constants.hpp>
#include <godot_cpp/classes/marshalls.hpp>
#include <godot_cpp/core/memory.hpp>
#include <godot_cpp/variant/packed_byte_array.hpp>
#include <godot_cpp/variant/string.hpp>
#include <godot_cpp/variant/utility_functions.hpp>

#include <cstdlib>
#include <cstring>

void Argon2Hasher::_bind_methods()
{
	ClassDB::bind_method(D_METHOD("set_time_cost", "iterations"), &Argon2Hasher::set_time_cost);
	ClassDB::bind_method(D_METHOD("set_memory_cost", "memory_kib"), &Argon2Hasher::set_memory_cost);
	ClassDB::bind_method(D_METHOD("set_parallelism", "threads"), &Argon2Hasher::set_parallelism);
	ClassDB::bind_method(D_METHOD("set_salt_length", "bytes"), &Argon2Hasher::set_salt_length);

	ClassDB::bind_method(D_METHOD("generate_b64_salt"), &Argon2Hasher::generate_b64_salt);
	ClassDB::bind_method(D_METHOD("hash_password_with_salt", "password", "base64_salt"), &Argon2Hasher::hash_password_with_salt);
	ClassDB::bind_method(D_METHOD("verify_password_with_salt", "password", "base64_salt", "base64_hash"), &Argon2Hasher::verify_password_with_salt);
}

Argon2Hasher::Argon2Hasher(){

}Argon2Hasher::~Argon2Hasher(){

}

void Argon2Hasher::set_time_cost(uint32_t cost) { _time_cost = cost; }
void Argon2Hasher::set_memory_cost(uint32_t mem) { _memory_cost = mem; }
void Argon2Hasher::set_parallelism(uint32_t threads) { _parallelism = threads; }
void Argon2Hasher::set_salt_length(uint32_t bytes) { _salt_length = bytes; }

String Argon2Hasher::generate_b64_salt() {
	PackedByteArray salt = _secure_random_bytes(_salt_length);
	return Marshalls::get_singleton()->raw_to_base64(salt);
}

String Argon2Hasher::hash_password_with_salt(String p_password, String p_base64_salt) {
	PackedByteArray salt = Marshalls::get_singleton()->base64_to_raw(p_base64_salt);
	std::string pwd = p_password.utf8().get_data();

	uint8_t hash[32];
	char encoded[128] = {0};

	int result = argon2_hash(
		_time_cost,
		_memory_cost,
		_parallelism,
		static_cast<const void *>(pwd.c_str()), pwd.length(),
		static_cast<const void *>(salt.ptr()), salt.size(),
		static_cast<void *>(hash), sizeof(hash),
		nullptr, 0,
		Argon2_id,
		ARGON2_VERSION_NUMBER // or just 0x13
	);

	if (result != ARGON2_OK)
	{
		UtilityFunctions::printerr("Argon2 hash failed: ", argon2_error_message(result));
		return "";
	}

	PackedByteArray hash_array;
	hash_array.resize(sizeof(hash));
	memcpy(hash_array.ptrw(), hash, sizeof(hash));
	return Marshalls::get_singleton()->raw_to_base64(hash_array);
}

bool Argon2Hasher::verify_password_with_salt(String p_password, String p_base64_salt, String p_base64_hash) {
	PackedByteArray salt = Marshalls::get_singleton()->base64_to_raw(p_base64_salt);
	PackedByteArray stored_hash = Marshalls::get_singleton()->base64_to_raw(p_base64_hash);
	std::string pwd = p_password.utf8().get_data();

	uint8_t computed_hash[32];

	int result = argon2_hash(
		_time_cost,
		_memory_cost,
		_parallelism,
		pwd.c_str(), pwd.length(),
		salt.ptr(), salt.size(),
		computed_hash, sizeof(computed_hash),
		nullptr, 0,
		Argon2_id,
		ARGON2_VERSION_NUMBER);

	if (result != ARGON2_OK) {
		UtilityFunctions::printerr("Argon2 verify hash failed: ", argon2_error_message(result));
		return false;
	}

	return stored_hash.size() == sizeof(computed_hash) &&
		   memcmp(stored_hash.ptr(), computed_hash, sizeof(computed_hash)) == 0;
}

PackedByteArray Argon2Hasher::_secure_random_bytes(int p_size) {
	PackedByteArray salt;
	salt.resize(p_size);

	mbedtls_entropy_context entropy;
	mbedtls_ctr_drbg_context ctr_drbg;

	const char *pers = "argon2_hasher_salt"; // addon specific custom extra entropy
	mbedtls_entropy_init(&entropy);
	mbedtls_ctr_drbg_init(&ctr_drbg);

	int res = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char *)pers, strlen(pers));
	if (res == 0) {
		mbedtls_ctr_drbg_random(&ctr_drbg, salt.ptrw(), p_size);
	}

	mbedtls_ctr_drbg_free(&ctr_drbg);
	mbedtls_entropy_free(&entropy);

	return salt;
}
