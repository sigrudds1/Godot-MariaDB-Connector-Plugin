// argon2_hasher.hpp
#pragma once

#include <godot_cpp/classes/ref_counted.hpp>
#include <godot_cpp/core/class_db.hpp>

using namespace godot;

class Argon2Hasher : public RefCounted {
    GDCLASS(Argon2Hasher, RefCounted);

private:
    uint32_t _time_cost = 2;
    uint32_t _memory_cost = 1 << 16; // 64 MiB
    uint32_t _parallelism = 1;
    uint32_t _salt_length = 16;

public:
    static void _bind_methods();

    void set_time_cost(uint32_t cost);
    void set_memory_cost(uint32_t mem);
    void set_parallelism(uint32_t threads);
    void set_salt_length(uint32_t len);

    String generate_b64_salt();
    String hash_password_with_salt(String password, String base64_salt);
    bool verify_password_with_salt(String password, String base64_salt, String base64_hash);

	Argon2Hasher();
	~Argon2Hasher();

private:
	PackedByteArray _secure_random_bytes(int size);

};
