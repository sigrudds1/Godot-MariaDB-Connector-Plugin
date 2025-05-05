/*************************************************************************/
/*  argon2_hasher.hpp                                                    */
/*************************************************************************/
/*                     This file is part of the                          */
/*                      MariaDBConnector addon                           */
/*                    for use in the Godot Engine                        */
/*                           GODOT ENGINE                                */
/*                      https://godotengine.org                          */
/*************************************************************************/
/* Copyright (c) 2021-2025 Shawn Shipton. https://vikingtinkerer.com     */
/*                                                                       */
/* Permission is hereby granted, free of charge, to any person obtaining */
/* a copy of this software and associated documentation files (the       */
/* "Software"), to deal in the Software without restriction, including   */
/* without limitation the rights to use, copy, modify, merge, publish,   */
/* distribute, sublicense, and/or sell copies of the Software, and to    */
/* permit persons to whom the Software is furnished to do so, subject to */
/* the following conditions:                                             */
/*                                                                       */
/* The above copyright notice and this permission notice shall be        */
/* included in all copies or substantial portions of the Software.       */
/*                                                                       */
/* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,       */
/* EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF    */
/* MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.*/
/* IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY  */
/* CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,  */
/* TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE     */
/* SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.                */
/*************************************************************************/
#pragma once

#include <godot_cpp/classes/ref_counted.hpp>
#include <godot_cpp/core/class_db.hpp>

using namespace godot;

class Argon2Hasher : public RefCounted {
	GDCLASS(Argon2Hasher, RefCounted);

private:
	uint32_t _time_cost = 2;
	uint32_t _memory_cost = 1 << 16;  // 64 MiB
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
