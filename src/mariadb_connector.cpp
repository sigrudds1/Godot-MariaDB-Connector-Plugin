/*************************************************************************/
/*  mariadb.cpp                                                          */
/*************************************************************************/
/*                     This file is part of the                          */
/*                     MariaDB connection module                         */
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

#include "mariadb_connector.hpp"
#include "ed25519_ref10/ed25519_auth.h"
#include "mariadb_conversions.hpp"
#include "mbedtls/sha1.h"
#include "mbedtls/sha512.h"

#include <godot_cpp/classes/marshalls.hpp>
#include <godot_cpp/classes/os.hpp>
#include <godot_cpp/classes/time.hpp>
#include <godot_cpp/core/memory.hpp>
#include <godot_cpp/variant/utility_functions.hpp>

using namespace godot;

static inline PackedByteArray _sha1(const PackedByteArray &p_data) {
	PackedByteArray output;
	output.resize(20);

	mbedtls_sha1_context ctx;
	mbedtls_sha1_init(&ctx);
	mbedtls_sha1_starts(&ctx);
	mbedtls_sha1_update(&ctx, p_data.ptr(), p_data.size());
	mbedtls_sha1_finish(&ctx, output.ptrw());
	mbedtls_sha1_free(&ctx);

	return output;
}

MariaDBConnector::MariaDBConnector() { _stream.instantiate(); }

MariaDBConnector::~MariaDBConnector() { disconnect_db(); }

// Bind all your methods used in this class
void MariaDBConnector::_bind_methods() {
	ClassDB::bind_method(
			D_METHOD("connect_db", "hostname", "port", "database", "username", "password", "authtype", "is_prehashed"),
			&MariaDBConnector::connect_db, DEFVAL(AUTH_TYPE_ED25519), DEFVAL(true));
	ClassDB::bind_method(D_METHOD("connect_db_ctx", "mariadb_connect_context"), &MariaDBConnector::connect_db_ctx);
	ClassDB::bind_method(D_METHOD("disconnect_db"), &MariaDBConnector::disconnect_db);
	ClassDB::bind_method(D_METHOD("execute_command", "sql_stmt"), &MariaDBConnector::excecute_command);

	ClassDB::bind_method(D_METHOD("get_last_query_converted"), &MariaDBConnector::get_last_query_converted);
	ClassDB::bind_method(D_METHOD("get_last_response"), &MariaDBConnector::get_last_response);
	ClassDB::bind_method(D_METHOD("get_last_transmitted"), &MariaDBConnector::get_last_transmitted);
	ClassDB::bind_method(D_METHOD("get_last_error"), &MariaDBConnector::get_last_error);
	ClassDB::bind_method(D_METHOD("get_last_error_code"), &MariaDBConnector::get_last_error);

	ClassDB::bind_method(D_METHOD("is_connected_db"), &MariaDBConnector::is_connected_db);

	ClassDB::bind_method(D_METHOD("select_query", "sql_stmt"), &MariaDBConnector::select_query);
	ClassDB::bind_method(D_METHOD("query", "sql_stmt"), &MariaDBConnector::query);

	ClassDB::bind_method(D_METHOD("set_dbl_to_string", "is_to_str"), &MariaDBConnector::set_dbl_to_string);
	ClassDB::bind_method(D_METHOD("set_db_name", "db_name"), &MariaDBConnector::set_db_name);
	ClassDB::bind_method(D_METHOD("set_ip_type", "type"), &MariaDBConnector::set_ip_type);
	ClassDB::bind_method(D_METHOD("set_server_timeout", "msec"), &MariaDBConnector::set_server_timeout, DEFVAL(1000));

	ADD_PROPERTY(PropertyInfo(Variant::INT, "is_connected_db"), "", "is_connected_db");
	ADD_PROPERTY(PropertyInfo(Variant::INT, "last_error"), "", "get_last_error_code");

	BIND_ENUM_CONSTANT(IP_TYPE_IPV4);
	BIND_ENUM_CONSTANT(IP_TYPE_IPV6);
	BIND_ENUM_CONSTANT(IP_TYPE_ANY);

	BIND_ENUM_CONSTANT(AUTH_TYPE_ED25519);
	BIND_ENUM_CONSTANT(AUTH_TYPE_MYSQL_NATIVE);

	BIND_ENUM_CONSTANT(OK);
	BIND_ENUM_CONSTANT(ERR_NO_RESPONSE);
	BIND_ENUM_CONSTANT(ERR_NOT_CONNECTED);
	BIND_ENUM_CONSTANT(ERR_PACKET_LENGTH_MISMATCH);
	BIND_ENUM_CONSTANT(ERR_SERVER_PROTOCOL_INCOMPATIBLE);
	BIND_ENUM_CONSTANT(ERR_CLIENT_PROTOCOL_INCOMPATIBLE);
	BIND_ENUM_CONSTANT(ERR_SEQUENCE_MISMATCH);
	BIND_ENUM_CONSTANT(ERR_AUTH_PLUGIN_NOT_SET);
	BIND_ENUM_CONSTANT(ERR_AUTH_PLUGIN_INCOMPATIBLE);
	BIND_ENUM_CONSTANT(ERR_AUTH_FAILED);
	BIND_ENUM_CONSTANT(ERR_USERNAME_EMPTY);
	BIND_ENUM_CONSTANT(ERR_PASSWORD_EMPTY);
	BIND_ENUM_CONSTANT(ERR_DB_NAME_EMPTY);
	BIND_ENUM_CONSTANT(ERR_PASSWORD_HASH_LENGTH);
	BIND_ENUM_CONSTANT(ERR_INVALID_HOSTNAME);
	BIND_ENUM_CONSTANT(ERR_CONNECTION_ERROR);
	BIND_ENUM_CONSTANT(ERR_INIT_ERROR);
	BIND_ENUM_CONSTANT(ERR_UNAVAILABLE);
	BIND_ENUM_CONSTANT(ERR_PROTOCOL_MISMATCH);
	BIND_ENUM_CONSTANT(ERR_AUTH_PROTOCOL_MISMATCH);
	BIND_ENUM_CONSTANT(ERR_SEND_FAILED);
	BIND_ENUM_CONSTANT(ERR_INVALID_PORT);
	BIND_ENUM_CONSTANT(ERR_UNKNOWN);
	BIND_ENUM_CONSTANT(ERR_PACKET);
}

// Custom Functions
// private
void MariaDBConnector::m_add_packet_header(PackedByteArray &p_pkt, uint8_t p_pkt_seq) {
	PackedByteArray t = little_endian_to_vbytes(p_pkt.size(), 3);
	t.push_back(p_pkt_seq);
	t.append_array(p_pkt);
	p_pkt = t.duplicate();
}

MariaDBConnector::ErrorCode MariaDBConnector::_rcv_bfr_chk(
		PackedByteArray &p_bfr, int &p_bfr_size, const size_t p_cur_pos, const size_t p_bytes_needed) {
	if (p_bfr_size - p_cur_pos < p_bytes_needed)
		p_bfr.append_array(m_recv_data(_server_timout_msec));
	// m_append_thread_data(p_bfr);

	p_bfr_size = p_bfr.size();
	if (p_bfr_size - p_cur_pos < p_bytes_needed) {
		return MariaDBConnector::ErrorCode::ERR_PACKET_LENGTH_MISMATCH;
	} else {
		return MariaDBConnector::ErrorCode::OK;
	}
}

// client protocol 4.1
MariaDBConnector::ErrorCode MariaDBConnector::m_client_protocol_v41(
		const AuthType p_srvr_auth_type, const PackedByteArray p_srvr_salt) {
	PackedByteArray srvr_response_pba;
	PackedByteArray srvr_auth_msg_pba;
	uint8_t seq_num = 0;
	AuthType user_auth_type = AUTH_TYPE_ED25519;

	// Per https://mariadb.com/kb/en/connection/#handshake-response-packet
	// int<4> client capabilities
	_client_capabilities = 0;
	_client_capabilities |= (_server_capabilities & (uint64_t)Capabilities::CLIENT_MYSQL);
	// client_capabilities |= (uint64_t)Capabilities::FOUND_ROWS;
	_client_capabilities |= (uint64_t)Capabilities::LONG_FLAG; //??
	_client_capabilities |= (_server_capabilities & (uint64_t)Capabilities::CONNECT_WITH_DB);
	_client_capabilities |= (uint64_t)Capabilities::LOCAL_FILES;
	_client_capabilities |= (uint64_t)Capabilities::CLIENT_PROTOCOL_41;
	_client_capabilities |= (uint64_t)Capabilities::CLIENT_INTERACTIVE;
	_client_capabilities |= (uint64_t)Capabilities::SECURE_CONNECTION;

	// Not listed in MariaDB docs but if not set it won't parse the stream
	// correctly
	_client_capabilities |= (uint64_t)Capabilities::RESERVED2;

	_client_capabilities |= (uint64_t)Capabilities::MULTI_STATEMENTS;
	_client_capabilities |= (uint64_t)Capabilities::MULTI_RESULTS;
	_client_capabilities |= (uint64_t)Capabilities::PS_MULTI_RESULTS;
	_client_capabilities |= (uint64_t)Capabilities::PLUGIN_AUTH;

	// Don't think this is needed for game dev needs, maybe for prepared
	// statements? _client_capabilities |= (_server_capabilities &
	// (uint64_t)Capabilities::CLIENT_SEND_CONNECT_ATTRS);

	_client_capabilities |= (uint64_t)Capabilities::CAN_HANDLE_EXPIRED_PASSWORDS; //??
	_client_capabilities |= (uint64_t)Capabilities::SESSION_TRACK;
	_client_capabilities |= (_server_capabilities & (uint64_t)Capabilities::CLIENT_DEPRECATE_EOF);
	_client_capabilities |= (uint64_t)Capabilities::REMEMBER_OPTIONS; //??

	// Only send the first 4 bytes(32 bits) of capabilities the remaining will be
	// sent later in another 4 byte
	PackedByteArray send_buffer_pba = little_endian_to_vbytes(_client_capabilities, 4);
	// printf("_client_cap %ld", _client_capabilities);

	// int<4> max packet size
	// temp_vec = little_endian_bytes((uint32_t)0x40000000, 4);
	// send_buffer_vec.insert(send_buffer_vec.end(), temp_vec.begin(),
	// temp_vec.end());
	send_buffer_pba.append_array(little_endian_to_vbytes((uint32_t)0x40000000, 4));

	// TODO Find Collation list, create enum and setter
	//  int<1> client character collation
	send_buffer_pba.push_back(33); // utf8_general_ci

	// string<19> reserved
	// send_buffer_vec.insert(send_buffer_vec.end(), 19, 0);
	PackedByteArray temp_pba;
	temp_pba.resize(19);
	temp_pba.fill(0);
	send_buffer_pba.append_array(temp_pba);

	if (!(_server_capabilities & (uint64_t)Capabilities::CLIENT_MYSQL) && _srvr_major_ver >= 10 &&
			_srvr_minor_ver >= 2) {
		// TODO implement Extended capabilities, if needed, this will result in more
		// data between _client_capabilities |= (_server_capabilities &
		// (uint64_t)Capabilities::MARIADB_CLIENT_PROGRESS); _client_capabilities |=
		// (_server_capabilities &
		// (uint64_t)Capabilities::MARIADB_CLIENT_COM_MULTI); _client_capabilities
		// |= (_server_capabilities &
		// (uint64_t)Capabilities::MARIADB_CLIENT_STMT_BULK_OPERATIONS);
		// _client_capabilities |= (_server_capabilities &
		// (uint64_t)Capabilities::MARIADB_CLIENT_EXTENDED_TYPE_INFO);

		// we need the metadata in the stream so we can form the dictionary ??
		_client_capabilities |= (_server_capabilities & (uint64_t)Capabilities::MARIADB_CLIENT_CACHE_METADATA);
		// int<4> extended client capabilities
		temp_pba = little_endian_to_vbytes(_client_capabilities, 4, 4);
		send_buffer_pba.append_array(temp_pba);
	} else {
		// string<4> reserved
		temp_pba.resize(4);
		temp_pba.fill(0);
		send_buffer_pba.append_array(temp_pba);
	}

	// string<NUL> username
	send_buffer_pba.append_array(_username);
	send_buffer_pba.push_back(0); // NUL terminated

	PackedByteArray auth_response_pba;
	if (p_srvr_auth_type == AUTH_TYPE_MYSQL_NATIVE && (_client_auth_type == AUTH_TYPE_MYSQL_NATIVE)) {
		auth_response_pba = get_mysql_native_password_hash(_password_hashed, p_srvr_salt);
	}

	// if (server_capabilities & PLUGIN_AUTH_LENENC_CLIENT_DATA)
	// string<lenenc> authentication data
	// else if (server_capabilities & SECURE_CONNECTION) //mysql uses secure
	// connection flag for transactions
	if (!(_server_capabilities & (uint64_t)Capabilities::CLIENT_MYSQL) &&
			(_server_capabilities & (uint64_t)Capabilities::SECURE_CONNECTION)) {
		// int<1> length of authentication response
		send_buffer_pba.push_back((uint8_t)auth_response_pba.size());
		// string<fix> authentication response
		send_buffer_pba.append_array(auth_response_pba);
	} else {
		// else string<NUL> authentication response null ended
		send_buffer_pba.append_array(auth_response_pba);
		send_buffer_pba.push_back(0); // NUL terminated
	}

	// if (server_capabilities & CLIENT_CONNECT_WITH_DB)
	// string<NUL> default database name
	if (_client_capabilities & (uint64_t)Capabilities::CONNECT_WITH_DB) {
		send_buffer_pba.append_array(_dbname);
		send_buffer_pba.push_back(0); // NUL terminated
	}

	// if (server_capabilities & CLIENT_PLUGIN_AUTH)
	// string<NUL> authentication plugin name
	PackedByteArray auth_plugin_name_pba = kAuthTypeNames[(size_t)AUTH_TYPE_MYSQL_NATIVE].to_ascii_buffer();
	send_buffer_pba.append_array(auth_plugin_name_pba);
	send_buffer_pba.push_back(0); // NUL terminated

	// Implementing CLIENT_SEND_CONNECT_ATTRS will just add more data, I don't
	// think it is needed for game dev use if (server_capabilities &
	// CLIENT_SEND_CONNECT_ATTRS) int<lenenc> size of connection attributes while
	// packet has remaining data string<lenenc> key string<lenenc> value

	m_add_packet_header(send_buffer_pba, ++seq_num);
	_stream->put_data(send_buffer_pba);

	srvr_response_pba = m_recv_data(_server_timout_msec);
	size_t itr = 4;

	if (srvr_response_pba.size() > 0) {
		// 4th byte is seq should be 2
		seq_num = srvr_response_pba[3];
		// 5th byte is status
		uint8_t status = srvr_response_pba[itr];
		if (status == 0x00) {
			_authenticated = true;
			return ErrorCode::OK;
		} else if (status == 0xFE) {
			user_auth_type = m_get_server_auth_type(m_find_vbytes_str_at(srvr_response_pba, itr));
		} else if (status == 0xFF) {
			m_handle_server_error(srvr_response_pba, itr);
			_authenticated = false;
			return ErrorCode::ERR_AUTH_FAILED;
		} else {
			ERR_FAIL_V_EDMSG(ErrorCode::ERR_UNKNOWN,
					"Unhandled response code:" + String::num_uint64(srvr_response_pba[itr], 16, true));
		}
	}

	if (user_auth_type == AUTH_TYPE_ED25519 && _client_auth_type == AUTH_TYPE_ED25519) {
		// print_line(("using AUTH_TYPE_ED25519"));
		// srvr_auth_msg.assign(srvr_response.begin() + itr + 1,
		// srvr_response.end());
		srvr_auth_msg_pba.append_array(srvr_response_pba.slice(itr + 1));
		auth_response_pba = get_client_ed25519_signature(_password_hashed, srvr_auth_msg_pba);
		send_buffer_pba = auth_response_pba;
	} else {
		return ErrorCode::ERR_AUTH_PROTOCOL_MISMATCH;
	}

	m_add_packet_header(send_buffer_pba, ++seq_num);

	Error err = _stream->put_data(send_buffer_pba);
	if (err != Error::OK) {
		ERR_PRINT("Failed to put data!");
		return ErrorCode::ERR_SEND_FAILED;
	}

	srvr_response_pba = m_recv_data(_server_timout_msec);

	if (srvr_response_pba.size() > 0) {
		// 4th byte is seq should be 2
		seq_num = srvr_response_pba[3];
		// 5th byte is status
		itr = 4;
		if (srvr_response_pba[itr] == 0x00) {
			_authenticated = true;
		} else if (srvr_response_pba[itr] == 0xFF) {
			m_handle_server_error(srvr_response_pba, itr);
			_authenticated = false;
			return ErrorCode::ERR_AUTH_FAILED;
		} else {
			ERR_FAIL_V_MSG(ErrorCode::ERR_UNKNOWN,
					"Unhandled response code:" + String::num_uint64(srvr_response_pba[itr], 16, true));
		}
	}

	return ErrorCode::OK;
}

MariaDBConnector::ErrorCode MariaDBConnector::m_connect() {
	disconnect_db();

	ErrorCode err;

	Error godot_err = _stream->connect_to_host(_ip, _port);
	switch (godot_err) {
		case Error::OK:
			err = ErrorCode::OK;
			break;
		case Error::ERR_CANT_CONNECT:
		case Error::ERR_CONNECTION_ERROR:
			err = ErrorCode::ERR_CONNECTION_ERROR;
			break;
		case Error::ERR_CANT_RESOLVE:
			err = ErrorCode::ERR_INVALID_HOSTNAME;
			break;
		case Error::ERR_INVALID_PARAMETER:
		default:
			err = ErrorCode::ERR_INIT_ERROR;
			break;
	}

	if (err != ErrorCode::OK) {
		ERR_PRINT("Cannot connect to host with IP: " + String(_ip) + " and port: " + itos(_port));
		return err;
	}

	for (size_t i = 0; i < 1000; i++) {
		_stream->poll();
		if (_stream->get_status() == StreamPeerTCP::STATUS_CONNECTED) {
			break;
		} else {
			OS::get_singleton()->delay_usec(1000);
		}
	}

	if (_stream->get_status() != StreamPeerTCP::STATUS_CONNECTED) {
		ERR_PRINT("TCP connection not established after polling. IP: " + String(_ip) + " Port: " + itos(_port));
		return ErrorCode::ERR_CONNECTION_ERROR;
	}

	PackedByteArray recv_buffer = m_recv_data(_server_timout_msec);
	if (recv_buffer.size() <= 4) {
		ERR_PRINT("connect: Receive buffer empty!");
		return ErrorCode::ERR_UNAVAILABLE;
	}

	// per https://mariadb.com/kb/en/connection/
	// The first packet from the server on a connection is a greeting
	// giving/suggesting the requirements to login

	/* Per https://mariadb.com/kb/en/0-packet/
	 * On all packet stages between packet segment the standard packet is sent
	 * int<3> rcvd_bfr[0] to rcvd_bfr[2] First 3 bytes are packet length
	 * int<1> rcvd_bfr[3] 4th byte is sequence number
	 * byte<n> rcvd_bfr[4] to rcvd_bfr[4 + n] remaining bytes are the packet body
	 * n = packet length
	 */

	uint32_t packet_length =
			(uint32_t)recv_buffer[0] + ((uint32_t)recv_buffer[1] << 8) + ((uint32_t)recv_buffer[2] << 16);
	// On initial connect the packet length should be 4 byte less than buffer
	// length
	if (packet_length != ((uint32_t)recv_buffer.size() - 4)) {
		ERR_PRINT("Receive buffer does not match expected size!");
		return ErrorCode::ERR_PACKET_LENGTH_MISMATCH;
	}

	// 4th byte is sequence number, increment this when replying with login
	// request, if client starts then start at 0
	if (recv_buffer[3] != 0) {
		ERR_PRINT("Packet sequence error!");
		return ErrorCode::ERR_SEQUENCE_MISMATCH;
	}

	// From the 5th byte on is the packet body

	/* 5th byte is protocol version, currently only 10 for MariaDBConnector and
	 * MySQL v3.21.0+, protocol version 9 for older MySQL versions.
	 */

	if (recv_buffer[4] == 10) {
		m_server_init_handshake_v10(recv_buffer);
	} else {
		ERR_PRINT("Unsupported protocol version in handshake packet!");
		return ErrorCode::ERR_PROTOCOL_MISMATCH;
	}

	// Passing as lambda so external non-static members can be accessed
	// _tcp_thread = std::thread([this] { m_tcp_thread_func(); });

	return ErrorCode::OK;
} // m_connect

Variant MariaDBConnector::m_get_type_data(const int p_db_field_type, const PackedByteArray p_data) {
	String rtn_val;
	rtn_val.parse_utf8((const char *)p_data.ptr(), p_data.size());
	switch (p_db_field_type) {
		case 1: // MYSQL_TYPE_TINY
		case 2: // MYSQL_TYPE_SHORT aka SMALLINT
		case 3: // MYSQL_TYPE_LONG
		case 8: // MYSQL_TYPE_LONGLONG
		case 9: // MYSQL_TYPE_INT24 aka MEDIUMINT
		case 13: // MYSQL_TYPE_YEAR aka SMALLINT
			return rtn_val.to_int();
			break;
		case 0: // MYSQL_TYPE_DECIMAL
		case 4: // MYSQL_TYPE_FLOAT
			return rtn_val.to_float();
			break;
		case 5: // MYSQL_TYPE_DOUBLE
			if (_dbl_to_string) {
				return rtn_val;
			} else {
				return rtn_val.to_float();
			}
			break;
		default:
			return rtn_val;
	}
	return 0;
}

MariaDBConnector::AuthType MariaDBConnector::m_get_server_auth_type(String p_srvr_auth_name) {
	AuthType server_auth_type = AUTH_TYPE_ED25519;
	if (p_srvr_auth_name == "mysql_native_password") {
		server_auth_type = AUTH_TYPE_MYSQL_NATIVE;
	} else if (p_srvr_auth_name == "client_ed25519") {
		server_auth_type = AUTH_TYPE_ED25519;
	}
	// TODO(sigrudds1) Add cached_sha2 for mysql
	return server_auth_type;
}

PackedByteArray MariaDBConnector::m_recv_data(uint32_t p_timeout, uint32_t p_expected_bytes) {
	int32_t byte_cnt = 0;
	PackedByteArray out_buffer;
	uint64_t start_msec = Time::get_singleton()->get_ticks_msec();
	uint64_t time_lapse = 0;
	bool data_rcvd = false;
	// printf("start\n");
	while (is_connected_db() && time_lapse < p_timeout) {
		_stream->poll();
		byte_cnt = _stream->get_available_bytes();
		if (byte_cnt > 0) {
			out_buffer.append_array(_stream->get_data(byte_cnt)[1]);
			data_rcvd = (p_expected_bytes == 0 || out_buffer.size() >= p_expected_bytes);
		} else if (data_rcvd) {
			break;
		}
		time_lapse = Time::get_singleton()->get_ticks_msec() - start_msec;
	}

	return out_buffer;
}

void MariaDBConnector::m_handle_server_error(const PackedByteArray p_src_buffer, size_t &p_last_pos) {
	// REF https://mariadb.com/kb/en/err_packet/
	uint16_t srvr_error_code = (uint16_t)p_src_buffer[++p_last_pos];
	srvr_error_code += (uint16_t)p_src_buffer[++p_last_pos] << 8;
	String msg = String::num_uint64((uint64_t)srvr_error_code) + " - ";
	if (srvr_error_code == 0xFFFF) {
		// int<1> stage
		// int<1> max_stage
		// int<3> progress
		// string<lenenc> progress_info
	} else {
		if (p_src_buffer[p_last_pos + 1] == '#') {
			msg += "SQL State:";
			for (size_t itr = 0; itr < 6; ++itr)
				msg += (char)p_src_buffer[++p_last_pos];
			msg += " - ";
			while (p_last_pos < (size_t)p_src_buffer.size() - 1) {
				msg += (char)p_src_buffer[++p_last_pos];
			}
		} else {
			// string<EOF> human - readable error message
			while (p_last_pos < (size_t)p_src_buffer.size() - 1) {
				msg += (char)p_src_buffer[++p_last_pos];
			}
		}
	}
	ERR_FAIL_COND_EDMSG(srvr_error_code != OK, msg);
}

String MariaDBConnector::m_find_vbytes_str(PackedByteArray p_buf) {
	size_t start_pos = 0;
	return m_find_vbytes_str_at(p_buf, start_pos);
}

String MariaDBConnector::m_find_vbytes_str_at(PackedByteArray p_buf, size_t &p_start_pos) {
	String str;
	while (p_buf[++p_start_pos] != 0 && p_start_pos < (size_t)p_buf.size()) {
		str += p_buf[p_start_pos];
	}
	return str;
}

PackedByteArray MariaDBConnector::m_get_pkt_bytes(
		const PackedByteArray &p_src_buf, size_t &p_start_pos, const size_t p_byte_cnt) {
	PackedByteArray rtn;
	if (p_byte_cnt <= 0 || p_start_pos + p_byte_cnt > (size_t)p_src_buf.size()) {
		return rtn;
	}

	rtn = p_src_buf.slice(p_start_pos, p_start_pos + p_byte_cnt);
	p_start_pos += p_byte_cnt - 1;
	return rtn;
}

size_t MariaDBConnector::m_get_pkt_len_at(const PackedByteArray p_src_buf, size_t &p_start_pos) {
	size_t len = (size_t)p_src_buf[p_start_pos];
	len += (size_t)p_src_buf[++p_start_pos] << 8;
	len += (size_t)p_src_buf[++p_start_pos] << 16;
	return len;
}

MariaDBConnector::ErrorCode MariaDBConnector::m_server_init_handshake_v10(const PackedByteArray &p_src_buffer) {
	// nul string - read the 5th byte until the first nul(00), this is server
	// version string, it is nul terminated
	size_t pkt_itr = 3;
	_server_ver_str = "";
	while (p_src_buffer[++pkt_itr] != 0 && pkt_itr < (size_t)p_src_buffer.size()) {
		_server_ver_str += (char)p_src_buffer[pkt_itr];
	}

	_server_ver_str = _server_ver_str.strip_escapes();

	if (_server_ver_str.begins_with("5.5.5-")) {
		PackedStringArray split_ver_str = _server_ver_str.split("-");
		PackedStringArray split_ver_str_seg = split_ver_str[1].split(".");

		_srvr_major_ver = split_ver_str_seg[0].to_int();
		_srvr_minor_ver = split_ver_str_seg[1].to_int();
	}

	// 4bytes - doesn't appear to be needed.
	pkt_itr += 4;

	// salt part 1 - 8 bytes
	PackedByteArray server_salt;
	for (size_t j = 0; j < 8; j++)
		server_salt.push_back(p_src_buffer[++pkt_itr]);

	// reserved byte
	pkt_itr++;

	_server_capabilities = 0;
	// 2bytes -server capabilities part 1
	_server_capabilities = (uint64_t)p_src_buffer[++pkt_itr];
	_server_capabilities += ((uint64_t)p_src_buffer[++pkt_itr]) << 8;

	// 1byte - server default collation code
	++pkt_itr;

	// 2bytes - Status flags
	// uint16_t status = 0;
	// status = (uint16_t)p_src_buffer[++pkt_itr];
	// status += ((uint16_t)p_src_buffer[++pkt_itr]) << 8;
	pkt_itr += 2;

	// 2bytes - server capabilities part 2
	_server_capabilities += ((uint64_t)p_src_buffer[++pkt_itr]) << 16;
	_server_capabilities += ((uint64_t)p_src_buffer[++pkt_itr]) << 24;

	if (!(_server_capabilities & (uint64_t)Capabilities::CLIENT_PROTOCOL_41)) {
		ERR_FAIL_V_MSG(ErrorCode::ERR_AUTH_PROTOCOL_MISMATCH, "Incompatible authorization protocol!");
	}
	// TODO(sigrudds1) Make auth plugin not required if using ssl/tls
	if (!(_server_capabilities & (uint64_t)Capabilities::PLUGIN_AUTH)) {
		ERR_FAIL_V_MSG(ErrorCode::ERR_AUTH_PROTOCOL_MISMATCH, "Authorization protocol not set!");
	}

	// 1byte - salt length 0 for none
	uint8_t server_salt_length = p_src_buffer[++pkt_itr];

	// 6bytes - filler
	pkt_itr += 6;

	// 4bytes - filler or server capabilities part 3 (mariadb v10.2 or later)
	// "MariaDBConnector extended capablities"
	if (!(_server_capabilities & (uint64_t)Capabilities::CLIENT_MYSQL) && _srvr_major_ver >= 10 &&
			_srvr_minor_ver >= 2) {
		_server_capabilities += ((uint64_t)p_src_buffer[++pkt_itr]) << 32;
		_server_capabilities += ((uint64_t)p_src_buffer[++pkt_itr]) << 40;
		_server_capabilities += ((uint64_t)p_src_buffer[++pkt_itr]) << 48;
		_server_capabilities += ((uint64_t)p_src_buffer[++pkt_itr]) << 56;
	} else {
		pkt_itr += 4;
	}

	// 12bytes - salt part 2
	for (size_t j = 0; j < (size_t)std::max(13, server_salt_length - 8); j++)
		server_salt.push_back(p_src_buffer[++pkt_itr]);

	// 1byte - reserved
	// nul string - auth plugin name, length = auth plugin string length
	String tmp;
	while (p_src_buffer[++pkt_itr] != 0 && pkt_itr < (size_t)p_src_buffer.size()) {
		tmp += p_src_buffer[pkt_itr];
	}

	// determine which auth method the server can use
	AuthType p_srvr_auth_type = m_get_server_auth_type(tmp);

	return m_client_protocol_v41(p_srvr_auth_type, server_salt);
} // server_init_handshake_v10

void MariaDBConnector::m_hash_password(String p_password) {
	// Store password as a hash, only the hash is needed
	if (_client_auth_type == AUTH_TYPE_MYSQL_NATIVE) {
		_password_hashed = p_password.sha1_buffer();
	} else if (_client_auth_type == AUTH_TYPE_ED25519) {
		_password_hashed.resize(64);

		mbedtls_sha512_context ctx;
		mbedtls_sha512_init(&ctx);
		mbedtls_sha512_starts(&ctx, 0);
		mbedtls_sha512_update(&ctx, reinterpret_cast<const uint8_t *>(p_password.utf8().ptr()), p_password.length());
		mbedtls_sha512_finish(&ctx, _password_hashed.ptrw());
		mbedtls_sha512_free(&ctx);
	}
}

void MariaDBConnector::m_update_username(String p_username) { _username = p_username.to_utf8_buffer(); }

// public
MariaDBConnector::ErrorCode MariaDBConnector::connect_db(const String &p_host, const int p_port, const String &p_dbname,
		const String &p_username, const String &p_password, const AuthType p_authtype, const bool p_is_prehashed) {
	if (p_host.is_valid_ip_address()) {
		_ip = p_host;
	} else {
		_ip = IP::get_singleton()->resolve_hostname(p_host, (IP::Type)_ip_type);
	}

	if (!_ip.is_valid_ip_address()) {
		ERR_PRINT("Invalid hostname or IP address");
		return ErrorCode::ERR_INVALID_HOSTNAME;
	}

	if (p_port <= 0 || p_port > 65535) {
		ERR_PRINT("Invalid port");
		return ErrorCode::ERR_INVALID_PORT;
	}
	_port = p_port;

	if (p_dbname.length() <= 0 && _client_capabilities & (uint64_t)Capabilities::CONNECT_WITH_DB) {
		ERR_PRINT("dbname not set");
		return ErrorCode::ERR_DB_NAME_EMPTY;
	} else {
		set_db_name(p_dbname);
	}

	if (p_username.length() <= 0) {
		ERR_PRINT("username not set");
		return ErrorCode::ERR_USERNAME_EMPTY;
	}

	if (p_password.length() <= 0) {
		ERR_PRINT("password not set");
		return ErrorCode::ERR_PASSWORD_EMPTY;
	}

	if (p_is_prehashed) {
		if (p_authtype == AUTH_TYPE_MYSQL_NATIVE) {
			if (!is_valid_hex(p_password, 40)) {
				ERR_PRINT("Password not proper for MySQL Native prehash, must be 40 "
						  "hex characters!");
				return ErrorCode::ERR_PASSWORD_HASH_LENGTH;
			}
		} else if (p_authtype == AUTH_TYPE_ED25519) {
			if (!is_valid_hex(p_password, 128)) {
				ERR_PRINT("Password not proper for ED25519, must be 128 hex characters!");
				return ErrorCode::ERR_PASSWORD_HASH_LENGTH;
			}
		}
		_password_hashed = hex_str_to_bytes(p_password);
	} else {
		m_hash_password(p_password);
	}

	m_update_username(p_username);

	_client_auth_type = p_authtype;
	return m_connect();
}

MariaDBConnector::ErrorCode MariaDBConnector::connect_db_ctx(const Ref<MariaDBConnectContext> &p_context) {
	if (p_context.is_null()) {
		ERR_PRINT("ConnectionContext is null.");
		return ErrorCode::ERR_INIT_ERROR;
	}

	const int encoding = p_context->get_encoding();
	String password = p_context->get_password();
	const bool is_prehashed = p_context->get_is_prehashed();

	if (encoding == MariaDBConnectContext::ENCODE_BASE64) {
		// BASE64 should always be treated as binary -> hex
		password = Marshalls::get_singleton()->base64_to_raw(password).hex_encode();
	} else if (is_prehashed) {
		if (encoding == MariaDBConnectContext::ENCODE_PLAIN) {
			// convert plain to hex
			password = password.to_utf8_buffer().hex_encode();
		}
		// Just pass hex
	}
	// hex decode is dangerous, just pass the unmodified string if hex or plain

	return connect_db(p_context->get_hostname(), p_context->get_port(), p_context->get_db_name(),
			p_context->get_username(), password, static_cast<MariaDBConnector::AuthType>(p_context->get_auth_type()),
			is_prehashed);
}

void MariaDBConnector::disconnect_db() {
	// _tcp_polling = false;
	if (is_connected_db()) {
		// say goodbye too the server
		//  uint8_t output[5] = {0x01, 0x00, 0x00, 0x00, 0x01};
		String str = "0100000001";
		_stream->put_data(str.hex_decode());
		_stream->disconnect_from_host();
	}
	_authenticated = false;
}

Dictionary MariaDBConnector::excecute_command(const String &p_sql_stmt) { return _query(p_sql_stmt, true); }

PackedByteArray MariaDBConnector::get_last_query_converted() { return _last_query_converted; }

PackedByteArray MariaDBConnector::get_last_response() { return _last_response; }

PackedByteArray MariaDBConnector::get_last_transmitted() { return _last_transmitted; }

PackedByteArray MariaDBConnector::get_client_ed25519_signature(
		const PackedByteArray &p_sha512_hashed_passwd, const PackedByteArray &p_svr_msg) {
	// MySQL does not supprt this auth method
	PackedByteArray rtn_val;
	rtn_val.resize(64);
	ed25519_sign_msg(p_sha512_hashed_passwd.ptr(), p_svr_msg.ptr(), 32, rtn_val.ptrw());
	return rtn_val;
}

PackedByteArray MariaDBConnector::get_mysql_native_password_hash(
		const PackedByteArray &p_sha1_hashed_passwd, const PackedByteArray &p_srvr_salt) {
	// Per https://mariadb.com/kb/en/connection/#mysql_native_password-plugin
	// Both MariaDB and MySQL support this authentication method

	// First SHA1 Hashing
	PackedByteArray hash = _sha1(p_sha1_hashed_passwd);
	// Combine server salt and hash
	PackedByteArray combined_salt_pwd;
	combined_salt_pwd.resize(40); // 20-byte salt + 20-byte hash

	for (int i = 0; i < 20; i++) {
		combined_salt_pwd.set(i, p_srvr_salt[i]); // First 20 bytes: salt
		combined_salt_pwd.set(i + 20, hash[i]); // Next 20 bytes: hashed password
	}

	// Second SHA1 Hashing
	PackedByteArray final_hash = _sha1(combined_salt_pwd);
	// XOR original password hash with final hash
	PackedByteArray hash_out;
	hash_out.resize(20);

	for (int i = 0; i < 20; i++) {
		hash_out.set(i, p_sha1_hashed_passwd[i] ^ final_hash[i]);
	}

	return hash_out;
}

bool MariaDBConnector::is_connected_db() {
	_stream->poll();
	return _stream->get_status() == StreamPeerTCP::STATUS_CONNECTED;
}

TypedArray<Dictionary> MariaDBConnector::select_query(const String &p_sql_stmt) {
	TypedArray<Dictionary> result;
	Variant query_result = _query(p_sql_stmt);

	if (query_result.get_type() == Variant::INT) {
		// Not a valid SELECT response, INSERT, DELETE, UPDATE or error
		return result;
	}

	Array raw_array = query_result;
	for (int i = 0; i < raw_array.size(); i++) {
		if (raw_array[i].get_type() == Variant::DICTIONARY) {
			result.push_back(raw_array[i]);
		}
	}

	return result;
}

Variant MariaDBConnector::_query(const String &p_sql_stmt, const bool p_is_command) {
	_last_error = ErrorCode::OK;
	if (!is_connected_db()) {
		_last_error = ErrorCode::ERR_NOT_CONNECTED;
		if (p_is_command) {
			return 0;
		} else {
			return ERR_NOT_CONNECTED;
		}
	}
	if (!_authenticated) {
		_last_error = ErrorCode::ERR_NOT_CONNECTED;
		if (p_is_command) {
			return 0;
		} else {
			return (uint32_t)ErrorCode::ERR_AUTH_FAILED;
		}
	}
	// _tcp_polling = true;

	PackedByteArray send_buffer_vec;
	int bfr_size = 0;

	/* For interest of speed over memory I am working with the entire buffer
	 * and keeping track of the iteration point, as most queries for
	 * game dev should be small but speedy.
	 */

	size_t pkt_itr = 0;
	size_t pkt_len; // techinically section length everything arrives in one
					// stream packet
	size_t len_encode = 0;
	bool done = false;
	// From MariaDBConnector version 10.2 dep_eof should be true
	bool dep_eof = (_client_capabilities & (uint64_t)Capabilities::CLIENT_DEPRECATE_EOF);

	send_buffer_vec.push_back(0x03);
	_last_query_converted = p_sql_stmt.to_utf8_buffer();

	send_buffer_vec.append_array(_last_query_converted);
	m_add_packet_header(send_buffer_vec, 0);

	_last_transmitted = send_buffer_vec;
	// _tcp_mutex.lock();
	_stream->put_data(send_buffer_vec);
	// _tcp_mutex.unlock();

	PackedByteArray srvr_response = m_recv_data(_server_timout_msec);
	// m_append_thread_data(srvr_response);

	if (srvr_response.size() == 0) {
		_last_error = ErrorCode::ERR_NO_RESPONSE;
		if (p_is_command) {
			return 0;
		} else {
			return (uint32_t)ErrorCode::ERR_NO_RESPONSE;
		}
	}

	// Not doing anything with this value, here, because the buffer may have been
	// full and more data is needed. So I am using the process time to allow more
	// to get into the buffer, instead of constantly polling the buffer
	//	before any work is done, there are more and smaller internal packets
	// with buffer size checks for every 	sub-packet.
	pkt_len = m_get_pkt_len_at(srvr_response, pkt_itr);

	// uint8_t seq_num = srvr_response[++pkt_itr];
	++pkt_itr;

	/* https://mariadb.com/kb/en/result-set-packets/
	 * The pkt_itr should be at 3, we are on the 4th byte and wlll iterate before
	 * use Resultset metadata All segment packets start with packet length(3
	 * bytes) and sequence number This is a small packet with packet length of 1
	 * to 9 of 4 to 19 bytes to determine how many columns of data are being sent.
	 */

	uint64_t col_cnt = 0;
	uint8_t test = srvr_response[++pkt_itr];
	// print_line("Column Count Test Byte:" + String::num_int64(test, 16));
	// https://mariadb.com/kb/en/protocol-data-types/#length-encoded-integers
	if (test == 0xFF) {
		m_handle_server_error(srvr_response, pkt_itr);
		_last_error = ErrorCode::ERR_PACKET;

		if (p_is_command) {
			return 0;
		} else {
			return (uint32_t)_last_error;
		}
	} else if (test == 0xFE) {
		col_cnt = bytes_to_num_itr_pos<uint64_t>(srvr_response.ptr(), 8, pkt_itr);
	} else if (test == 0xFD) {
		col_cnt = bytes_to_num_itr_pos<uint64_t>(srvr_response.ptr(), 3, pkt_itr);
	} else if (test == 0xFC) {
		col_cnt = bytes_to_num_itr_pos<uint64_t>(srvr_response.ptr(), 2, pkt_itr);
	} else if (test == 0xFB) {
		// null value
		// TODO needs investigation, not sure why this would happen
	} else if (test == 0x00) {
		if (p_is_command) {
			Dictionary result;

			// Affected rows
			uint64_t affected_rows = 0;
			uint8_t marker = srvr_response[++pkt_itr];

			if (marker < 0xFB) {
				affected_rows = marker;
			} else if (marker == 0xFC) {
				affected_rows = bytes_to_num_itr_pos<uint64_t>(srvr_response.ptr(), 2, pkt_itr);
			} else if (marker == 0xFD) {
				affected_rows = bytes_to_num_itr_pos<uint64_t>(srvr_response.ptr(), 3, pkt_itr);
			} else if (marker == 0xFE) {
				affected_rows = bytes_to_num_itr_pos<uint64_t>(srvr_response.ptr(), 8, pkt_itr);
			}

			// Last insert ID
			uint64_t last_insert_id = 0;
			marker = srvr_response[++pkt_itr];

			if (marker < 0xFB) {
				last_insert_id = marker;
			} else if (marker == 0xFC) {
				last_insert_id = bytes_to_num_itr_pos<uint64_t>(srvr_response.ptr(), 2, pkt_itr);
			} else if (marker == 0xFD) {
				last_insert_id = bytes_to_num_itr_pos<uint64_t>(srvr_response.ptr(), 3, pkt_itr);
			} else if (marker == 0xFE) {
				last_insert_id = bytes_to_num_itr_pos<uint64_t>(srvr_response.ptr(), 8, pkt_itr);
			}

			// Status flags and warnings
			uint16_t status_flags = srvr_response[++pkt_itr] | (srvr_response[++pkt_itr] << 8);
			uint16_t warnings = srvr_response[++pkt_itr] | (srvr_response[++pkt_itr] << 8);

			// Info message
			String info_message = "";
			if (pkt_itr + 1 < srvr_response.size()) {
				info_message =
						String::utf8((const char *)&srvr_response[pkt_itr + 1], srvr_response.size() - (pkt_itr + 1));
			}

			// Build dictionary
			result["affected_rows"] = affected_rows;
			result["last_insert_id"] = last_insert_id;
			result["status_flags"] = status_flags;
			result["warnings"] = warnings;
			result["info"] = info_message;

			return result;
		}
		return 0;
	} else {
		col_cnt = srvr_response[pkt_itr];
	}

	if (_client_capabilities & (uint64_t)Capabilities::MARIADB_CLIENT_CACHE_METADATA) {
		++pkt_itr;
	}

	Array col_data;
	//	for each column (i.e column_count times)
	for (size_t itr = 0; itr < col_cnt; ++itr) {
		_last_error = _rcv_bfr_chk(srvr_response, bfr_size, pkt_itr, 24);
		ERR_FAIL_COND_V_EDMSG(_last_error != OK, _last_error,
				vformat("ERR_PACKET_LENGTH_MISMATCH rcvd %d expect %d", bfr_size, pkt_itr + 24));

		pkt_len = m_get_pkt_len_at(srvr_response, ++pkt_itr);
		if (_rcv_bfr_chk(srvr_response, bfr_size, pkt_itr, pkt_len) != OK) {
			srvr_response.append_array(m_recv_data(_server_timout_msec, pkt_len));
		}

		// seq_num = srvr_response[++pkt_itr];
		++pkt_itr;

		//	Column Definition packet
		// https://mariadb.com/kb/en/result-set-packets/#column-definition-packet

		//	string<lenenc> catalog (always 'def')
		len_encode = srvr_response[++pkt_itr];
		vbytes_to_utf8_itr_at(srvr_response, pkt_itr, len_encode);

		//	string<lenenc> schema (database name)
		len_encode = srvr_response[++pkt_itr];
		_last_error = _rcv_bfr_chk(srvr_response, bfr_size, pkt_itr, len_encode);
		ERR_FAIL_COND_V_EDMSG(_last_error != OK, _last_error,
				vformat("ERR_PACKET_LENGTH_MISMATCH rcvd %d expect %d", bfr_size, pkt_itr + len_encode));
		vbytes_to_utf8_itr_at(srvr_response, pkt_itr, len_encode);

		//	string<lenenc> table alias
		len_encode = srvr_response[++pkt_itr];

		_last_error = _rcv_bfr_chk(srvr_response, bfr_size, pkt_itr, len_encode);
		ERR_FAIL_COND_V_EDMSG(_last_error != OK, _last_error,
				vformat("ERR_PACKET_LENGTH_MISMATCH rcvd %d expect %d", bfr_size, pkt_itr + len_encode));

		vbytes_to_utf8_itr_at(srvr_response, pkt_itr, len_encode);

		//	string<lenenc> table
		len_encode = srvr_response[++pkt_itr];

		_last_error = _rcv_bfr_chk(srvr_response, bfr_size, pkt_itr, len_encode);
		ERR_FAIL_COND_V_EDMSG(_last_error != OK, _last_error,
				vformat("ERR_PACKET_LENGTH_MISMATCH rcvd %d expect %d", bfr_size, pkt_itr + len_encode));

		vbytes_to_utf8_itr_at(srvr_response, pkt_itr, len_encode);

		//	string<lenenc> column alias
		len_encode = srvr_response[++pkt_itr];

		_last_error = _rcv_bfr_chk(srvr_response, bfr_size, pkt_itr, len_encode);
		ERR_FAIL_COND_V_EDMSG(_last_error != OK, _last_error,
				vformat("ERR_PACKET_LENGTH_MISMATCH rcvd %d expect %d", bfr_size, pkt_itr + len_encode));

		String column_name = vbytes_to_utf8_itr_at(srvr_response, pkt_itr, len_encode);

		//	string<lenenc> column
		len_encode = srvr_response[++pkt_itr];

		_last_error = _rcv_bfr_chk(srvr_response, bfr_size, pkt_itr, len_encode);
		ERR_FAIL_COND_V_EDMSG(_last_error != OK, _last_error,
				vformat("ERR_PACKET_LENGTH_MISMATCH rcvd %d expect %d", bfr_size, pkt_itr + len_encode));

		vbytes_to_utf8_itr_at(srvr_response, pkt_itr, len_encode);

		// TODO(sigrudds1) Handle "MariaDBConnector extended capablities" (several
		// locations)
		//		if extended type supported (see
		// MARIADB_CLIENT_EXTENDED_TYPE_INFO ) 			int<lenenc>
		// length extended info 			loop
		// int<1> data type: 0x00:type, 0x01: format string<lenenc> value

		//	int<lenenc> length of fixed fields (=0xC)
		uint8_t remaining = srvr_response[++pkt_itr];

		_last_error = _rcv_bfr_chk(srvr_response, bfr_size, pkt_itr, remaining);
		ERR_FAIL_COND_V_EDMSG(_last_error != OK, _last_error,
				vformat("ERR_PACKET_LENGTH_MISMATCH rcvd %d expect %d", bfr_size, pkt_itr + remaining));

		// ++pkt_itr; //remaining bytes in packet section

		//	int<2> character set number
		uint16_t char_set = bytes_to_num_itr_pos<uint16_t>(srvr_response.ptr(), 2, pkt_itr);

		// int<4> max. column size the number in parenthesis eg int(10),
		// varchar(255) uint32_t col_size =
		// bytes_to_num_itr<uint32_t>(srvr_response.data(), 4, pkt_itr);
		pkt_itr += 4;

		//	int<1> Field types
		// https://mariadb.com/kb/en/result-set-packets/#field-types
		uint8_t field_type = srvr_response[++pkt_itr];

		//	int<2> Field detail flag
		// https://mariadb.com/kb/en/result-set-packets/#field-details-flag
		pkt_itr += 2;

		//	int<1> decimals
		pkt_itr += 1;
		//	int<2> - unused -
		pkt_itr += 2;
		Dictionary column_data;
		column_data["name"] = column_name;
		column_data["char_set"] = char_set;
		column_data["field_type"] = field_type;

		col_data.push_back(column_data);
	}

	//	if not (CLIENT_DEPRECATE_EOF capability set) get EOF_Packet
	if (!dep_eof) {
		pkt_itr += 5; // bypass for now
	}

	// String dict_string = Variant(col_data).stringify();
	// print_line("Dictionary: " + dict_string);

	Array arr;

	// process values
	while (!done && pkt_itr < (size_t)srvr_response.size()) {
		// Last packet is always 11 bytes, pkt len code = 3 bytes, seq = 1 byte, pkt
		// data = 7 bytes
		_last_error = _rcv_bfr_chk(srvr_response, bfr_size, pkt_itr, 11);
		ERR_FAIL_COND_V_EDMSG(_last_error != OK, _last_error,
				vformat("ERR_PACKET_LENGTH_MISMATCH rcvd %d expect %d", bfr_size, pkt_itr + 11));

		pkt_len = m_get_pkt_len_at(srvr_response, ++pkt_itr);

		_last_error = _rcv_bfr_chk(srvr_response, bfr_size, pkt_itr, pkt_len);
		ERR_FAIL_COND_V_EDMSG(_last_error != OK, _last_error,
				vformat("ERR_PACKET_LENGTH_MISMATCH rcvd %d expect %d", bfr_size, pkt_itr + pkt_len));

		// seq_num = srvr_response[++pkt_itr];
		++pkt_itr;
		test = srvr_response[pkt_itr + 1];

		if (test == 0xFE && dep_eof && pkt_len < 0xFFFFFF) {
			done = true;
			break;
		}
		Dictionary dict;
		// https://mariadb.com/kb/en/protocol-data-types/#length-encoded-strings
		for (size_t itr = 0; itr < col_cnt; ++itr) {
			_last_error = _rcv_bfr_chk(srvr_response, bfr_size, pkt_itr, 2);
			ERR_FAIL_COND_V_EDMSG(_last_error != OK, _last_error,
					vformat("ERR_PACKET_LENGTH_MISMATCH rcvd %d expect %d", bfr_size, pkt_itr + 2));

			test = srvr_response[++pkt_itr];
			if (test == 0xFF) {
				// ERR_Packet
				//  Don't think these two if's are needed for column data
				//  } else if ((test == 0x00 && !dep_eof /* && pkt_len < 0xFFFFFF */) ||
				//  		(test == 0xFE && pkt_len < 0xFFFFFF && dep_eof)) {
				//  	//OK_Packet
				//  	done = true;
				//  	break;
				//  } else if (test == 0xFE && pkt_len < 0xFFFFFF && !dep_eof) {
				//  	//EOF_Packet
				//  	done = true;
				//  	break;
			} else {
				if (test == 0xFE) {
					_last_error = _rcv_bfr_chk(srvr_response, bfr_size, pkt_itr, 8);
					ERR_FAIL_COND_V_EDMSG(_last_error != OK, _last_error,
							vformat("ERR_PACKET_LENGTH_MISMATCH rcvd %d expect %d", bfr_size, pkt_itr + 8));
					len_encode = bytes_to_num_itr_pos<uint64_t>(srvr_response.ptr(), 8, pkt_itr);
				} else if (test == 0xFD) {
					_last_error = _rcv_bfr_chk(srvr_response, bfr_size, pkt_itr, 3);
					ERR_FAIL_COND_V_EDMSG(_last_error != OK, _last_error,
							vformat("ERR_PACKET_LENGTH_MISMATCH rcvd %d expect %d", bfr_size, pkt_itr + 3));
					len_encode = bytes_to_num_itr_pos<uint64_t>(srvr_response.ptr(), 3, pkt_itr);
				} else if (test == 0xFC) {
					len_encode = bytes_to_num_itr_pos<uint64_t>(srvr_response.ptr(), 2, pkt_itr);
				} else if (test == 0xFB) {
					// null value need to skip
					len_encode = 0;
				} else {
					len_encode = srvr_response[pkt_itr];
				}

				_last_error = _rcv_bfr_chk(srvr_response, bfr_size, pkt_itr, len_encode);
				ERR_FAIL_COND_V_EDMSG(_last_error != OK, _last_error,
						vformat("ERR_PACKET_LENGTH_MISMATCH rcvd %d expect %d", bfr_size, pkt_itr + len_encode));

				// print_line("len_encode:" + String::num_int64(len_encode));
				bool valid = false;

				// NOTE when accessing Dictionaries in C++ you must assign the value to
				// the expected type or you get undefined and erratic  behavior
				String field_name = String(col_data[itr].get("name", &valid));
				ERR_FAIL_COND_V_EDMSG(!valid, Variant(), vformat("ERROR: 'name' key is missing at index %d", itr));

				if (len_encode > 0) {
					PackedByteArray data = m_get_pkt_bytes(srvr_response, ++pkt_itr, len_encode);
					// ✅ Convert Variant to int64_t before passing it to
					// m_get_type_data()
					valid = false;
					int64_t field_type = int64_t(col_data[itr].get("field_type", &valid));

					if (!valid) {
						// print_line("ERROR: 'field_type' key is missing at index " +
						// String::num_int64(itr));
						dict[field_name] = Variant(); // Store empty if missing
					} else {
						dict[field_name] = m_get_type_data(field_type, data);
					}
				} else {
					dict[field_name] = Variant();
				}
			}
		}

		if (!done)
			arr.push_back(dict);
	}
	// _tcp_polling = false;
	_last_response = PackedByteArray(srvr_response);

	return Variant(arr);
}

void MariaDBConnector::set_dbl_to_string(bool p_is_to_str) { _dbl_to_string = p_is_to_str; }

// TODO If db is not the same and connected then change db on server
void MariaDBConnector::set_db_name(String p_dbname) {
	_dbname = p_dbname.to_utf8_buffer();
	// _dbname = p_dbname.to_ascii_buffer(); // TODO Add character set
	// compatibility??
}

void MariaDBConnector::set_ip_type(IpType p_type) { _ip_type = p_type; }
