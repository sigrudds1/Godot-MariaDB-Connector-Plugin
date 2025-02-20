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
#include "mariadb_conversions.hpp"
#include "mbedtls/sha512.h"
#include "ed25519_ref10/ed25519_auth.h"

#include <godot_cpp/core/memory.hpp>
#include <godot_cpp/classes/time.hpp>
#include <godot_cpp/classes/os.hpp>
#include <godot_cpp/variant/utility_functions.hpp>


// #include <godot_cpp/variant/utility_functions.hpp>


using namespace godot;

MariaDBConnector::MariaDBConnector() {
	_stream.instantiate();
}

MariaDBConnector::~MariaDBConnector() {
	disconnect_db();
	// _tcp_polling = false;
	// _running = false;

	// if (_tcp_thread.joinable())
	// 	_tcp_thread.join();
}

//Bind all your methods used in this class
void MariaDBConnector::_bind_methods() {
	ClassDB::bind_method(D_METHOD("connect_db", "hostname", "port", "database", "username", "password", "authtype",
			"is_prehashed"), &MariaDBConnector::connect_db, DEFVAL(AUTH_TYPE_ED25519), DEFVAL(true));
	ClassDB::bind_method(D_METHOD("disconnect_db"), &MariaDBConnector::disconnect_db);
	ClassDB::bind_method(D_METHOD("get_last_query"), &MariaDBConnector::get_last_query);
	ClassDB::bind_method(D_METHOD("get_last_query_converted"), &MariaDBConnector::get_last_query_converted);
	ClassDB::bind_method(D_METHOD("get_last_response"), &MariaDBConnector::get_last_response);
	ClassDB::bind_method(D_METHOD("get_last_transmitted"), &MariaDBConnector::get_last_transmitted);
	ClassDB::bind_method(D_METHOD("is_connected_db"), &MariaDBConnector::is_connected_db);
	ClassDB::bind_method(D_METHOD("set_dbl_to_string", "is_to_str"), &MariaDBConnector::set_dbl_to_string);
	ClassDB::bind_method(D_METHOD("set_db_name", "db_name"), &MariaDBConnector::set_db_name);
	ClassDB::bind_method(D_METHOD("query", "sql_stmt"), &MariaDBConnector::query);

	BIND_ENUM_CONSTANT(IP_TYPE_IPV4);
	BIND_ENUM_CONSTANT(IP_TYPE_IPV6);
	BIND_ENUM_CONSTANT(IP_TYPE_ANY);

	BIND_ENUM_CONSTANT(AUTH_TYPE_MYSQL_NATIVE);
	BIND_ENUM_CONSTANT(AUTH_TYPE_ED25519);
}

//Custom Functions
//private
void MariaDBConnector::m_add_packet_header(PackedByteArray &p_pkt, uint8_t p_pkt_seq) {
	PackedByteArray t = little_endian_to_vbytes(p_pkt.size(), 3);
	t.push_back(p_pkt_seq);
	t.append_array(p_pkt);
	p_pkt = t.duplicate();
}

// void MariaDBConnector::m_append_thread_data(PackedByteArray &p_data, const uint64_t p_timeout) {
// 	int sz = 0;
// 	uint64_t start = Time::get_singleton()->get_ticks_msec();
// 	while (sz == 0 && Time::get_singleton()->get_ticks_msec() - start <= p_timeout) {
// 		_tcp_mutex.lock();
// 		sz = _tcp_thread_data.size();
// 		if (sz > 0) {
// 			p_data.append_array(_tcp_thread_data);
// 			_tcp_thread_data.clear();
// 		}
// 		_tcp_mutex.unlock();
// 		if (sz == 0) {
// 			OS::get_singleton()->delay_usec(1000);
// 		}
// 	}
// }

uint32_t MariaDBConnector::m_chk_rcv_bfr(
		PackedByteArray &p_bfr,
		int &p_bfr_size,
		const size_t p_cur_pos,
		const size_t p_need) {
	if (p_bfr_size - p_cur_pos < p_need)
		p_bfr.append_array(m_recv_data(1000));
		// m_append_thread_data(p_bfr);

	p_bfr_size = p_bfr.size();
	if (p_bfr_size - p_cur_pos < p_need) {
		return (uint32_t)ERR_PACKET_LENGTH_MISMATCH;
	} else {
		return (uint32_t)OK;
	}
}

//client protocol 4.1
Error MariaDBConnector::m_client_protocol_v41(const AuthType p_srvr_auth_type, const PackedByteArray p_srvr_salt) {
	PackedByteArray srvr_response;
	PackedByteArray srvr_auth_msg;
	uint8_t seq_num = 0;
	AuthType user_auth_type = AUTH_TYPE_ED25519;

	//Per https://mariadb.com/kb/en/connection/#handshake-response-packet
	//int<4> client capabilities
	_client_capabilities = 0;
	_client_capabilities |= (_server_capabilities & (uint64_t)Capabilities::CLIENT_MYSQL);
	//client_capabilities |= (uint64_t)Capabilities::FOUND_ROWS;
	_client_capabilities |= (uint64_t)Capabilities::LONG_FLAG; //??
	_client_capabilities |= (_server_capabilities & (uint64_t)Capabilities::CONNECT_WITH_DB);
	_client_capabilities |= (uint64_t)Capabilities::LOCAL_FILES;
	_client_capabilities |= (uint64_t)Capabilities::CLIENT_PROTOCOL_41;
	_client_capabilities |= (uint64_t)Capabilities::CLIENT_INTERACTIVE;
	_client_capabilities |= (uint64_t)Capabilities::SECURE_CONNECTION;

	// Not listed in MariaDBConnector docs but if not set it won't parse the stream correctly
	_client_capabilities |= (uint64_t)Capabilities::RESERVED2;

	_client_capabilities |= (uint64_t)Capabilities::MULTI_STATEMENTS;
	_client_capabilities |= (uint64_t)Capabilities::MULTI_RESULTS;
	_client_capabilities |= (uint64_t)Capabilities::PS_MULTI_RESULTS;
	_client_capabilities |= (uint64_t)Capabilities::PLUGIN_AUTH;

	// Don't think this is needed for game dev needs, maybe for prepared statements?
	// _client_capabilities |= (_server_capabilities & (uint64_t)Capabilities::CLIENT_SEND_CONNECT_ATTRS);

	_client_capabilities |= (uint64_t)Capabilities::CAN_HANDLE_EXPIRED_PASSWORDS; //??
	_client_capabilities |= (uint64_t)Capabilities::SESSION_TRACK;
	_client_capabilities |= (_server_capabilities & (uint64_t)Capabilities::CLIENT_DEPRECATE_EOF);
	_client_capabilities |= (uint64_t)Capabilities::REMEMBER_OPTIONS; //??

	// Only send the first 4 bytes(32 bits) of capabilities the remaining will be sent later in another 4 byte
	PackedByteArray send_buffer_vec = little_endian_to_vbytes(_client_capabilities, 4);
	// printf("_client_cap %ld", _client_capabilities);

	// int<4> max packet size
	// temp_vec = little_endian_bytes((uint32_t)0x40000000, 4);
	// send_buffer_vec.insert(send_buffer_vec.end(), temp_vec.begin(), temp_vec.end());
	send_buffer_vec.append_array(little_endian_to_vbytes((uint32_t)0x40000000, 4));

	// int<1> client character collation
	send_buffer_vec.push_back(33); //utf8_general_ci

	// string<19> reserved
	// send_buffer_vec.insert(send_buffer_vec.end(), 19, 0);
	PackedByteArray temp_vec;
	temp_vec.resize(19);
	temp_vec.fill(0);
	send_buffer_vec.append_array(temp_vec);

	if (!(_server_capabilities & (uint64_t)Capabilities::CLIENT_MYSQL) && _srvr_major_ver >= 10 &&
			_srvr_minor_ver >= 2) {
		// TODO implement Extended capabilities, if needed, this will result in more data between
		// _client_capabilities |= (_server_capabilities & (uint64_t)Capabilities::MARIADB_CLIENT_PROGRESS);
		// _client_capabilities |= (_server_capabilities & (uint64_t)Capabilities::MARIADB_CLIENT_COM_MULTI);
		// _client_capabilities |= (_server_capabilities & (uint64_t)Capabilities::MARIADB_CLIENT_STMT_BULK_OPERATIONS);
		// _client_capabilities |= (_server_capabilities & (uint64_t)Capabilities::MARIADB_CLIENT_EXTENDED_TYPE_INFO);

		// we need the metadata in the stream so we can form the dictionary ??
		_client_capabilities |= (_server_capabilities & (uint64_t)Capabilities::MARIADB_CLIENT_CACHE_METADATA);
		// int<4> extended client capabilities
		temp_vec = little_endian_to_vbytes(_client_capabilities, 4, 4);
		send_buffer_vec.append_array(temp_vec);
	} else {
		// string<4> reserved
		temp_vec.resize(4);
		temp_vec.fill(0);
		send_buffer_vec.append_array(temp_vec);
	}

	// string<NUL> username
	//send_buffer_vec.insert(send_buffer_vec.end(), _username.begin(), _username.end());
	send_buffer_vec.append_array(_username);
	send_buffer_vec.push_back(0); //NUL terminated

	PackedByteArray auth_response;
	if (p_srvr_auth_type == AUTH_TYPE_MYSQL_NATIVE && (_client_auth_type == AUTH_TYPE_MYSQL_NATIVE))
		auth_response = get_mysql_native_password_hash(_password_hashed, p_srvr_salt);

	// if (server_capabilities & PLUGIN_AUTH_LENENC_CLIENT_DATA)
	// string<lenenc> authentication data
	// else if (server_capabilities & SECURE_CONNECTION) //mysql uses secure connection flag for transactions
	if (!(_server_capabilities & (uint64_t)Capabilities::CLIENT_MYSQL) &&
			(_server_capabilities & (uint64_t)Capabilities::SECURE_CONNECTION)) {
		//int<1> length of authentication response
		send_buffer_vec.push_back((uint8_t)auth_response.size());
		//string<fix> authentication response
		send_buffer_vec.append_array(auth_response);
	} else {
		//else string<NUL> authentication response null ended
		send_buffer_vec.append_array(auth_response);
		send_buffer_vec.push_back(0); //NUL terminated
	}

	// if (server_capabilities & CLIENT_CONNECT_WITH_DB)
	// string<NUL> default database name
	if (_client_capabilities & (uint64_t)Capabilities::CONNECT_WITH_DB) {
		send_buffer_vec.append_array(_dbname);
		send_buffer_vec.push_back(0); //NUL terminated
	}

	//if (server_capabilities & CLIENT_PLUGIN_AUTH)
	//string<NUL> authentication plugin name
	PackedByteArray auth_plugin_name = kAuthTypeNames[(size_t)AUTH_TYPE_MYSQL_NATIVE].to_ascii_buffer();
	send_buffer_vec.append_array(auth_plugin_name);
	send_buffer_vec.push_back(0); //NUL terminated

	// Implementing CLIENT_SEND_CONNECT_ATTRS will just add more data, I don't think it is needed for game dev use
	// if (server_capabilities & CLIENT_SEND_CONNECT_ATTRS)
	//int<lenenc> size of connection attributes
	//while packet has remaining data
	//string<lenenc> key
	//string<lenenc> value

	m_add_packet_header(send_buffer_vec, ++seq_num);
	_stream->put_data(send_buffer_vec);

	srvr_response = m_recv_data(1000);
	size_t itr = 4;

	if (srvr_response.size() > 0) {
		//4th byte is seq should be 2
		seq_num = srvr_response[3];
		//5th byte is status
		uint8_t status = srvr_response[itr];
		if (status == 0x00) {
			_authenticated = true;
			return Error::OK;
		} else if (status == 0xFE) {
			user_auth_type = m_get_server_auth_type(m_find_vbytes_str_at(srvr_response, itr));
		} else if (status == 0xFF) {
			m_handle_server_error(srvr_response, itr);
			_authenticated = false;
			return Error::ERR_UNAUTHORIZED;
		} else {
			ERR_FAIL_V_EDMSG(Error::ERR_BUG, "Unhandled response code:" + String::num_uint64(srvr_response[itr], 16, true));
		}
	}

	if (user_auth_type == AUTH_TYPE_ED25519 && _client_auth_type == AUTH_TYPE_ED25519) {
		//srvr_auth_msg.assign(srvr_response.begin() + itr + 1, srvr_response.end());
		srvr_auth_msg.append_array(srvr_response.slice(itr + 1));
		auth_response = get_client_ed25519_signature(_password_hashed, srvr_auth_msg);
		send_buffer_vec = auth_response;
	} else {
		return Error::ERR_INVALID_PARAMETER;
	}

	m_add_packet_header(send_buffer_vec, ++seq_num);

	Error err = _stream->put_data(send_buffer_vec);
	ERR_FAIL_COND_V_MSG(err != Error::OK, err, "Failed to put data!");

	srvr_response = m_recv_data(1000);

	if (srvr_response.size() > 0) {
		//4th byte is seq should be 2
		seq_num = srvr_response[3];
		//5th byte is status
		itr = 4;
		if (srvr_response[itr] == 0x00) {
			_authenticated = true;
		} else if (srvr_response[itr] == 0xFF) {
			m_handle_server_error(srvr_response, itr);
			_authenticated = false;
			return Error::ERR_UNAUTHORIZED;
		} else {
			ERR_FAIL_V_MSG(Error::ERR_BUG, "Unhandled response code:" + String::num_uint64(srvr_response[itr], 16, true));
		}
	}

	return Error::OK;
}

Error MariaDBConnector::m_connect() {

	disconnect_db();


	Error err;
	if (_ip.is_valid_ip_address() && _port > 0) {
		err = _stream->connect_to_host(_ip, _port);
	} else {
		err = Error::ERR_INVALID_PARAMETER;
	}

	ERR_FAIL_COND_V_MSG(err != Error::OK, err, "Cannot connect to host with IP: " + String(_ip) + " and port: " + itos(_port));

	for (size_t i = 0; i < 1000; i++) {
		_stream->poll();
		if (_stream->get_status() == StreamPeerTCP::STATUS_CONNECTED) {
			break;
		} else {
			OS::get_singleton()->delay_usec(1000);
		}
	}

	ERR_FAIL_COND_V_MSG(_stream->get_status() != StreamPeerTCP::STATUS_CONNECTED, Error::ERR_CONNECTION_ERROR,
			"Cannot connect to host with IP: " + String(_ip) + " and port: " + itos(_port));


	PackedByteArray recv_buffer = m_recv_data(250);
	if (recv_buffer.size() <= 4) {
		ERR_FAIL_V_MSG(Error::ERR_UNAVAILABLE, "connect: Recv buffer empty!");
	}

	// per https://mariadb.com/kb/en/connection/
	// The first packet from the server on a connection is a greeting giving/suggesting the requirements to login

	/* Per https://mariadb.com/kb/en/0-packet/
	 * On all packet stages between packet segment the standard packet is sent
	 * int<3> rcvd_bfr[0] to rcvd_bfr[2] First 3 bytes are packet length
	 * int<1> rcvd_bfr[3] 4th byte is sequence number
	 * byte<n> rcvd_bfr[4] to rcvd_bfr[4 + n] remaining bytes are the packet body n = packet length
	 */

	uint32_t packet_length = (uint32_t)recv_buffer[0] + ((uint32_t)recv_buffer[1] << 8) +
			((uint32_t)recv_buffer[2] << 16);
	// On initial connect the packet length should be 4 byte less than buffer length
	if (packet_length != ((uint32_t)recv_buffer.size() - 4)) {
		ERR_FAIL_V_MSG(Error::FAILED, "Recv bfr does not match expected size!");
	}

	// 4th byte is sequence number, increment this when replying with login request, if client starts then start at 0
	if (recv_buffer[3] != 0) {
		ERR_FAIL_V_MSG(Error::FAILED, "Packet sequence error!");
	}

	// From the 5th byte on is the packet body

	/* 5th byte is protocol version, currently only 10 for MariaDBConnector and MySQL v3.21.0+,
	 * protocol version 9 for older MySQL versions.
	 */
	if (recv_buffer[4] == 10) {
		m_server_init_handshake_v10(recv_buffer);
	} else {
		ERR_FAIL_V_MSG(Error::FAILED, "Protocol version incompatible!");
	}

	// Passing as lambda so external non-static members can be accessed
	// _tcp_thread = std::thread([this] { m_tcp_thread_func(); });

	return Error::OK;
} //m_connect

// void MariaDBConnector::m_tcp_thread_func() {
// 	int32_t byte_cnt = 0;
// 	PackedByteArray transfer_bfr;

// 	while (_running) {
// 		while (_tcp_polling) {
// 			if (!is_connected_db())
// 				continue;
// 			byte_cnt = _stream.get_available_bytes();
// 			if (byte_cnt > 0) {
// 				Array rcv_bfr = _stream.get_data(byte_cnt);
// 				transfer_bfr.append_array(rcv_bfr[1]);
// 			}

// 			if (transfer_bfr.size() > 0) {
// 				_tcp_mutex.lock();
// 				_tcp_thread_data.append_array(transfer_bfr);
// 				transfer_bfr.clear();
// 				_tcp_mutex.unlock();
// 			}
// 		}
// 		OS::get_singleton()->delay_usec(1000);
// 	}
// }

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
	//TODO(sigrudds1) Add cached_sha2 for mysql
	return server_auth_type;
}

PackedByteArray MariaDBConnector::m_recv_data(uint32_t p_timeout) {
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
			// Array recv_buffer = _stream.get_data(byte_cnt);
			data_rcvd = true;
			out_buffer.append_array(_stream->get_data(byte_cnt)[1]);
			start_msec = Time::get_singleton()->get_ticks_msec();
		} else if (data_rcvd) {
			break;
		}
		time_lapse = Time::get_singleton()->get_ticks_msec() - start_msec;
	}

	return out_buffer;
}

void MariaDBConnector::m_handle_server_error(const PackedByteArray p_src_buffer, size_t &p_last_pos) {
	//REF https://mariadb.com/kb/en/err_packet/
	uint16_t srvr_error_code = (uint16_t)p_src_buffer[++p_last_pos];
	srvr_error_code += (uint16_t)p_src_buffer[++p_last_pos] << 8;
	String msg = String::num_uint64((uint64_t)srvr_error_code) + " - ";
	if (srvr_error_code == 0xFFFF) {
		//int<1> stage
		//int<1> max_stage
		//int<3> progress
		//string<lenenc> progress_info
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
			//string<EOF> human - readable error message
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

PackedByteArray MariaDBConnector::m_get_pkt_bytes(const PackedByteArray &p_src_buf, size_t &p_start_pos,
		const size_t p_byte_cnt){
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

Error MariaDBConnector::m_server_init_handshake_v10(const PackedByteArray &p_src_buffer) {

	//nul string - read the 5th byte until the first nul(00), this is server version string, it is nul terminated
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

	//4bytes - doesn't appear to be needed.
	pkt_itr += 4;

	//salt part 1 - 8 bytes
	PackedByteArray server_salt;
	for (size_t j = 0; j < 8; j++)
		server_salt.push_back(p_src_buffer[++pkt_itr]);

	//reserved byte
	pkt_itr++;

	_server_capabilities = 0;
	//2bytes -server capabilities part 1
	_server_capabilities = (uint64_t)p_src_buffer[++pkt_itr];
	_server_capabilities += ((uint64_t)p_src_buffer[++pkt_itr]) << 8;

	//1byte - server default collation code
	++pkt_itr;

	//2bytes - Status flags
	//uint16_t status = 0;
	//status = (uint16_t)p_src_buffer[++pkt_itr];
	//status += ((uint16_t)p_src_buffer[++pkt_itr]) << 8;
	pkt_itr += 2;

	//2bytes - server capabilities part 2
	_server_capabilities += ((uint64_t)p_src_buffer[++pkt_itr]) << 16;
	_server_capabilities += ((uint64_t)p_src_buffer[++pkt_itr]) << 24;

	if (!(_server_capabilities & (uint64_t)Capabilities::CLIENT_PROTOCOL_41)) {
		ERR_FAIL_V_MSG(Error::FAILED, "Incompatible authorization protocol!");
	}
	//TODO(sigrudds1) Make auth plugin not required if using ssl/tls
	if (!(_server_capabilities & (uint64_t)Capabilities::PLUGIN_AUTH)) {
		ERR_FAIL_V_MSG(Error::FAILED, "Authorization protocol not set!");
	}

	//1byte - salt length 0 for none
	uint8_t server_salt_length = p_src_buffer[++pkt_itr];

	//6bytes - filler
	pkt_itr += 6;

	// 4bytes - filler or server capabilities part 3 (mariadb v10.2 or later) "MariaDBConnector extended capablities"
	if (!(_server_capabilities & (uint64_t)Capabilities::CLIENT_MYSQL) &&
			_srvr_major_ver >= 10 && _srvr_minor_ver >= 2) {
		_server_capabilities += ((uint64_t)p_src_buffer[++pkt_itr]) << 32;
		_server_capabilities += ((uint64_t)p_src_buffer[++pkt_itr]) << 40;
		_server_capabilities += ((uint64_t)p_src_buffer[++pkt_itr]) << 48;
		_server_capabilities += ((uint64_t)p_src_buffer[++pkt_itr]) << 56;
	} else {
		pkt_itr += 4;
	}

	//12bytes - salt part 2
	for (size_t j = 0; j < (size_t)std::max(13, server_salt_length - 8); j++)
		server_salt.push_back(p_src_buffer[++pkt_itr]);

	//1byte - reserved
	//nul string - auth plugin name, length = auth plugin string length
	String tmp;
	while (p_src_buffer[++pkt_itr] != 0 && pkt_itr < (size_t)p_src_buffer.size()) {
		tmp += p_src_buffer[pkt_itr];
	}

	//determine which auth method the server can use
	AuthType p_srvr_auth_type = m_get_server_auth_type(tmp);

	return m_client_protocol_v41(p_srvr_auth_type, server_salt);
} //server_init_handshake_v10

void MariaDBConnector::m_update_password(String p_password) {
	if (_is_pre_hashed)
		return;

	//take the password and store it as the hash, only the hash is needed
	if (_client_auth_type == AUTH_TYPE_MYSQL_NATIVE) {
		_password_hashed = p_password.sha1_buffer();
	} else if (_client_auth_type == AUTH_TYPE_ED25519) {
		_password_hashed.resize(64);
		void *ctx = memalloc(sizeof(mbedtls_sha512_context));
		mbedtls_sha512_init((mbedtls_sha512_context *)ctx);
		mbedtls_sha512_starts_ret((mbedtls_sha512_context *)ctx, 0);
		mbedtls_sha512_update_ret((mbedtls_sha512_context *)ctx, (uint8_t *)p_password.ascii().ptr(),
				p_password.length());
		mbedtls_sha512_finish_ret((mbedtls_sha512_context *)ctx, _password_hashed.ptrw());
		mbedtls_sha512_free((mbedtls_sha512_context *)ctx);
		memfree((mbedtls_sha512_context *)ctx);
	}
}

void MariaDBConnector::m_update_username(String p_username) {
	_username = p_username.to_ascii_buffer();
}

//public
Error MariaDBConnector::connect_db(
		String p_host,
		int p_port,
		String p_dbname,
		String p_username,
		String p_hashed_password,
		AuthType p_authtype,
		bool p_is_prehashed) {

	if (p_host.is_valid_ip_address())
	{
		_ip = p_host;
	}
	else
	{
		_ip = IP::get_singleton()->resolve_hostname(p_host, (IP::Type)_ip_type);
	}

	_port = p_port;
	// _tcp_polling = false;
	// _running = true;

	_client_auth_type = p_authtype;
	_is_pre_hashed = p_is_prehashed;

	if (p_username.length() <= 0) {
		ERR_PRINT("username not set");
		return Error::ERR_INVALID_PARAMETER;
	}

	if (p_hashed_password.length() <= 0) {
		ERR_PRINT("password not set");
		return Error::ERR_INVALID_PARAMETER;
	}

	if (p_dbname.length() <= 0 && _client_capabilities & (uint64_t)Capabilities::CONNECT_WITH_DB) {
		ERR_PRINT("dbname not set");
		return Error::ERR_INVALID_PARAMETER;
	} else {
		set_db_name(p_dbname);
	}

	m_update_username(p_username);

	if (p_is_prehashed) {
		_password_hashed = hex_str_to_v_bytes(p_hashed_password);
	} else {
		m_update_password(p_hashed_password);
	}

	return m_connect();
}

void MariaDBConnector::disconnect_db() {
	// _tcp_polling = false;
	if (is_connected_db()) {
		//say goodbye too the server
		// uint8_t output[5] = {0x01, 0x00, 0x00, 0x00, 0x01};
		String str = "0100000001";
		_stream->put_data(str.hex_decode());
		_stream->disconnect_from_host();
	}
	_authenticated = false;
}

String MariaDBConnector::get_last_query() {
	return _last_query;
}

PackedByteArray MariaDBConnector::get_last_query_converted() {
	return _last_query_converted;
}

PackedByteArray MariaDBConnector::get_last_response() {
	return _last_response;
}

PackedByteArray MariaDBConnector::get_last_transmitted() {
	return _last_transmitted;
}

PackedByteArray MariaDBConnector::get_client_ed25519_signature(const PackedByteArray p_sha512_hashed_passwd, const PackedByteArray p_svr_msg)
{
	//MySQL does not supprt this auth method
	PackedByteArray rtn_val;
	rtn_val.resize(64);
	ed25519_sign_msg(p_sha512_hashed_passwd.ptr(), p_svr_msg.ptr(), 32, rtn_val.ptrw());
	return rtn_val;
}

PackedByteArray MariaDBConnector::get_mysql_native_password_hash(PackedByteArray p_sha1_hashed_passwd, PackedByteArray p_srvr_salt) {
	//per https://mariadb.com/kb/en/connection/#mysql_native_password-plugin
	//Both MariaDB and MySQL support this auth method
	// uint8_t hash[20] = {};
	PackedByteArray hash = String((const char *)p_sha1_hashed_passwd.ptr()).sha1_buffer();
	// CryptoCore::sha1(p_sha1_hashed_passwd.ptr(), 20, hash);

	PackedByteArray combined_salt_pwd;
	combined_salt_pwd.resize(40);
	// uint8_t combined_salt_pwd[40] = {};
	for (size_t i = 0; i < 20; i++) {
		combined_salt_pwd[i] = p_srvr_salt[i];
		combined_salt_pwd[i + 20] = hash[i];
	}

	// CryptoCore::sha1((const uint8_t *)combined_salt_pwd, 40, hash);
	hash = String((const char *)combined_salt_pwd.ptr()).sha1_buffer();
	PackedByteArray hash_out;
	for (size_t i = 0; i < 20; i++) {
		hash_out.push_back(p_sha1_hashed_passwd[i] ^ hash[i]);
	}

	return hash_out;
}

bool MariaDBConnector::is_connected_db() {
	_stream->poll();
	return _stream->get_status() == StreamPeerTCP::STATUS_CONNECTED;
}

Variant MariaDBConnector::query(String sql_stmt) {
	if (!is_connected_db())
		return (uint32_t)ERR_NOT_CONNECTED;
	if (!_authenticated)
		return (uint32_t)ERR_AUTH_FAILED;

	// _tcp_polling = true;

	_last_query = sql_stmt;
	PackedByteArray send_buffer_vec;
	int bfr_size = 0;

	/* For interest of speed over memory I am working with the entire buffer
	 * and keeping track of the iteration point, as most queries for
	 * game dev should be small but speedy.
	 */

	size_t pkt_itr = 0;
	size_t pkt_len; //techinically section length everything arrives in one stream packet
	size_t len_encode = 0;
	bool done = false;
	// From MariaDBConnector version 10.2 dep_eof should be true
	bool dep_eof = (_client_capabilities & (uint64_t)Capabilities::CLIENT_DEPRECATE_EOF);

	send_buffer_vec.push_back(0x03);
	_last_query_converted = sql_stmt.to_utf8_buffer();

	send_buffer_vec.append_array(_last_query_converted);
	m_add_packet_header(send_buffer_vec, 0);

	_last_transmitted = send_buffer_vec;
	// _tcp_mutex.lock();
	_stream->put_data(send_buffer_vec);
	// _tcp_mutex.unlock();

	PackedByteArray srvr_response = m_recv_data(1000);
	// m_append_thread_data(srvr_response);
	bfr_size = srvr_response.size();

	if (bfr_size == 0) {
		return (uint32_t)ERR_NO_RESPONSE;
	}

	pkt_len = m_get_pkt_len_at(srvr_response, pkt_itr);

	// uint8_t seq_num = srvr_response[++pkt_itr];
	++pkt_itr;

	/* https://mariadb.com/kb/en/result-set-packets/
	 * The pkt_itr should be at 3, we are on teh 4th byte and wlll iterate before use
	 * Resultset metadata
	 * All segment packets start with packet length(3 bytes) and sequence number
	 * This is a small packet with packet length of 1 to 9 of 4 to 19 bytes
	 * to determine how many columns of data are being sent.
	 */

	uint64_t col_cnt = 0;
	uint8_t test = srvr_response[++pkt_itr];
	// https://mariadb.com/kb/en/protocol-data-types/#length-encoded-integers
	if (test == 0xFF) {
		int err = srvr_response[pkt_itr + 1] + (srvr_response[pkt_itr + 2] << 8);
		m_handle_server_error(srvr_response, pkt_itr);
		return err;
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
		ERR_FAIL_COND_V_EDMSG(m_chk_rcv_bfr(srvr_response, bfr_size, pkt_itr, 24) != OK, ERR_PACKET_LENGTH_MISMATCH,
				vformat("ERR_PACKET_LENGTH_MISMATCH rcvd %d expect %d", bfr_size, pkt_itr + 24));

		pkt_len = m_get_pkt_len_at(srvr_response, ++pkt_itr);

		// seq_num = srvr_response[++pkt_itr];
		++pkt_itr;

		//	Column Definition packet
		// https://mariadb.com/kb/en/result-set-packets/#column-definition-packet

		//	string<lenenc> catalog (always 'def')
		len_encode = srvr_response[++pkt_itr];
		vbytes_to_utf8_itr_at(srvr_response, pkt_itr, len_encode);

		//	string<lenenc> schema (database name)
		len_encode = srvr_response[++pkt_itr];
		ERR_FAIL_COND_V_EDMSG(m_chk_rcv_bfr(srvr_response, bfr_size, pkt_itr, len_encode) != OK, ERR_PACKET_LENGTH_MISMATCH,
				vformat("ERR_PACKET_LENGTH_MISMATCH rcvd %d expect %d", bfr_size, pkt_itr + len_encode));
		vbytes_to_utf8_itr_at(srvr_response, pkt_itr, len_encode);

		//	string<lenenc> table alias
		len_encode = srvr_response[++pkt_itr];
		ERR_FAIL_COND_V_EDMSG(m_chk_rcv_bfr(srvr_response, bfr_size, pkt_itr, len_encode) != OK, ERR_PACKET_LENGTH_MISMATCH,
				vformat("ERR_PACKET_LENGTH_MISMATCH rcvd %d expect %d", bfr_size, pkt_itr + len_encode));
		vbytes_to_utf8_itr_at(srvr_response, pkt_itr, len_encode);

		//	string<lenenc> table
		len_encode = srvr_response[++pkt_itr];
		ERR_FAIL_COND_V_EDMSG(m_chk_rcv_bfr(srvr_response, bfr_size, pkt_itr, len_encode) != OK, ERR_PACKET_LENGTH_MISMATCH,
				vformat("ERR_PACKET_LENGTH_MISMATCH rcvd %d expect %d", bfr_size, pkt_itr + len_encode));
		vbytes_to_utf8_itr_at(srvr_response, pkt_itr, len_encode);

		//	string<lenenc> column alias
		len_encode = srvr_response[++pkt_itr];
		ERR_FAIL_COND_V_EDMSG(m_chk_rcv_bfr(srvr_response, bfr_size, pkt_itr, len_encode) != OK, ERR_PACKET_LENGTH_MISMATCH,
				vformat("ERR_PACKET_LENGTH_MISMATCH rcvd %d expect %d", bfr_size, pkt_itr + len_encode));
		String column_name = vbytes_to_utf8_itr_at(srvr_response, pkt_itr, len_encode);

		//	string<lenenc> column
		len_encode = srvr_response[++pkt_itr];
		ERR_FAIL_COND_V_EDMSG(m_chk_rcv_bfr(srvr_response, bfr_size, pkt_itr, len_encode) != OK, ERR_PACKET_LENGTH_MISMATCH,
				vformat("ERR_PACKET_LENGTH_MISMATCH rcvd %d expect %d", bfr_size, pkt_itr + len_encode));
		vbytes_to_utf8_itr_at(srvr_response, pkt_itr, len_encode);

		// TODO(sigrudds1) Handle "MariaDBConnector extended capablities" (several locations)
		//		if extended type supported (see MARIADB_CLIENT_EXTENDED_TYPE_INFO )
		//			int<lenenc> length extended info
		//			loop
		//				int<1> data type: 0x00:type, 0x01: format
		//				string<lenenc> value

		//	int<lenenc> length of fixed fields (=0xC)
		uint8_t remaining = srvr_response[++pkt_itr];
		ERR_FAIL_COND_V_EDMSG(m_chk_rcv_bfr(srvr_response, bfr_size, pkt_itr, remaining) != OK, ERR_PACKET_LENGTH_MISMATCH,
				vformat("ERR_PACKET_LENGTH_MISMATCH rcvd %d expect %d", bfr_size, pkt_itr + remaining));
		// ++pkt_itr; //remaining bytes in packet section

		//	int<2> character set number
		uint16_t char_set = bytes_to_num_itr_pos<uint16_t>(srvr_response.ptr(), 2, pkt_itr);

		// int<4> max. column size the number in parenthesis eg int(10), varchar(255)
		// uint32_t col_size = bytes_to_num_itr<uint32_t>(srvr_response.data(), 4, pkt_itr);
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
		Dictionary data;
		data["name"] = column_name;
		data["char_set"] = char_set;
		data["field"] = field_type;
		col_data.push_back(data);
	}

	//	if not (CLIENT_DEPRECATE_EOF capability set) get EOF_Packet
	if (!dep_eof) {
		pkt_itr += 5; //bypass for now
	}

	Array arr;

	//process values
	while (!done && pkt_itr < (size_t)srvr_response.size()) {
		// Last packet is always 11 bytes, pkt len code = 3 bytes, seq = 1 byte, pkt data = 7 bytes
		ERR_FAIL_COND_V_EDMSG(m_chk_rcv_bfr(srvr_response, bfr_size, pkt_itr, 11) != OK, ERR_PACKET_LENGTH_MISMATCH,
				vformat("ERR_PACKET_LENGTH_MISMATCH rcvd %d expect %d", bfr_size, pkt_itr + 11));

		pkt_len = m_get_pkt_len_at(srvr_response, ++pkt_itr);
		ERR_FAIL_COND_V_EDMSG(m_chk_rcv_bfr(srvr_response, bfr_size, pkt_itr, pkt_len) != OK, ERR_PACKET_LENGTH_MISMATCH,
				vformat("ERR_PACKET_LENGTH_MISMATCH rcvd %d expect %d", bfr_size, pkt_itr + pkt_len));

		// seq_num = srvr_response[++pkt_itr];
		++pkt_itr;
		test = srvr_response[pkt_itr + 1];

		if (test == 0xFE && dep_eof && pkt_len < 0xFFFFFF) {
			done = true;
			break;
		}
		Dictionary dict;
		//https://mariadb.com/kb/en/protocol-data-types/#length-encoded-strings
		for (size_t itr = 0; itr < col_cnt; ++itr) {
			ERR_FAIL_COND_V_EDMSG(m_chk_rcv_bfr(srvr_response, bfr_size, pkt_itr, 2) != OK, ERR_PACKET_LENGTH_MISMATCH, vformat("ERR_PACKET_LENGTH_MISMATCH rcvd %d expect %d", bfr_size, pkt_itr + 2));
			test = srvr_response[++pkt_itr];
			if (test == 0xFF) {
				//ERR_Packet
				ERR_FAIL_COND_V_EDMSG(m_chk_rcv_bfr(srvr_response, bfr_size, pkt_itr, 2) != OK, ERR_PACKET_LENGTH_MISMATCH, vformat("ERR_PACKET_LENGTH_MISMATCH rcvd %d expect %d", bfr_size, pkt_itr + 2));
				// Don't think these two if's are needed for column data
				// } else if ((test == 0x00 && !dep_eof /* && pkt_len < 0xFFFFFF */) ||
				// 		(test == 0xFE && pkt_len < 0xFFFFFF && dep_eof)) {
				// 	//OK_Packet
				// 	done = true;
				// 	break;
				// } else if (test == 0xFE && pkt_len < 0xFFFFFF && !dep_eof) {
				// 	//EOF_Packet
				// 	done = true;
				// 	break;
			} else {
				if (test == 0xFE) {
					ERR_FAIL_COND_V_EDMSG(m_chk_rcv_bfr(srvr_response, bfr_size, pkt_itr, 8) != OK, ERR_PACKET_LENGTH_MISMATCH, vformat("ERR_PACKET_LENGTH_MISMATCH rcvd %d expect %d", bfr_size, pkt_itr + 8));
					len_encode = bytes_to_num_itr_pos<uint64_t>(srvr_response.ptr(), 8, pkt_itr);
				} else if (test == 0xFD) {
					ERR_FAIL_COND_V_EDMSG(m_chk_rcv_bfr(srvr_response, bfr_size, pkt_itr, 3) != OK, ERR_PACKET_LENGTH_MISMATCH, vformat("ERR_PACKET_LENGTH_MISMATCH rcvd %d expect %d", bfr_size, pkt_itr + 3));
					len_encode = bytes_to_num_itr_pos<uint64_t>(srvr_response.ptr(), 3, pkt_itr);
				} else if (test == 0xFC) {
					ERR_FAIL_COND_V_EDMSG(m_chk_rcv_bfr(srvr_response, bfr_size, pkt_itr, 2) != OK, ERR_PACKET_LENGTH_MISMATCH, vformat("ERR_PACKET_LENGTH_MISMATCH rcvd %d expect %d", bfr_size, pkt_itr + 2));
					len_encode = bytes_to_num_itr_pos<uint64_t>(srvr_response.ptr(), 2, pkt_itr);
				} else if (test == 0xFB) {
					//null value need to skip
					len_encode = 0;
				} else {
					len_encode = srvr_response[pkt_itr];
				}

				ERR_FAIL_COND_V_EDMSG(m_chk_rcv_bfr(srvr_response, bfr_size, pkt_itr, len_encode) != OK, ERR_PACKET_LENGTH_MISMATCH,
						vformat("ERR_PACKET_LENGTH_MISMATCH rcvd %d expect %d", bfr_size, pkt_itr + len_encode));

				if (len_encode > 0) {
					PackedByteArray data = m_get_pkt_bytes(srvr_response, ++pkt_itr, len_encode);
					dict[col_data[itr]["name"]] = m_get_type_data(col_data[itr]["field_type"], data);
				} else {
					dict[col_data[itr]["name"]] = Variant();
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

void MariaDBConnector::set_dbl_to_string(bool p_is_to_str) {
	_dbl_to_string = p_is_to_str;
}

// TODO If db is not the same and connected then change db on server
void MariaDBConnector::set_db_name(String p_dbname) {
	_dbname = p_dbname.to_utf8_buffer();
	// _dbname = p_dbname.to_ascii_buffer(); // TODO Add character set compatibility??
}

void MariaDBConnector::set_ip_type(IpType p_type) {
	_ip_type = p_type;
}
