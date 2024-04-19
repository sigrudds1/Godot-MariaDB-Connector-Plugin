#ifndef MARIADB_CONNECTOR_HPP
#define MARIADB_CONNECTOR_HPP

#include <godot_cpp/core/class_db.hpp>
#include <godot_cpp/core/binder_common.hpp>

#include <godot_cpp/classes/ref_counted.hpp>
#include <godot_cpp/classes/ip.hpp>
#include <godot_cpp/classes/stream_peer_tcp.hpp>

// #include <thread>
// #include <godot_cpp/classes/thread.hpp>
// #include <godot_cpp/classes/mutex.hpp>

using namespace godot;

constexpr uint8_t kCharacterCollationId = 33; //utf8_general_ci
constexpr char *kCharacterCollationName = (char *)"utf8_general_ci";

class MariaDBConnector : public RefCounted {
	GDCLASS(MariaDBConnector, RefCounted);

public:
	enum AuthType {
		AUTH_TYPE_ED25519,
		AUTH_TYPE_MYSQL_NATIVE,
		AUTH_TYPE_LAST,
	};

	enum IpType {
		IP_TYPE_IPV4 = IP::TYPE_IPV4,
		IP_TYPE_IPV6 = IP::TYPE_IPV6,
		IP_TYPE_ANY = IP::TYPE_ANY,
	};

	enum ErrorCodes {
		OK = 0,
		ERR_NO_RESPONSE,
		ERR_NOT_CONNECTED,
		ERR_PACKET_LENGTH_MISMATCH,
		ERR_PACKET_SEQUENCE_ERROR,
		ERR_SERVER_PROTOCOL_INCOMPATIBLE,
		ERR_CLIENT_PROTOCOL_INCOMPATIBLE,
		ERR_AUTH_PLUGIN_NOT_SET,
		ERR_AUTH_PLUGIN_INCOMPATIBLE,
		ERR_AUTH_FAILED,
		ERR_USERNAME_EMPTY,
		ERR_PASSWORD_EMPTY,
		ERR_DB_EMPTY
	};

private:
	//https://mariadb.com/kb/en/connection/#capabilities
	enum class Capabilities : uint64_t {
		LONG_PASSWORD = (1UL << 0), //MySQL
		CLIENT_MYSQL = (1UL << 0), //MariaDBConnector - lets server know this is a mysql client
		FOUND_ROWS = (1UL << 1),
		LONG_FLAG = (1UL << 2), //Not listed in MariaDBConnector
		CONNECT_WITH_DB = (1UL << 3),
		NO_SCHEMA = (1UL << 4), //Not listed in MariaDBConnector
		NO_DB_TABLE_COLUMN = (1UL << 4), //Alternate name, Not listed in MariaDBConnector
		COMPRESS = (1UL << 5),
		ODBC = (1UL << 6), //Not listed in MariaDBConnector
		LOCAL_FILES = (1UL << 7),
		IGNORE_SPACE = (1UL << 8),
		CLIENT_PROTOCOL_41 = (1UL << 9),
		CLIENT_INTERACTIVE = (1UL << 10),
		SSL = (1UL << 11),
		IGNORE_SIGPIPE = (1UL << 12), //MySQL
		TRANSACTIONS_MARIA = (1UL << 12), //MariaDBConnector
		TRANSACTIONS_MYSQL = (1UL << 13), //MySQL
		SECURE_CONNECTION = (1UL << 13), //MariaDBConnector
		RESERVED = (1UL << 14), //Not listed in MariaDBConnector
		RESERVED2 = (1UL << 15), //Not in Maria Docs but needed
		MULTI_STATEMENTS = (1UL << 16),
		MULTI_RESULTS = (1UL << 17),
		PS_MULTI_RESULTS = (1UL << 18),
		PLUGIN_AUTH = (1UL << 19),
		CLIENT_SEND_CONNECT_ATTRS = (1UL << 20),
		PLUGIN_AUTH_LENENC_CLIENT_DATA = (1UL << 21), //TODO Add compatibility
		CAN_HANDLE_EXPIRED_PASSWORDS = (1UL << 22), //Not listed in MariaDBConnector
		SESSION_TRACK = (1UL << 23),
		CLIENT_DEPRECATE_EOF = (1UL << 24),
		OPTIONAL_RESULTSET_METADATA = (1UL << 25),
		CLIENT_ZSTD_COMPRESSION_ALGORITHM = (1UL << 26),
		CLIENT_QUERY_ATTRIBUTES = (1UL << 27), //Not listed in MariaDBConnector
		//NOT_USED = (1UL << 28),
		CLIENT_CAPABILITY_EXTENSION = (1UL << 29), //MariaDBConnector reserved for future use.
		SSL_VERIFY_SERVER_CERT = (1UL << 30), //Not listed in MariaDBConnector
		REMEMBER_OPTIONS = (1UL << 31), //Not listed in MariaDBConnector
		MARIADB_CLIENT_PROGRESS = (1UL << 32),
		MARIADB_CLIENT_COM_MULTI = (1UL << 33),
		MARIADB_CLIENT_STMT_BULK_OPERATIONS = (1UL << 34),
		MARIADB_CLIENT_EXTENDED_TYPE_INFO = (1UL << 35),
		MARIADB_CLIENT_CACHE_METADATA = (1UL << 36)
	};



	const String kAuthTypeNamesStr = "client_ed25519,mysql_native_password";
	const PackedStringArray kAuthTypeNames = kAuthTypeNamesStr.split(",");
	bool _dbl_to_string = false;
	IpType _ip_type = IpType::IP_TYPE_ANY;
	AuthType _client_auth_type = AUTH_TYPE_ED25519;
	bool _is_pre_hashed = true;
	bool _authenticated = false;
	uint64_t _client_capabilities = 0;
	uint64_t _server_capabilities = 0;

	PackedByteArray _username;
	PackedByteArray _password_hashed;
	PackedByteArray _dbname;

	StreamPeerTCP _stream;
	String _ip;
	int _port = 0;

	// bool _running = true;
	// bool _tcp_polling;
	// Mutex _tcp_mutex;
	// std::thread _tcp_thread;
	// PackedByteArray _tcp_thread_data;

	String _protocol_ver;
	String _server_ver_str;
	uint8_t _srvr_major_ver = 0;
	uint8_t _srvr_minor_ver = 0;
	String _last_query;
	PackedByteArray _last_query_converted;
	PackedByteArray _last_transmitted;
	PackedByteArray _last_response;


	/**
	 * \brief			Adds the packet size and sequence number to the beginning of the packet,
	 *					it must be used once just before sending stream to server.
	 * \param stream	std::vector<uint8_t> the stream to be modified.
	 * \param sequance	int
	 */
	void m_add_packet_header(PackedByteArray &p_pkt, uint8_t p_pkt_seq);

	// void m_append_thread_data(PackedByteArray &p_data, const uint64_t p_timeout = 1000);
	// void m_tcp_thread_func();

	uint32_t m_chk_rcv_bfr(PackedByteArray &bfr, int &bfr_size, const size_t cur_pos, const size_t need);

	Error m_client_protocol_v41(const AuthType p_srvr_auth_type, const PackedByteArray p_srvr_salt);
	Error m_connect();

	String m_find_vbytes_str_at(PackedByteArray p_buf, size_t &p_start_pos);
	String m_find_vbytes_str(PackedByteArray p_buf);

	PackedByteArray m_get_pkt_bytes(const PackedByteArray &src_buf, size_t &start_pos, const size_t byte_cnt);
	size_t m_get_pkt_len_at(const PackedByteArray p_src_buf, size_t &p_start_pos);
	AuthType m_get_server_auth_type(String p_srvr_auth_name);
	Variant m_get_type_data(const int p_db_field_type, const PackedByteArray p_data);

	PackedByteArray m_recv_data(uint32_t p_timeout);
	//TODO(sigrudds1) Add error log file using the username in the filename
	void m_handle_server_error(const PackedByteArray p_src_buffer, size_t &p_last_pos);
	Error m_server_init_handshake_v10(const PackedByteArray &p_src_buffer);
	void m_update_password(String p_password);
	void m_update_username(String P_username);


protected:
	static void _bind_methods();

public:
	/**
	 * \brief				This method sets the authentication type used.
	 *
	 * \param host
	 * \param port
	 * \param dbname
	 * \param username
	 * \param password
	 * \param auth_type		enum AuthType determines what authoriztion type will be statically used.
	 * \param is_pre_hash	bool if set the password used will be hashed by the required type before used.
	 * \return 				uint32_t 0 = no error, see error enum class ErrorCode
	 */
	Error connect_db(String host, int port, String dbname, String username, String password,
			AuthType auth_type = AuthType::AUTH_TYPE_ED25519, bool is_prehashed = true);

	void disconnect_db();

	String get_last_query();
	PackedByteArray get_last_query_converted();
	PackedByteArray get_last_response();
	PackedByteArray get_last_transmitted();

	// PackedByteArray get_caching_sha2_passwd_hash(PackedByteArray p_sha256_hashed_passwd, PackedByteArray p_srvr_salt);
	PackedByteArray get_client_ed25519_signature(PackedByteArray p_sha512_hashed_passwd, PackedByteArray p_svr_msg);
	PackedByteArray get_mysql_native_password_hash(PackedByteArray p_sha1_hashed_passwd, PackedByteArray p_srvr_salt);

	bool is_connected_db();

	Variant query(String sql_stmt);


	//TODO(sigrudds1) Implement SSL/TLS
	//void tls_enable(bool enable);

	void set_dbl_to_string(bool is_to_str);
	void set_db_name(String p_db_name);
	void set_ip_type(IpType p_type);
	//TODO(sigrudds1) Async Callbacks signals

	MariaDBConnector();
	~MariaDBConnector();
};

VARIANT_ENUM_CAST(MariaDBConnector::AuthType);
VARIANT_ENUM_CAST(MariaDBConnector::IpType);



#endif