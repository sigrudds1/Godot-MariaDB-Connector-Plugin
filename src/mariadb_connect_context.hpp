#pragma once

#include <godot_cpp/classes/ref_counted.hpp>
#include <godot_cpp/core/class_db.hpp>
#include "mariadb_connector_common.hpp"


using namespace godot;
// using MariaDBConnector_AuthType = MariaDBConnector::AuthType;

class MariaDBConnectContext : public RefCounted {
	GDCLASS(MariaDBConnectContext, RefCounted);

public:
	enum AuthType {
		AUTH_TYPE_ED25519 = MariaDBConnectorCommon::AUTH_TYPE_ED25519,
		AUTH_TYPE_MYSQL_NATIVE = MariaDBConnectorCommon::AUTH_TYPE_MYSQL_NATIVE,
		AUTH_TYPE_LAST = MariaDBConnectorCommon::AUTH_TYPE_LAST
	};
	enum Encoding {
		ENCODE_BASE64,
		ENCODE_HEX,
		ENCODE_PLAIN
	};


	void set_hostname(const String &p_hostname) { _hostname = p_hostname; }
	void set_port(int p_port) { _port = p_port; }
	void set_db_name(const String &p_db_name) { _db_name = p_db_name; }
	void set_username(const String &p_username) { _username = p_username; }
	void set_password(const String &p_password) { _password = p_password; }
	void set_auth_type(AuthType p_auth_type) { _auth_type = p_auth_type; }
	void set_encoding(Encoding p_encoding) { _encoding = p_encoding; }
	void set_is_prehashed(bool p_is_prehashed) { _is_prehashed = p_is_prehashed; }

	String get_hostname() const { return _hostname; }
	int get_port() const { return _port; }
	String get_db_name() const { return _db_name; }
	String get_username() const { return _username; }
	String get_password() const { return _password; }
	AuthType get_auth_type() const { return _auth_type; }
	Encoding get_encoding() const { return _encoding; }
	bool get_is_prehashed() const { return _is_prehashed; }

protected:
	static void _bind_methods();

private:
	String _hostname = "127.0.0.1";
	int _port = 3306;
	String _db_name;
	String _username;
	String _password;
	AuthType _auth_type = AuthType::AUTH_TYPE_ED25519;
	Encoding _encoding = ENCODE_BASE64;
	bool _is_prehashed = true;
};

VARIANT_ENUM_CAST(MariaDBConnectContext::Encoding);
VARIANT_ENUM_CAST(MariaDBConnectContext::AuthType);
