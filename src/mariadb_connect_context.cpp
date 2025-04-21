#include "mariadb_connect_context.hpp"

void MariaDBConnectContext::_bind_methods() {
	ClassDB::bind_method(D_METHOD("set_hostname", "hostname"), &MariaDBConnectContext::set_hostname);
	ClassDB::bind_method(D_METHOD("set_port", "port"), &MariaDBConnectContext::set_port);
	ClassDB::bind_method(D_METHOD("set_db_name", "db_name"), &MariaDBConnectContext::set_db_name);
	ClassDB::bind_method(D_METHOD("set_username", "username"), &MariaDBConnectContext::set_username);
	ClassDB::bind_method(D_METHOD("set_password", "password"), &MariaDBConnectContext::set_password);
	ClassDB::bind_method(D_METHOD("set_auth_type", "auth_type"), &MariaDBConnectContext::set_auth_type);
	ClassDB::bind_method(D_METHOD("set_encoding", "encoding"), &MariaDBConnectContext::set_encoding);
	ClassDB::bind_method(D_METHOD("set_is_prehashed", "is_prehashed"), &MariaDBConnectContext::set_is_prehashed);

	ClassDB::bind_method(D_METHOD("get_hostname"), &MariaDBConnectContext::get_hostname);
	ClassDB::bind_method(D_METHOD("get_port"), &MariaDBConnectContext::get_port);
	ClassDB::bind_method(D_METHOD("get_db_name"), &MariaDBConnectContext::get_db_name);
	ClassDB::bind_method(D_METHOD("get_username"), &MariaDBConnectContext::get_username);
	ClassDB::bind_method(D_METHOD("get_password"), &MariaDBConnectContext::get_password);
	ClassDB::bind_method(D_METHOD("get_auth_type"), &MariaDBConnectContext::get_auth_type);
	ClassDB::bind_method(D_METHOD("get_encoding"), &MariaDBConnectContext::get_encoding);
	ClassDB::bind_method(D_METHOD("get_is_prehashed"), &MariaDBConnectContext::get_is_prehashed);

	ADD_PROPERTY(PropertyInfo(Variant::STRING, "hostname"), "set_hostname", "get_hostname");
	ADD_PROPERTY(PropertyInfo(Variant::INT, "port"), "set_port", "get_port");
	ADD_PROPERTY(PropertyInfo(Variant::STRING, "db_name"), "set_db_name", "get_db_name");
	ADD_PROPERTY(PropertyInfo(Variant::STRING, "username"), "set_username", "get_username");
	ADD_PROPERTY(PropertyInfo(Variant::STRING, "password"), "set_password", "get_password");
	ADD_PROPERTY(PropertyInfo(Variant::INT, "auth_type"), "set_auth_type", "get_auth_type");
	ADD_PROPERTY(PropertyInfo(Variant::INT, "encoding"), "set_encoding", "get_encoding");
	ADD_PROPERTY(PropertyInfo(Variant::BOOL, "is_prehashed"), "set_is_prehashed", "get_is_prehashed");

	BIND_ENUM_CONSTANT(ENCODE_BASE64);
	BIND_ENUM_CONSTANT(ENCODE_HEX);
	BIND_ENUM_CONSTANT(ENCODE_PLAIN);

	BIND_ENUM_CONSTANT(AUTH_TYPE_ED25519);
	BIND_ENUM_CONSTANT(AUTH_TYPE_MYSQL_NATIVE);
}
