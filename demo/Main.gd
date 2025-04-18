extends Node

enum AuthType{
	NATIVE_PLAIN = 1,
	NATIVE_HASHED,
	ED25519_PLAIN,
	ED25519_HASHED,
}

# See the create_db.sql file to insall the data needed for this test
# Run the insert record functions once, then comment it out.

var ed: Dictionary = {
	"db_plain_text_pwd": "secret",
	"db_sha1_hashed_pwd": "e5e9fa1ba31ecd1ae84f75caaa474f3a663f05f4",
	"db_sha512_hashed_pwd": "bd2b1aaf7ef4f09be9f52ce2d8d599674d81aa9d6a4421696dc4d93dd0619d68" +
		"2ce56b4d64a9ef097761ced99e0f67265b5f76085e5b0ee7ca4696b2ad6fe2b2",
	"db_hostname": "127.0.0.1",
	"db_max_conns": 5,
	"db_name": "Godot_Test",
	"db_port": 3306,
	"db_native_user": "native_user",
	"db_ed_user": "ed_user"
}

var qry_stmt_array: PackedStringArray = [
	"SELECT * FROM Godot_Test.many_records LIMIT 1;",
	"SELECT * FROM Godot_Test.many_columns;"
]

var db: MariaDBConnector

var _auth_type: AuthType = AuthType.ED25519_HASHED


func _ready() -> void:
	db = MariaDBConnector.new()
	_connect_to_db_srvr(_auth_type)
	# Use inserts once to build data if using structure only
	# The release zip has the full db
#	_insert_many_columns() 
#	_insert_many_records()
	_run_db()
	
	var hasher := Argon2Hasher.new()
	var salt: String = hasher.generate_b64_salt()
	var hashed: String = hasher.hash_password_with_salt("secret", salt)
	print("argon2 hash: %s" % hashed)


func _exit_tree() -> void:
	db.disconnect_db()


func print_db_response(pba: PackedByteArray) -> void:
	for idx in range(pba.size() - 1, -1, -1):
		if pba[idx] < 32:
			pba.remove_at(idx)
	print(pba.get_string_from_ascii())


func _run_db() -> void:
	if db.is_connected_db():
		var start_uticks := Time.get_ticks_usec()
		var stmt: String = qry_stmt_array[0]
		print(stmt)
		var qry = db.query(stmt)
		if typeof(qry) == TYPE_ARRAY:
			print("total records received:", qry.size(), " time:", 
				Time.get_ticks_usec() - start_uticks)
			if qry.size() > 0:
				print(qry[0])
		else:
			print(stmt)
			print("ERROR:", qry)
	else:
		push_error("DB not connected")


func _connect_to_db_srvr(p_auth_type: AuthType) -> void:
	var err: int = MariaDBConnector.ErrorCode.OK
	match p_auth_type:
		AuthType.NATIVE_PLAIN:
			err = db.connect_db(
					ed["db_hostname"],
					ed["db_port"],
					ed["db_name"],
					ed["db_native_user"],
					ed["db_plain_text_pwd"],
					MariaDBConnector.AUTH_TYPE_MYSQL_NATIVE,
					false
			)
		AuthType.NATIVE_HASHED:
			err = db.connect_db(
					ed["db_hostname"],
					ed["db_port"],
					ed["db_name"],
					ed["db_native_user"],
					ed["db_sha1_hashed_pwd"],
					MariaDBConnector.AUTH_TYPE_MYSQL_NATIVE
			)
		AuthType.ED25519_PLAIN:
			err = db.connect_db(
					ed["db_hostname"],
					ed["db_port"],
					ed["db_name"],
					ed["db_ed_user"],
					ed["db_plain_text_pwd"],
					MariaDBConnector.AUTH_TYPE_ED25519,
					false
			)
		AuthType.ED25519_HASHED:
			err = db.connect_db(
					ed["db_hostname"],
					ed["db_port"],
					ed["db_name"],
					ed["db_ed_user"],
					ed["db_sha512_hashed_pwd"],
					MariaDBConnector.AUTH_TYPE_ED25519,
			)
	if err:
		print("db connect err:", err)


func _insert_many_columns() -> void:
	var stmt: String = "INSERT INTO Godot_Test.many_columns VALUES "
	for i in range(1, 253):
		stmt += "(%d)" % i
	
	stmt += ";"
	print(stmt)
	var err = db.query(stmt)
	if err != OK:
		printerr("Insert fail:" , err)


func _insert_many_records() -> void:
	var stmt: String = "INSERT INTO Godot_Test.`many_records (type, zone_id, player_id, map_id, " +\
			"text_field) VALUES " 
	for i in 10:
		stmt += "(%d, %d, %d, %d, %s)" % [i * 10 + 1, i * 10 + 2, i * 10 + 3, i * 10 + 4, 
			"Some text for record %d" % i]
	
	stmt += ";"
	print(stmt)
	var err = db.query(stmt)
	if err != OK:
		printerr("Insert fail:" , err)
