
#pragma once

class MariaDBConnectorCommon {
public:
	enum AuthType {
		AUTH_TYPE_ED25519,
		AUTH_TYPE_MYSQL_NATIVE,
		AUTH_TYPE_LAST
	};
};