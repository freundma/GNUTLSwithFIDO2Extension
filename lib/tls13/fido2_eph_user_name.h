#ifndef GNUTLS_LIB_TLS13_FIDO2_EPH_USER_NAME_H
#define GNUTLS_LIB_TLS13_FIDO2_EPH_USER_NAME_H

#include "ext/fido2.h"

#define SQL_QUERY "INSERT INTO Users VALUES(?, ?, ?);"

int _gnutls13_fido2_set_eph_user_name_server_share(gnutls_buffer_st* buf, fido2_server_ext_st* priv);
int _gnutls13_fido2_parse_eph_user_name_server_share(gnutls_buffer_st* buf, fido2_client_ext_st* priv);
int _gnutls13_fido2_set_eph_user_name_client_share(gnutls_buffer_st* buf, fido2_client_ext_st* priv);
int _gnutls13_fido2_parse_eph_user_name_client_share(gnutls_buffer_st* buf, fido2_server_ext_st* priv);
int _gnutls13_fido2_db_name_response(gnutls_session_t session, fido2_server_ext_st* priv);

#endif /* GNUTLS_LIB_TLS13_FIDO2_EPH_USER_NAME_H */