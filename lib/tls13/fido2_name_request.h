#ifndef GNUTLS_LIB_TLS13_FIDO2_NAME_REQUEST_H
#define GNUTLS_LIB_TLS13_FIDO2_NAME_REQUEST_H

#include "ext/fido2.h"

int _gnutls13_send_fido2_name_request(gnutls_session_t session, fido2_server_ext_st* priv);
int _gnutls13_recv_fido2_name_request(gnutls_session_t session, fido2_client_ext_st* priv);

#endif /* GNUTLS_LIB_TLS13_FIDO2_NAME_REQUEST_H */