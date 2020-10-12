#ifndef GNUTLS_LIB_TLS13_FIDO2_ASSERTION_REQUEST_H
#define GNUTLS_LIB_TLS13_FIDO2_ASSERTION_REQUEST_H

#include "ext/fido2.h"
#include <assert.h>

#define AUTHENTICATE_FI_MSG "POST /api/v1/authenticate HTTP/1.0\r\n\
Content-Type: application/x-www-form-urlencoded\r\n\
Content-Length: 0\r\n\r\n"
#define AUTHENTICATE_FN_MSG "POST /api/v1/authenticate HTTP/1.0\r\n\
Content-Type: application/x-www-form-urlencoded\r\n\
Content-Length: %zu\r\n\r\n\
username=%s"
#define LOOP_CHECK(rval, cmd) \
        do { \
                rval = cmd; \
        } while (rval == GNUTLS_E_AGAIN || rval == GNUTLS_E_INTERRUPTED);
#define MAX_BUF 8192
#define MAX_FN_MSG_LENGTH 256
#define CHALLENGE_LENGTH 43
#define ALLOWCREDENTIAL_ID_LENGTH 64

int _gnutls13_send_fido2_assertion_request(gnutls_session_t session, fido2_server_ext_st* priv);
int _gnutls13_recv_fido2_assertion_request(gnutls_session_t session, fido2_client_ext_st* priv);

#endif /* GNUTLS_LIB_TLS13_FIDO2_ASSERTION_REQUEST_H */