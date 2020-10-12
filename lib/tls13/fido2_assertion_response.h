#ifndef GNUTLS_LIB_TLS13_FIDO2_ASSERTION_RESPONSE_H
#define GNUTLS_LIB_TLS13_FIDO2_ASSERTION_RESPONSE_H

#include "ext/fido2.h"
#include <assert.h>

#define FINISH_MSG "POST /api/v1/authenticate/finish HTTP/1.0\r\n\
Content-Type: application/json\r\n\
Content-Length: %zu\r\n\r\n\
%s"
#define LOOP_CHECK(rval, cmd) \
        do { \
                rval = cmd; \
        } while (rval == GNUTLS_E_AGAIN || rval == GNUTLS_E_INTERRUPTED);
#define MAX_BUF 16384
#define MAX_FINISH_MSG_LENGTH 2048
#define AUTHENTICATOR_DATA_LENGTH 37

int _gnutls13_send_fido2_assertion_response(gnutls_session_t session, fido2_client_ext_st* priv);
int _gnutls13_recv_fido2_assertion_response(gnutls_session_t session, fido2_server_ext_st* priv);

typedef enum {
        GNUTLS_FIDO2_CBOR_OFFSET_2 = 24,
        GNUTLS_FIDO2_CBOR_OFFSET_3 = 25,
        GNUTLS_FIDO2_CBOR_OFFSET_5 = 26,
        GNUTLS_FIDO2_CBOR_OFFSET_9 = 27
} gnutls_fido2_cbor_offset_t;

#endif /* GNUTLS_LIB_TLS13_FIDO2_ASSERTION_RESPONSE_H */