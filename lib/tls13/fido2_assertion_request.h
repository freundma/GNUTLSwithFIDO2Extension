/*
 * Copyright (C) 2020, Mario Freund
 *
 * This file is part of the FIDO2 extension of GnuTLS.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 3 of
 * the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>
 *
 */

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