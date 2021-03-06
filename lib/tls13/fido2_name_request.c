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

#include "gnutls_int.h"
#include "tls13/fido2_name_request.h"
#include "tls13/fido2_eph_user_name.h"
#include "ext/fido2.h"
#include "mbuffers.h"
#include "handshake.h"

int _gnutls13_send_fido2_name_request(gnutls_session_t session, fido2_server_ext_st* priv)
{
    int ret;
    gnutls_buffer_st buf;
    mbuffer_st *bufel = NULL;

    ret = _gnutls_buffer_init_handshake_mbuffer(&buf);
    if (ret < 0) {
        return gnutls_assert_val(ret);
    }

    ret = _gnutls13_fido2_set_eph_user_name_server_share(&buf, priv);
    if (ret < 0) {
        gnutls_assert();
        goto cleanup;
    }

    bufel = _gnutls_buffer_to_mbuffer(&buf);
    ret =  _gnutls_send_handshake(session, bufel, GNUTLS_HANDSHAKE_FIDO2_NAME_REQUEST);

    cleanup:
        _gnutls_buffer_clear(&buf);
        return ret;
}

int _gnutls13_recv_fido2_name_request(gnutls_session_t session, fido2_client_ext_st* priv)
{
    int ret;
    gnutls_buffer_st buf;

    ret = _gnutls_recv_handshake(session, GNUTLS_HANDSHAKE_FIDO2_NAME_REQUEST, 1, &buf);
    if (ret < 0) {
        gnutls_assert();
        return ret;
    }

    if (buf.length == 0) {
        session->internals.fido2_status = GNUTLS_FIDO2_STATUS_INACTIVE;
        ret = 0;
        goto cleanup;
    }

    if (buf.length != 32) {
        gnutls_assert();
        ret = GNUTLS_E_UNEXPECTED_PACKET_LENGTH;
        goto cleanup;
    }

    ret = _gnutls13_fido2_parse_eph_user_name_server_share(&buf, priv);
    if (ret < 0) {
        gnutls_assert();
        goto cleanup;
    }

    cleanup:
        _gnutls_buffer_clear(&buf);
        return ret;
}
