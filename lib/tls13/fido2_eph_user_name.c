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

#include "tls13/fido2_eph_user_name.h"
#include <sqlite3.h>

int _gnutls13_fido2_set_eph_user_name_server_share(gnutls_buffer_st* buf, fido2_server_ext_st* priv)
{
    int ret;

    /* generating 32 Byte server share for ephemeral username */
    ret = gnutls_rnd(GNUTLS_RND_RANDOM, priv->eph_user_name_server_share, sizeof(priv->eph_user_name_server_share));
    if (ret < 0) {
        gnutls_assert();
        return ret;
    }

    /* append to buffer */
    ret = _gnutls_buffer_append_data(buf, priv->eph_user_name_server_share, sizeof(priv->eph_user_name_server_share));
    if (ret < 0) {
        gnutls_assert();
        return ret;
    }

    return ret;
}

int _gnutls13_fido2_parse_eph_user_name_server_share(gnutls_buffer_st* buf, fido2_client_ext_st* priv)
{
    int ret;
    uint8_t eph_user_name_server_share[32];
    uint8_t concatenated_shares[64];
    uint8_t eph_user_name_raw[32]; /* SHA256-Hash always produces 32 Bytes */

    /* get server share for ephemeral user name */
    memcpy(eph_user_name_server_share, buf->data, buf->length);

    /* generating 32 Byte client share for ephemeral user name */
    ret = gnutls_rnd(GNUTLS_RND_RANDOM,priv->eph_user_name_client_share, sizeof(priv->eph_user_name_client_share));
    if (ret < 0) {
        gnutls_assert();
        return ret;
    }

    /* generating ephemeral user name */
    memcpy(concatenated_shares, eph_user_name_server_share, sizeof(eph_user_name_server_share));
    memcpy(concatenated_shares + sizeof(eph_user_name_server_share), priv->eph_user_name_client_share, sizeof(priv->eph_user_name_client_share));
 
    ret = gnutls_hash_fast(GNUTLS_DIG_SHA256, (void*) concatenated_shares, sizeof(concatenated_shares), (void*) eph_user_name_raw);
    if (ret < 0) {
        gnutls_assert();
        return ret;
    }
    memcpy(priv->eph_user_name, eph_user_name_raw, sizeof(eph_user_name_raw));
    priv->eph_user_name_set = 1;

    return ret;
}

int _gnutls13_fido2_set_eph_user_name_client_share(gnutls_buffer_st* buf, fido2_client_ext_st* priv)
{
    int ret;

    /* append client share for ephemeral user name */
    ret = _gnutls_buffer_append_data(buf, priv->eph_user_name_client_share, sizeof(priv->eph_user_name_client_share));
    if (ret < 0) {
        gnutls_assert();
        return ret;
    }

    return ret;
}

int _gnutls13_fido2_parse_eph_user_name_client_share(gnutls_buffer_st* buf, fido2_server_ext_st* priv)
{
    int ret;
    uint8_t eph_user_name_client_share[32];
    uint8_t concatenated_shares[64];
    uint8_t eph_user_name_raw[32]; /* SHA256-Hash always produces 32 Bytes */
    size_t length;

    /* get client share for ephemeral user name */
    memcpy(eph_user_name_client_share, buf->data, 32);
    DECR_LEN(buf->length, 32);
    buf->data += 32;

    /* generating ephemeral user name */
    memcpy(concatenated_shares, priv->eph_user_name_server_share, sizeof(priv->eph_user_name_server_share));
    memcpy(concatenated_shares + sizeof(priv->eph_user_name_server_share), eph_user_name_client_share, sizeof(eph_user_name_client_share));
 
    ret = gnutls_hash_fast(GNUTLS_DIG_SHA256, (void*) concatenated_shares, sizeof(concatenated_shares), (void*) eph_user_name_raw);
    if (ret < 0) {
        gnutls_assert();
        return ret;
    }
    memcpy(priv->eph_user_name, eph_user_name_raw, sizeof(eph_user_name_raw));
    priv->eph_user_name_set = 1;

    return ret;
}

int _gnutls13_fido2_db_name_response(gnutls_session_t session, fido2_server_ext_st* priv)
{
    int ret;
    sqlite3_stmt *res;
    sqlite3* db;

    /* compute expiration time */
    time_t t;
    time(&t);
    long expiration_time = t + 604800; /* 1 week (referes to lifetime of psks) */

    ret = sqlite3_open(priv->db_location, &db);
    if (ret != SQLITE_OK) {
        goto error;
    }

    ret = sqlite3_prepare_v2(db, SQL_QUERY, -1, &res, NULL);
    if (ret != SQLITE_OK) {
        goto error;
    }

    ret = sqlite3_bind_blob(res, 1, (void*) priv->eph_user_name, 32, SQLITE_STATIC);
    if (ret != SQLITE_OK) {
        goto error;
    }

    ret = sqlite3_bind_text(res, 2, priv->username, strlen(priv->username), NULL);
    if (ret != SQLITE_OK) {
        goto error;
    }

    ret = sqlite3_bind_int(res, 3, expiration_time);
    if (ret != SQLITE_OK) {
        goto error;
    }

    sqlite3_step(res);
    ret = sqlite3_finalize(res);
    if (ret != SQLITE_OK) {
        goto error;
    }

    sqlite3_close(db);
    return ret;

    error:
        sqlite3_close(db);
        gnutls_assert();
        return GNUTLS_E_INTERNAL_ERROR;


}