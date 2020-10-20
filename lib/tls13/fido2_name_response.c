#include "gnutls_int.h"
#include "tls13/fido2_name_response.h"
#include "tls13/fido2_eph_user_name.h"
#include "ext/fido2.h"
#include "mbuffers.h"
#include "handshake.h"
#include <time.h>

int _gnutls13_send_fido2_name_response(gnutls_session_t session, fido2_client_ext_st* priv)
{
    int ret;
    gnutls_buffer_st buf;
    mbuffer_st *bufel = NULL;

    ret = _gnutls_buffer_init_handshake_mbuffer(&buf);
    if (ret < 0) {
        return gnutls_assert_val(ret);
    }

    ret = _gnutls13_fido2_set_eph_user_name_client_share(&buf, priv);
    if (ret < 0) {
        gnutls_assert();
        goto cleanup;
    }

    /* append username and length of it */
    ret = _gnutls_buffer_append_data_prefix(&buf, 8, (void*) priv->username, strlen(priv->username));
    if (ret < 0) {
        gnutls_assert();
        goto cleanup;
    }

    bufel = _gnutls_buffer_to_mbuffer(&buf);
    ret = _gnutls_send_handshake(session, bufel, GNUTLS_HANDSHAKE_FIDO2_NAME_RESPONSE); 

    cleanup:
        _gnutls_buffer_clear(&buf);
        return ret;

}

int _gnutls13_recv_fido2_name_response(gnutls_session_t session, fido2_server_ext_st* priv)
{
    int ret;
    gnutls_buffer_st buf;
    size_t length;

    ret = _gnutls_recv_handshake(session, GNUTLS_HANDSHAKE_FIDO2_NAME_RESPONSE, 0, &buf);
    if (ret < 0) {
        gnutls_assert();
        return ret;
    }

    if (buf.length == 0) {
        ret = 0;
        goto cleanup;
    }

    if (buf.length <= 33) {
        gnutls_assert();
        ret = GNUTLS_E_UNEXPECTED_PACKET_LENGTH;
        goto cleanup;
    } /* must at least contain 32 byte client share + 1 byte length prefix for username */

    ret = _gnutls13_fido2_parse_eph_user_name_client_share(&buf, priv);
    if (ret < 0) {
        gnutls_assert();
        goto cleanup;
    }

    /* get actual username */
    length = buf.data[0];
    DECR_LEN(buf.length, 1);
    buf.data++;

    priv->username = gnutls_malloc(length+1);
    if (priv->username == NULL) {
        gnutls_assert();
        ret = GNUTLS_E_MEMORY_ERROR;
        goto cleanup;
    }

    memcpy(priv->username, buf.data, length);
    priv->username[length] = '\0'; /* NULL termination */
    DECR_LENGTH_COM(buf.length, length, ret = GNUTLS_E_UNEXPECTED_PACKET_LENGTH);
    if (ret < 0) {
        gnutls_free(priv->username);
        goto cleanup;
    }

    /* put (ephemeral username, username, expiration time) into  user db */
    ret = _gnutls13_fido2_db_name_response(session, priv);
    if (ret < 0) {
        gnutls_assert();
        gnutls_free(priv->username);
        goto cleanup;
    }
    
    cleanup:
        _gnutls_buffer_clear(&buf);
        return ret;
}