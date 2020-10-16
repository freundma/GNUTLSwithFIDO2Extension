#include "gnutls_int.h"
#include "tls13/fido2_assertion_response.h"
#include "tls13/fido2_eph_user_name.h"
#include "tls13/fido2_rp.h"
#include "ext/fido2.h"
#include "mbuffers.h"
#include "handshake.h"
#include <jansson.h> /* jansson library for json operations */
#include <nettle/base64.h> /* for base64url encoding */

extern int fido_assert_generate(void);

extern void fido_assert_deinit(void);

extern void fido_assert_free_dev(void);

extern size_t fido_assert_get_authenticator_data_length(void);

extern int fido_assert_get_authenticator_data(unsigned char **auth_data);

extern size_t fido_assert_get_signature_length(void);

extern int fido_assert_get_signature(unsigned char **sig);

extern size_t fido_assert_get_user_handle_length(void);

extern int fido_assert_get_user_handle(unsigned char **user_handle);

extern size_t fido_assert_get_selected_credential_length(void);

extern int fido_assert_get_selected_credential(unsigned char **selected_credential);

int set_json_base64url(json_t *object, uint8_t *data, size_t length, const char *key);

int parse_authenticator_data(gnutls_buffer_st *buf, uint8_t *auth_data);

int parse_client_extensions_output(gnutls_buffer_st *buf);

int get_user_id(char *answer, fido2_server_ext_st *priv);

int _gnutls13_send_fido2_assertion_response(gnutls_session_t session, fido2_client_ext_st *priv)
{
    int ret;
    uint8_t flags = GNUTLS_FIDO2_SELECTED_CREDENTIAL_ID_SET;
    gnutls_buffer_st buf;
    mbuffer_st* bufel;
    uint8_t* auth_data;
    uint8_t* signature;
    uint8_t* selected_credential_id;
    uint8_t* user_handle;
    size_t cbor_offset = 0;

    if (priv->mode == GNUTLS_FIDO2_MODE_FN) {
        flags = flags | GNUTLS_FIDO2_EPH_USER_NAME_CLIENT_SHARE_SET;
    }
    ret = fido_assert_generate();
    if (ret < 0) {
            if (ret == -2) {
                goto user_canceled_alert;
            }
        goto internal_error_alert;
    }

    auth_data = gnutls_malloc(fido_assert_get_authenticator_data_length());
    if (auth_data == NULL) {
        gnutls_assert();
        ret = GNUTLS_E_MEMORY_ERROR;
        goto early_error;
    }
    ret = fido_assert_get_authenticator_data((unsigned char**) &auth_data);
    if (ret < 0) {
        gnutls_assert();
        ret = GNUTLS_E_INTERNAL_ERROR;
        goto early_error;
    }
    if(auth_data[0] & GNUTLS_FIDO2_CBOR_OFFSET_2) {
        cbor_offset = 2;
    } else if (auth_data[0] & GNUTLS_FIDO2_CBOR_OFFSET_3) {
        cbor_offset = 3;
    } else if (auth_data[0] & GNUTLS_FIDO2_CBOR_OFFSET_5) {
        cbor_offset = 5;
    } else if (auth_data[0] & GNUTLS_FIDO2_CBOR_OFFSET_9) {
        cbor_offset = 9;
    } else {
        gnutls_assert();
        ret = GNUTLS_E_INTERNAL_ERROR;
        goto early_error;
    }

    signature = gnutls_malloc(fido_assert_get_signature_length());
    if (signature == NULL) {
        gnutls_assert();
        ret = GNUTLS_E_MEMORY_ERROR;
        gnutls_free(auth_data);
        goto early_error;
    }
    ret = fido_assert_get_signature((unsigned char**) &signature);
    if (ret < 0) {
        gnutls_assert();
        ret = GNUTLS_E_INTERNAL_ERROR;
        gnutls_free(auth_data);
        goto early_error;
    }

    if (priv->mode == GNUTLS_FIDO2_MODE_FI) {
        flags = flags | GNUTLS_FIDO2_USER_HANDLE_SET;
        user_handle = gnutls_malloc(fido_assert_get_user_handle_length());
        if (user_handle == NULL) {
            gnutls_assert();
            ret = GNUTLS_E_MEMORY_ERROR;
            gnutls_free(auth_data);
            gnutls_free(signature);
            goto early_error;
        }
        ret = fido_assert_get_user_handle((unsigned char**) &user_handle);
        if (ret < 0) {
            gnutls_assert();
            ret = GNUTLS_E_INTERNAL_ERROR;
            gnutls_free(auth_data);
            gnutls_free(signature);
            goto early_error;
        }
    }

    selected_credential_id = gnutls_malloc(fido_assert_get_selected_credential_length());
    if (selected_credential_id == NULL) {
        gnutls_assert();
        ret = GNUTLS_E_MEMORY_ERROR;
        gnutls_free(auth_data);
        gnutls_free(signature);
        if (flags & GNUTLS_FIDO2_USER_HANDLE_SET) {
            gnutls_free(user_handle);
        }
        goto early_error;
    }
    ret = fido_assert_get_selected_credential((unsigned char**) &selected_credential_id);
    if (ret < 0) {
        gnutls_assert();
        ret = GNUTLS_E_INTERNAL_ERROR;
        gnutls_free(auth_data);
        gnutls_free(signature);
        if (flags & GNUTLS_FIDO2_USER_HANDLE_SET) {
            gnutls_free(user_handle);
        }
        goto early_error;
    }

    ret = _gnutls_buffer_init_handshake_mbuffer(&buf);
    if (ret < 0){
        gnutls_assert();
        goto end;
    }

    /* flags */
    ret = _gnutls_buffer_append_data(&buf, &flags, 1);
    if (ret < 0) {
        gnutls_assert();
        goto end;
    }

    /* client data json */
    ret = _gnutls_buffer_append_data_prefix(&buf, 24, (void*) priv->client_data_json, strlen(priv->client_data_json) + 1);
    if (ret < 0) {
        gnutls_assert();
        goto end;
    }

    /* authenticator data */
    /* get rid of cbor information at start */
    ret = _gnutls_buffer_append_data(&buf, (void*) auth_data + cbor_offset, fido_assert_get_authenticator_data_length() - cbor_offset);
    if (ret < 0) {
        gnutls_assert();
        goto end;
    }

    /* signature */
    ret = _gnutls_buffer_append_data_prefix(&buf, 16, (void*) signature, fido_assert_get_signature_length());
    if (ret < 0) {
        gnutls_assert();
        goto end;
    }

    /* user handle */
    if (flags & GNUTLS_FIDO2_USER_HANDLE_SET) {
        ret = _gnutls_buffer_append_data_prefix(&buf, 8, (void*) user_handle, fido_assert_get_user_handle_length());
        if (ret < 0) {
            gnutls_assert();
            goto end;
        }
    }

    /* selected credential id */ 
    ret = _gnutls_buffer_append_data_prefix(&buf, 16, (void*) selected_credential_id, fido_assert_get_selected_credential_length());
    if (ret < 0) {
        gnutls_assert();
        goto end;
    }

    /* client share for ephemeral username */
    if (flags & GNUTLS_FIDO2_EPH_USER_NAME_CLIENT_SHARE_SET) {
        ret = _gnutls13_fido2_set_eph_user_name_client_share(&buf, priv);
        if (ret < 0) {
            gnutls_assert();
            goto end;
        }
    }

    /* At the moment no extension handling is implemented.  
    * So the client extensions output is not set.
    */

    bufel = _gnutls_buffer_to_mbuffer(&buf);
    ret = _gnutls_send_handshake(session, bufel, GNUTLS_HANDSHAKE_FIDO2_ASSERTION_RESPONSE);
    goto end;

    early_error:
        fido_assert_deinit();
        fido_assert_free_dev();
        return ret;

    end:
        gnutls_free(auth_data);
        gnutls_free(signature);
        if (flags & GNUTLS_FIDO2_USER_HANDLE_SET) {
            gnutls_free(user_handle);
        }
        gnutls_free(selected_credential_id);
        fido_assert_deinit();
        fido_assert_free_dev();
        _gnutls_buffer_clear(&buf);
        return ret;
    
    user_canceled_alert:
        fido_assert_deinit();
        fido_assert_free_dev();
        ret = gnutls_alert_send(session, GNUTLS_AL_FATAL, GNUTLS_A_USER_CANCELED);
        gnutls_assert();
        if (ret < 0) {
            return ret;
        }
        return GNUTLS_E_INTERNAL_ERROR;
    
    internal_error_alert:
        fido_assert_deinit();
        fido_assert_free_dev();
        ret = gnutls_alert_send(session, GNUTLS_AL_FATAL, GNUTLS_A_INTERNAL_ERROR);
        gnutls_assert();
        if (ret < 0) {
            return ret;
        }
        return GNUTLS_E_INTERNAL_ERROR;
}

int _gnutls13_recv_fido2_assertion_response(gnutls_session_t session, fido2_server_ext_st *priv)
{
    gnutls_buffer_st buf;
    int ret;
    uint8_t flags;
    size_t length;
    char* client_data_json;
    uint8_t authenticator_data[AUTHENTICATOR_DATA_LENGTH];
    uint8_t* signature;
    char finish_msg[MAX_FINISH_MSG_LENGTH];
    char buffer[MAX_BUF + 1];
    int sd;
    gnutls_certificate_credentials_t xcred;

    ret = _gnutls_recv_handshake(session, GNUTLS_HANDSHAKE_FIDO2_ASSERTION_RESPONSE, 0, &buf);
    if (ret < 0) {
        gnutls_assert();
        return ret;
    }

    json_t* authenticator_response = json_object();
    json_t* response = json_object();
    json_t* credential = json_object();
    json_t* client_extension_results_json = json_object();
    json_t* type_json = json_string("public-key");

    flags = buf.data[0];
    DECR_LENGTH_COM(buf.length, 1, ret = GNUTLS_E_UNEXPECTED_PACKET_LENGTH);
    if (ret < 0) {
        goto early_error;
    }
    buf.data++;

    /* request-ID */
    json_t* request_id_json = json_string(priv->request_id);
    ret = json_object_set(authenticator_response, "requestId", request_id_json);
    if (ret < 0) {
        gnutls_assert();
        ret = GNUTLS_E_INTERNAL_ERROR;
        goto error;
    }

    /* client data json */
    length = _gnutls_read_uint24(buf.data);
    DECR_LENGTH_COM(buf.length, 3, ret = GNUTLS_E_UNEXPECTED_PACKET_LENGTH);
    if (ret < 0) {
        goto error;
    }
    buf.data += 3;
    client_data_json = gnutls_malloc(length);
    if (client_data_json == NULL) {
        gnutls_assert();
        ret = GNUTLS_E_MEMORY_ERROR;
        goto error;
    }
    memcpy(client_data_json, buf.data, length);
    DECR_LENGTH_COM(buf.length, length, ret = GNUTLS_E_UNEXPECTED_PACKET_LENGTH);
    if (ret < 0) {
        gnutls_free(client_data_json);
        goto error;
    }
    buf.data += length;

    ret = set_json_base64url(response, (uint8_t*) client_data_json, strlen(client_data_json), "clientDataJSON");
    if (ret < 0) {
        gnutls_assert();
        gnutls_free(client_data_json);
        goto error;
    }
    gnutls_free(client_data_json);

    /* authenticator data */
    ret = parse_authenticator_data(&buf, authenticator_data);
    if (ret < 0) {
        gnutls_assert();
        goto error;
    }

    ret = set_json_base64url(response, authenticator_data, AUTHENTICATOR_DATA_LENGTH, "authenticatorData");
    if (ret < 0) {
        gnutls_assert();
        goto error;
    }

    /* signature */
    length = _gnutls_read_uint16(buf.data);
    DECR_LENGTH_COM(buf.length, 2, ret = GNUTLS_E_UNEXPECTED_PACKET_LENGTH);
    if (ret < 0){
        goto error;
    }
    buf.data += 2;
    signature = gnutls_malloc(length);
    if (signature == NULL) {
        gnutls_assert();
        ret = GNUTLS_E_MEMORY_ERROR;
        goto error;
    }
    memcpy(signature, buf.data, length);
    DECR_LENGTH_COM(buf.length, length, ret = GNUTLS_E_UNEXPECTED_PACKET_LENGTH);
    if (ret < 0){
        gnutls_free(signature);
        goto error;
    }
    buf.data += length;

    ret = set_json_base64url(response, signature, length, "signature");
    if (ret < 0) {
        gnutls_assert();
        gnutls_free(signature);
        goto error;
    }
    gnutls_free(signature);

    /* user handle */
    if (flags & GNUTLS_FIDO2_USER_HANDLE_SET) {
        length = buf.data[0];
        DECR_LENGTH_COM(buf.length, 1, ret = GNUTLS_E_UNEXPECTED_PACKET_LENGTH);
        if (ret < 0){
            goto error;
        }
        buf.data++;
        uint8_t* user_handle = gnutls_malloc(length);
        if (user_handle == NULL) {
            gnutls_assert();
            ret = GNUTLS_E_MEMORY_ERROR;
            goto error;
        }
        memcpy(user_handle, buf.data, length);
        DECR_LENGTH_COM(buf.length, length, ret = GNUTLS_E_UNEXPECTED_PACKET_LENGTH);
        if (ret < 0) {
            gnutls_free(user_handle);
            goto error;
        }
        buf.data += length;

        ret = set_json_base64url(response, user_handle, length, "userHandle");
        if (ret < 0) {
            gnutls_assert();
            gnutls_free(user_handle);
            goto error;
        }
        gnutls_free(user_handle);
    }

    /* selected credential id */
    if (flags & GNUTLS_FIDO2_SELECTED_CREDENTIAL_ID_SET) {
        length = _gnutls_read_uint16(buf.data);
        DECR_LENGTH_COM(buf.length, 2, ret = GNUTLS_E_UNEXPECTED_PACKET_LENGTH);
        if (ret < 0) {
            goto error;
        }
        buf.data += 2;
        uint8_t* selected_credential_id = gnutls_malloc(length);
        if (selected_credential_id == NULL) {
            gnutls_assert();
            ret = GNUTLS_E_MEMORY_ERROR;
            goto error;
        }
        memcpy(selected_credential_id, buf.data, length);
        DECR_LENGTH_COM(buf.length, length, ret = GNUTLS_E_UNEXPECTED_PACKET_LENGTH);
        if (ret < 0){
            gnutls_free(selected_credential_id);
            goto error;
        }
        buf.data += length;

        ret = set_json_base64url(credential, selected_credential_id, length, "id");
        if (ret < 0) {
            gnutls_assert();
            gnutls_free(selected_credential_id);
            goto error;
        }
        gnutls_free(selected_credential_id);
    } else {
        ret = json_object_set(credential, "id", json_null());
        if (ret < 0) {
            gnutls_assert();
            goto error;
        }
    }

    /* client extensions output
     * Only parsing for compability.
     * No information kept or processed.
     */
    if (flags & GNUTLS_FIDO2_CLIENT_EXTENSION_OUTPUT_SET) {
        ret = parse_client_extensions_output(&buf);
        if (ret < 0) {
            gnutls_assert();
            goto error;
        }
    }

    /* ephemeral username */
    if (flags & GNUTLS_FIDO2_EPH_USER_NAME_CLIENT_SHARE_SET) {
        if (buf.length != 32) {
            gnutls_assert();
            ret = GNUTLS_E_UNEXPECTED_PACKET_LENGTH;
            goto error;
        }
        ret = _gnutls13_fido2_parse_eph_user_name_client_share(&buf, priv);
        if (ret < 0) {
            gnutls_assert();
            goto error;
        }

        ret = _gnutls13_fido2_db_name_response(session, priv);
        if (ret < 0) {
            gnutls_assert();
            goto error;
        }
    } else {
        if (buf.length != 0) {
            gnutls_assert();
            ret = GNUTLS_E_UNEXPECTED_PACKET_LENGTH;
            goto error;
        }
    }

    ret = json_object_set(credential, "response", response);
    if (ret < 0) {
        gnutls_assert();
        ret = GNUTLS_E_INTERNAL_ERROR;
        goto error;
    }

    ret = json_object_set(client_extension_results_json, "appid", json_false());
    if (ret < 0) {
        gnutls_assert();
        ret = GNUTLS_E_INTERNAL_ERROR;
        goto error;
    }

    ret = json_object_set(credential, "clientExtensionResults", client_extension_results_json);
    if (ret < 0) {
        gnutls_assert();
        ret = GNUTLS_E_INTERNAL_ERROR;
        goto error;
    }

    ret = json_object_set(credential, "type", type_json);
    if (ret < 0) {
        gnutls_assert();
        ret = GNUTLS_E_INTERNAL_ERROR;
        goto error;
    }

    ret = json_object_set(authenticator_response, "credential", credential);
    if (ret < 0) {
        gnutls_assert();
        ret = GNUTLS_E_INTERNAL_ERROR;
        goto error;
    }

    char* authenticator_response_str = json_dumps(authenticator_response, 0);

    /* finish authentication */ 
    sprintf(finish_msg, FINISH_MSG, strlen(authenticator_response_str), authenticator_response_str);
    gnutls_free(authenticator_response_str);

    ret = _gnutls13_fido2_rp_connect(priv->rp_session, priv->rp_ip, priv->rp_port, &priv->rp_data, &sd, &xcred);
    if (ret < 0) {
        gnutls_assert();
        ret = GNUTLS_E_INTERNAL_ERROR;
        goto error;
    }

    LOOP_CHECK(ret, gnutls_record_send(*priv->rp_session, finish_msg, strlen(finish_msg)));
    if (ret < 0) {
        gnutls_assert();
        ret = GNUTLS_E_INTERNAL_ERROR;
        _gnutls13_fido2_rp_shutdown(priv->rp_session, &sd);
        gnutls_certificate_free_credentials(xcred);
        goto error;
    }

    /*rp answer */
    LOOP_CHECK(ret, gnutls_record_recv(*priv->rp_session, buffer, MAX_BUF));
    if (ret <= 0) {
        gnutls_assert();
        ret = GNUTLS_E_INTERNAL_ERROR;
        _gnutls13_fido2_rp_shutdown(priv->rp_session, &sd);
        gnutls_certificate_free_credentials(xcred);
        goto error;
    }

    _gnutls13_fido2_rp_shutdown(priv->rp_session, &sd);
    gnutls_certificate_free_credentials(xcred);

    /* extract json string out of server answer */
    char* answer = gnutls_malloc(ret+1);
    if (answer == NULL) {
        gnutls_assert();
        ret = GNUTLS_E_MEMORY_ERROR;
        goto error;
    }

    memcpy(answer, buffer, ret);
    answer[ret] = '\0'; /* finish string */

    /* evaluate status code.
     * we use buffer as kind of container to store the 
     * rest of the answer we don't need.  
     */
    int status_code;
    ret = sscanf(answer, "%s %i %s", buffer, &status_code, buffer + 9);
    if (ret != 3) {
        gnutls_assert();
        ret = GNUTLS_E_INTERNAL_ERROR;
        gnutls_free(answer);
        goto error;
    }
    if (status_code != 200) {
        goto authentication_error;
    }

    ret = get_user_id(answer, priv);
    if (ret < 0) {
        gnutls_assert();
        gnutls_free(answer);
        goto error;
    }

    priv->client_authenticated = 1;
    goto end;

    early_error:
        json_decref(authenticator_response);
        json_decref(credential);
        json_decref(response);
        json_decref(client_extension_results_json);
        json_decref(type_json);
        _gnutls_buffer_clear(&buf);
        return ret;

    error:
        json_decref(authenticator_response);
        json_decref(credential);
        json_decref(response);
        json_decref(client_extension_results_json);
        json_decref(type_json);
        json_decref(request_id_json);
        _gnutls_buffer_clear(&buf);
        return ret;

    authentication_error:
        json_decref(authenticator_response);
        json_decref(credential);
        json_decref(response);
        json_decref(client_extension_results_json);
        json_decref(type_json);
        json_decref(request_id_json);
        gnutls_free(answer);
        _gnutls_buffer_clear(&buf);
        ret = gnutls_alert_send(session, GNUTLS_AL_FATAL, GNUTLS_A_FIDO2_AUTHENTICATION_ERROR);
        gnutls_assert();
        if (ret < 0) {
            return ret;
        }
        return GNUTLS_E_FIDO2_AUTHENTICATION_ERROR;

    end:
        json_decref(authenticator_response);
        json_decref(credential);
        json_decref(response);
        json_decref(client_extension_results_json);
        json_decref(type_json);
        json_decref(request_id_json);
        gnutls_free(answer);
        _gnutls_buffer_clear(&buf);
        return ret;
}

int set_json_base64url(json_t* object, uint8_t* data, size_t length, const char* key)
{
    int ret;
    struct base64_encode_ctx ctx;

    base64url_encode_init(&ctx);
    char* base64url_str = gnutls_malloc(BASE64_ENCODE_LENGTH(length)+10); /* tolerance */
    if (base64url_str == NULL) {
        gnutls_assert();
        ret = GNUTLS_E_MEMORY_ERROR;
        return ret;
    }
    size_t output_length = base64_encode_update(&ctx, base64url_str, length, data);
    output_length += base64_encode_final(&ctx, base64url_str + output_length);
    base64url_str[output_length] = '\0'; /* NULL termination */

    json_t* base64url_json = json_string(base64url_str);

    ret = json_object_set(object, key, base64url_json);
    if (ret < 0) {
        gnutls_assert();
        ret = GNUTLS_E_INTERNAL_ERROR;
        json_decref(base64url_json);
        gnutls_free(base64url_str);
        return ret;
    }

    json_decref(base64url_json);
    gnutls_free(base64url_str);
    return ret;
}

int parse_authenticator_data(gnutls_buffer_st* buf, uint8_t* auth_data)
{
    size_t number;
    size_t length;
    uint8_t flags;

    /* RP-ID Hash */
    memcpy(auth_data, buf->data, 32);
    DECR_LEN(buf->length, 32);
    buf->data += 32;

    /* flags */
    flags = buf->data[0];
    DECR_LEN(buf->length, 1);
    buf->data++;
    uint8_t flags_new = flags;

    /* remove flags if there */
    if (flags_new & GNUTLS_FIDO2_AUTH_DATA_ATTESTED_CREDENTIAL) {
        flags_new = flags_new & ~(GNUTLS_FIDO2_AUTH_DATA_ATTESTED_CREDENTIAL);
    }
    if (flags_new & GNUTLS_FIDO2_AUTH_DATA_AUTH_EXT_OUTPUT) {
        flags_new = flags_new & ~(GNUTLS_FIDO2_AUTH_DATA_AUTH_EXT_OUTPUT);
    }

    memcpy(auth_data + 32, &flags_new, 1);

    /* signature count */
    memcpy(auth_data + 33, buf->data, 4);
    DECR_LEN(buf->length, 4);
    buf->data += 4;

    /* We neither process the attested credentials nor the authenticator
     * extensions output. The parsing is just for compability.
     */

    if (flags & GNUTLS_FIDO2_AUTH_DATA_ATTESTED_CREDENTIAL) {
        /* aaguid */
        DECR_LEN(buf->length, 16);
        buf->data += 16;

        /* length */
        length = _gnutls_read_uint16(buf->data);
        DECR_LEN(buf->length, 2);
        buf->data += 2;

        /* ID */
        DECR_LEN(buf->length, length);
        buf->data += length;

        /* key length */
        length = _gnutls_read_uint16(buf->data);
        DECR_LEN(buf->length, 2);
        buf->data += 2;

        /* public key */
        DECR_LEN(buf->length, length);
        buf->data += length;
    }

    if (flags & GNUTLS_FIDO2_AUTH_DATA_AUTH_EXT_OUTPUT) {
        number = buf->data[0];
        DECR_LEN(buf->length, 1);
        buf->data++;

        if (number > 63) {
            gnutls_assert();
            return GNUTLS_E_UNEXPECTED_PACKET_LENGTH;
        }

        for (size_t i = 0; i < number; i++) {
            /* length */
            length = buf->data[0];
            DECR_LEN(buf->length, 1);
            buf->data++;
            
            if (length > 31) {
                gnutls_assert();
                return GNUTLS_E_UNEXPECTED_PACKET_LENGTH;
            }

            /* ID */
            DECR_LEN(buf->length, length);
            buf->data += length;

            /* data length */
            length = _gnutls_read_uint16(buf->data);
            DECR_LEN(buf->data, 2);
            buf->data += 2;

            /* data */
            DECR_LEN(buf->length, length);
            buf->data += length;
        }
    }

    return 0;
}

int parse_client_extensions_output(gnutls_buffer_st* buf)
{
    size_t number;
    size_t length;
    
    number = buf->data[0];
    DECR_LEN(buf->length, 1);
    buf->data++;

    if (number > 63) {
        gnutls_assert();
        return GNUTLS_E_UNEXPECTED_PACKET_LENGTH;
    }

    for (size_t i = 0; i < number; i++) {
        length = buf->data[0];
        DECR_LEN(buf->length, 1);
        buf->data++;

        if(length > 31) {
            gnutls_assert();
            return GNUTLS_E_UNEXPECTED_PACKET_LENGTH;
        }
        DECR_LEN(buf->length, length);
        buf->data += length;

        length = _gnutls_read_uint16(buf->data);
        DECR_LEN(buf->length, 2);
        buf->data += 2;

        DECR_LEN(buf->length, length);
        buf->data += length;
    }

    /* No client extensions output is processed.
     * You could deal with it here in later versions.
     */
    return 0;
}

int get_user_id(char *answer, fido2_server_ext_st *priv)
{
    char* help;

    help = strchr(answer, '{'); /* beginning of json object */
    int index = (int) (help-answer);

    char* json_string = answer + index;
    json_t* answer_json = json_loads(json_string, 0, NULL);
    if (answer_json == NULL) {
        gnutls_assert();
        return GNUTLS_E_INTERNAL_ERROR;
    }

    void* iterator = json_object_iter_at(answer_json, "registrations");
    if (iterator == NULL) {
        gnutls_assert();
        json_decref(answer_json);
        return GNUTLS_E_INTERNAL_ERROR;
    }

    json_t* registrations = json_object_iter_value(iterator);
    json_t* registration_element = json_array_get(registrations, 0);
    if (registration_element == NULL) {
         gnutls_assert();
        json_decref(answer_json);
        return GNUTLS_E_INTERNAL_ERROR;
    }

    iterator = json_object_iter_at(registration_element, "userIdentity");
    if (iterator == NULL) {
        gnutls_assert();
        json_decref(answer_json);
        return GNUTLS_E_INTERNAL_ERROR;
    }

    json_t* user_identity = json_object_iter_value(iterator);
    iterator = json_object_iter_at(user_identity, "id");
    if (iterator == NULL) {
        gnutls_assert();
        json_decref(answer_json);
        return GNUTLS_E_INTERNAL_ERROR;
    }
    json_t* id_json = json_object_iter_value(iterator);
    char* id = json_string_value(id_json);

    priv->user_id = gnutls_malloc(strlen(id)+1);
    if (priv->user_id == NULL) {
        gnutls_assert();
        json_decref(answer_json);
        return GNUTLS_E_INTERNAL_ERROR;
    }
    strcpy(priv->user_id, id);

    json_decref(answer_json);
    return 0;
}