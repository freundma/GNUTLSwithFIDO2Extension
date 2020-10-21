#include "gnutls_int.h"
#include "tls13/fido2_assertion_request.h"
#include "tls13/fido2_eph_user_name.h"
#include "tls13/fido2_rp.h"
#include "ext/fido2.h"
#include "mbuffers.h"
#include "handshake.h"
#include <nettle/base64.h> /* for base64url encoding/decoding */
#include <nettle/sha3.h> /* for shaker funtion */
#include <jansson.h> /* jansson library for json operations */
#include <curl/curl.h> /*for url encoding of username */

extern int fido_assert_init(void);

extern void fido_assert_deinit(void);

extern int fido_assert_add_allow_credential(const unsigned char *id, size_t len);

extern int fido_assert_setup(const unsigned char *client_data_hash, const char *rpid,
                        const char *user_verification);

int parse_extensions(gnutls_buffer_st *buf);

int set_allow_credentials(gnutls_buffer_st *buf, json_t *aC_json);

int parse_allow_credentials(gnutls_buffer_st *buf, gnutls_session_t session);

int send_random_assertion_request(gnutls_session_t session, fido2_server_ext_st *priv);

char* rand_string(char *str, size_t size);

int _gnutls13_send_fido2_assertion_request(gnutls_session_t session, fido2_server_ext_st *priv)
{
    int ret;
    gnutls_buffer_st buf;
    mbuffer_st *bufel = NULL;
    char buffer[MAX_BUF + 1];
    char fn_msg[MAX_FN_MSG_LENGTH];
    uint8_t flags = GNUTLS_FIDO2_RP_ID_SET;
    uint64_t timeout = 0;
    char* user_verification = NULL;
    json_t* aC_json = NULL;
    json_t* uV_json = NULL;
    struct base64_decode_ctx ctx;
    int sd;
    gnutls_certificate_credentials_t xcred;

    ret = _gnutls_buffer_init_handshake_mbuffer(&buf);
    if (ret < 0) {
        return gnutls_assert_val(ret);
    }

    base64url_decode_init(&ctx);

    /* connect to rp server */
    ret = _gnutls13_fido2_rp_connect(priv->rp_session, priv->rp_ip, priv->rp_port, NULL, &sd, &xcred);
    if (ret < 0) {
        gnutls_assert();
        ret = GNUTLS_E_INTERNAL_ERROR;
        _gnutls_buffer_clear(&buf);
        return ret;
    }
        
    if (priv->mode == GNUTLS_FIDO2_MODE_FI) {
        /* FI mode */
        LOOP_CHECK(ret, gnutls_record_send(*priv->rp_session, AUTHENTICATE_FI_MSG, strlen(AUTHENTICATE_FI_MSG)));
        if (ret < 0) {
            gnutls_assert();
            ret = GNUTLS_E_INTERNAL_ERROR;
            goto rp_error;
        }
    } else {
        /* FN mode */
        /* url encoding of username */
        CURL* curl = curl_easy_init();
        if (curl == NULL) {
            gnutls_assert();
            ret = GNUTLS_E_INTERNAL_ERROR;
            goto rp_error;
        }
        char* url_username = curl_easy_escape(curl, priv->username, 0);
        if (url_username == NULL) {
            gnutls_assert();
            ret = GNUTLS_E_INTERNAL_ERROR;
            curl_easy_cleanup(curl);
            goto rp_error;
        }
        sprintf(fn_msg, AUTHENTICATE_FN_MSG, strlen(url_username) + 9, url_username);
        curl_free(url_username);
        curl_easy_cleanup(curl);
        LOOP_CHECK(ret, gnutls_record_send(*priv->rp_session, fn_msg, strlen(fn_msg)));
        if (ret < 0) {
            gnutls_assert();
            ret = GNUTLS_E_INTERNAL_ERROR;
            goto rp_error;
        }
        flags = flags | GNUTLS_FIDO2_EPH_USER_NAME_SERVER_SHARE_SET;
    } 

    /* get server answer (challenge etc.) */
    LOOP_CHECK(ret, gnutls_record_recv(*priv->rp_session, buffer, MAX_BUF));
    if (ret <= 0) {
        gnutls_assert();
        ret = GNUTLS_E_INTERNAL_ERROR;
        goto rp_error;
    }

    /* shutdown of rp connection and pack for session resumption */
    int another_ret = _gnutls13_fido2_rp_pack(priv->rp_session, &priv->rp_data, &sd);
    if (another_ret < 0) {
        gnutls_assert();
        another_ret = GNUTLS_E_INTERNAL_ERROR;
        _gnutls_buffer_clear(&buf);
        gnutls_certificate_free_credentials(xcred);
        return another_ret;
    }
    gnutls_certificate_free_credentials(xcred);

    /* extract json string out of rp server answer */
    char* answer = gnutls_malloc(ret+1);
    if (answer == NULL) {
        gnutls_assert();
        ret = GNUTLS_E_MEMORY_ERROR;
        _gnutls_buffer_clear(&buf);
        return ret;
    }

    memcpy(answer, buffer, ret);
    answer[ret] = '\0'; /* finish string */
    char* help;

    help = strchr(answer, '{'); /* beginning of json object */
    int index = (int) (help-answer);

    char* json_string = answer + index;
    
    json_t* json;
    json = json_loads(json_string, 0, NULL);

    gnutls_free(answer);

    /* In this case a "messages" - object is only provided when
     * the requested username is not registered. So
     * we do not have to process the rp server answer.
     */
    void* iterator = json_object_iter_at(json, "messages");
    if (iterator != NULL) {
        ret = send_random_assertion_request(session, priv);
        json_decref(json);
        _gnutls_buffer_clear(&buf);
        return ret;
    }

    iterator = json_object_iter_at(json, "request");
    if (iterator == NULL) {
        json_decref(json);
        gnutls_assert();
        ret = GNUTLS_E_INTERNAL_ERROR;
        goto cleanup;
    }
    json_t* request = json_object_iter_value(iterator);

    /*extract request-ID */
    iterator = json_object_iter_at(request, "requestId");
    if (iterator == NULL) {
        json_decref(json);
        gnutls_assert();
        ret = GNUTLS_E_INTERNAL_ERROR;
        goto cleanup;
    }
    json_t* request_id = json_object_iter_value(iterator);
    priv->request_id = gnutls_malloc(strlen(json_string_value(request_id))+1);
    if (priv->request_id == NULL) {
        json_decref(json);
        gnutls_assert();
        ret = GNUTLS_E_MEMORY_ERROR;
        goto cleanup;
    }
    strcpy(priv->request_id, json_string_value(request_id));

    /* extract publicKeyCredentialRequestOptions */
    iterator = json_object_iter_at(request, "publicKeyCredentialRequestOptions");
    if (iterator == NULL) {
        json_decref(json);
        gnutls_assert();
        ret = GNUTLS_E_INTERNAL_ERROR;
        goto cleanup;
    }
    json_t* pKCRO = json_object_iter_value(iterator);

    /* get challenge */
    iterator = json_object_iter_at(pKCRO, "challenge");
    if (iterator == NULL) {
        json_decref(json);
        gnutls_assert();
        ret = GNUTLS_E_INTERNAL_ERROR;
        goto cleanup;
    }
    json_t* challenge_json = json_object_iter_value(iterator);
    char* challenge_base64url = json_string_value(challenge_json);

    /* get timeout */
    iterator = json_object_iter_at(pKCRO, "timeout");
    if (iterator != NULL) {
        flags = flags | GNUTLS_FIDO2_TIMEOUT_SET;
        json_t* timeout_json = json_object_iter_value(iterator);
        timeout = (uint64_t) json_integer_value(timeout_json);
        json_decref(timeout_json);
    }

    /* get allow credentials */
    if (priv->mode == GNUTLS_FIDO2_MODE_FN) {
        iterator = json_object_iter_at(pKCRO, "allowCredentials");
        if (iterator == NULL) {
            gnutls_assert();
            ret = GNUTLS_E_INTERNAL_ERROR;
            goto error;
        }
        aC_json = json_object_iter_value(iterator);
        /* rest comes later */
        flags = flags | GNUTLS_FIDO2_ALLOW_CREDENTIALS_SET;
    }

    /* get user verification */
    iterator = json_object_iter_at(pKCRO, "userVerification");
    if (iterator != NULL) {
        flags = flags | GNUTLS_FIDO2_USER_VERIFICATION_SET;
        uV_json = json_object_iter_value(iterator);
        user_verification = json_string_value(uV_json);
    }

    /* At this point we don't parse set extensions for the purpose
     * of simplicity, but this could be a thing in later versions.
     */
    
    ret = _gnutls_buffer_append_data(&buf, &flags, 1);
    if (ret < 0) {
        gnutls_assert();
        goto error;
    }

    ret = _gnutls_buffer_append_data_prefix(&buf, 16, (void*) challenge_base64url, strlen(challenge_base64url));
    if (ret < 0) {
        gnutls_assert();
        goto error;
    }

    if (flags & GNUTLS_FIDO2_TIMEOUT_SET) {
        ret = _gnutls_buffer_append_data(&buf, &timeout, 8);
        if (ret < 0) {
            gnutls_assert();
            goto error;
        }
    }
    
    ret = _gnutls_buffer_append_data_prefix(&buf, 8, (void*) priv->rpid, strlen(priv->rpid));
    if (ret < 0) {
        gnutls_assert();
        goto error;
    }
    

    if (flags & GNUTLS_FIDO2_ALLOW_CREDENTIALS_SET) {
        ret = set_allow_credentials(&buf, aC_json);
        if (ret < 0) {
            gnutls_assert();
            goto error;
        }
    }

    if (flags & GNUTLS_FIDO2_USER_VERIFICATION_SET) {
        ret = _gnutls_buffer_append_data_prefix(&buf, 8, (void*) user_verification, strlen(user_verification));
        if (ret < 0) {
            gnutls_assert();
            goto error;
        }
    }

    if (flags & GNUTLS_FIDO2_EPH_USER_NAME_SERVER_SHARE_SET) {
        ret = _gnutls13_fido2_set_eph_user_name_server_share(&buf, priv);
        if (ret < 0) {
            gnutls_assert();
            goto error;
        }
    }
    bufel = _gnutls_buffer_to_mbuffer(&buf);
    ret = _gnutls_send_handshake(session, bufel, GNUTLS_HANDSHAKE_FIDO2_ASSERTION_REQUEST);

    json_decref(json);

    cleanup:
        _gnutls_buffer_clear(&buf);
        return ret;

    rp_error:
        _gnutls_buffer_clear(&buf);
        _gnutls13_fido2_rp_shutdown(priv->rp_session, &sd);
        gnutls_certificate_free_credentials(xcred);
        return ret;
    
    error:
        json_decref(json);
        _gnutls_buffer_clear(&buf);
        return ret;
}

int _gnutls13_recv_fido2_assertion_request(gnutls_session_t session, fido2_client_ext_st* priv)
{
    int ret;
    gnutls_buffer_st buf;
    uint8_t flags;
    size_t length;
    char* base64url_challenge;
    uint64_t timeout;
    char* rpid;
    char* user_verification;

    ret = _gnutls_recv_handshake(session, GNUTLS_HANDSHAKE_FIDO2_ASSERTION_REQUEST, 1, &buf);
    if (ret < 0) {
        gnutls_assert();
        return ret;
    }

    if (buf.length == 0) {
        session->internals.fido2_status = GNUTLS_FIDO2_STATUS_INACTIVE;
        _gnutls_buffer_clear(&buf);
        return 0;
    }

    ret = fido_assert_init();
    if (ret < 0) {
        gnutls_assert();
        ret = GNUTLS_E_INTERNAL_ERROR;
        _gnutls_buffer_clear(&buf);
        return ret;
    }

    if (buf.length <= 3) {
        ret = GNUTLS_E_UNEXPECTED_PACKET_LENGTH;
        goto early_error;
    }

    /* flags */
    flags = buf.data[0];
    buf.data++;
    DECR_LENGTH_COM(buf.length, 1, ret = GNUTLS_E_UNEXPECTED_PACKET_LENGTH);
    if (ret < 0) {
        goto early_error;
    }

    /* challenge */
    length = _gnutls_read_uint16(buf.data);
    DECR_LENGTH_COM(buf.length, 2, ret = GNUTLS_E_UNEXPECTED_PACKET_LENGTH);
    if (ret < 0) {
        goto early_error;
    }
    buf.data += 2;

    base64url_challenge = gnutls_malloc(length+1);
    if (base64url_challenge == NULL) {
        gnutls_assert();
        ret = GNUTLS_E_MEMORY_ERROR;
        goto early_error;
    }

    memcpy(base64url_challenge, buf.data, length);
    base64url_challenge[length] = '\0'; /* NULL termination */
    DECR_LENGTH_COM(buf.length, length, ret = GNUTLS_E_UNEXPECTED_PACKET_LENGTH);
    if (ret < 0) {
        gnutls_free(base64url_challenge);
        goto early_error;
    }
    buf.data += length;

    /* timeout, at the moment we don't process it in any way */
    if (flags & GNUTLS_FIDO2_TIMEOUT_SET) {
        memcpy(&timeout, buf.data, 8);
        DECR_LENGTH_COM(buf.length, 8, ret = GNUTLS_E_UNEXPECTED_PACKET_LENGTH);
        if (ret < 0) {
            gnutls_free(base64url_challenge);
            goto early_error;
        }
        buf.data += 8;
    }

    /* RP-ID */
    if (flags & GNUTLS_FIDO2_RP_ID_SET) {
        length = buf.data[0];
        DECR_LENGTH_COM(buf.length, 1, ret = GNUTLS_E_UNEXPECTED_PACKET_LENGTH);
        if (ret < 0) {
            gnutls_free(base64url_challenge);
            goto early_error;
        }
        buf.data++;

        rpid = gnutls_malloc(length+1);
        if (rpid == NULL) {
            gnutls_assert();
            ret = GNUTLS_E_MEMORY_ERROR;
            gnutls_free(base64url_challenge);
            goto early_error;
        }

        memcpy(rpid, buf.data, length);
        rpid[length] = '\0'; /* NULL termination */
        DECR_LENGTH_COM(buf.length, length, ret = GNUTLS_E_UNEXPECTED_PACKET_LENGTH);
        if (ret < 0){
            gnutls_free(base64url_challenge);
            gnutls_free(rpid);
            goto early_error;
        }
        buf.data += length;

        /* check RP-ID: According to the WebAuthn spec there has to be asserted that
         * the RP-ID is a equal to the server domain or a registrable domain suffix.
         * Here we just check for equality.
         */

        if (strcmp(rpid, priv->server_domain) != 0) {
            goto alert;
        }
    } else {
        rpid = gnutls_malloc(strlen(priv->server_domain)+1);
        if (rpid == NULL) {
            gnutls_assert();
            ret = GNUTLS_E_MEMORY_ERROR;
            gnutls_free(base64url_challenge);
            goto early_error;
        }

        strcpy(rpid, priv->server_domain);
    }

    /* allow credentials */
    if (flags & GNUTLS_FIDO2_ALLOW_CREDENTIALS_SET) {
        ret = parse_allow_credentials(&buf, session);
        if (ret < 0) {
            gnutls_assert();
            gnutls_free(base64url_challenge);
            gnutls_free(rpid);
            goto early_error;
        }
    }

    /* user verification */
    if (flags & GNUTLS_FIDO2_USER_VERIFICATION_SET) {
        length = buf.data[0];
        DECR_LENGTH_COM(buf.length, 1, ret = GNUTLS_E_UNEXPECTED_PACKET_LENGTH);
        if (ret < 0) {
            gnutls_free(base64url_challenge);
            gnutls_free(rpid);
            goto early_error;
        }
        buf.data++;

        user_verification = gnutls_malloc(length+1);
        if (user_verification == NULL) {
            gnutls_assert();
            ret = GNUTLS_E_MEMORY_ERROR;
            gnutls_free(base64url_challenge);
            gnutls_free(rpid);
            goto early_error;
        }

        memcpy(user_verification, buf.data, length);
        user_verification[length] = '\0';
        DECR_LENGTH_COM(buf.length, length, ret = GNUTLS_E_UNEXPECTED_PACKET_LENGTH);
        if (ret < 0) {
            gnutls_free(base64url_challenge);
            gnutls_free(rpid);
            gnutls_free(user_verification);
            goto early_error;
        }
        buf.data += length;
    } else {
        /* the default value for the user verification would be "preferred" */
        user_verification = gnutls_malloc(strlen("preferred")+1);
        if (user_verification == NULL) {
            gnutls_assert();
            ret = GNUTLS_E_MEMORY_ERROR;
            gnutls_free(base64url_challenge);
            gnutls_free(rpid);
            goto early_error;
        }
        strcpy(user_verification, "preferred");
    }

    /* extensions
     * The client only parses the extensions for compability.
     * The information about the extensions is not kept or processed.
     */
    if (flags & GNUTLS_FIDO2_EXTENSIONS_SET) {
        ret = parse_extensions(&buf);
        if (ret < 0) {
            gnutls_assert();
            gnutls_free(base64url_challenge);
            gnutls_free(rpid);
            gnutls_free(user_verification);
            goto early_error;
        }
    }

    /* ephemeral user name */
    if (flags & GNUTLS_FIDO2_EPH_USER_NAME_SERVER_SHARE_SET) {
        if (buf.length != 32) {
            gnutls_assert();
            ret = GNUTLS_E_UNEXPECTED_PACKET_LENGTH;
            gnutls_free(base64url_challenge);
            gnutls_free(rpid);
            gnutls_free(user_verification);
            goto early_error;
        }
        ret = _gnutls13_fido2_parse_eph_user_name_server_share(&buf, priv);
        if (ret < 0) {
            gnutls_assert();
            gnutls_free(base64url_challenge);
            gnutls_free(rpid);
            gnutls_free(user_verification);
            goto early_error;
        }

        DECR_LEN_FINAL(buf.length, 32);
    } else {
        if (buf.length != 0) {
            gnutls_assert();
            ret = GNUTLS_E_UNEXPECTED_PACKET_LENGTH;
            gnutls_free(base64url_challenge);
            gnutls_free(rpid);
            gnutls_free(user_verification);
            goto early_error;
        }
    }
        
    /* prepare assertion */

    /* https:// + server domain name + '/0' */
    char* origin = gnutls_malloc(8 + strlen(priv->server_domain) + 1);
    if (origin == NULL) {
        gnutls_assert();
        ret = GNUTLS_E_MEMORY_ERROR;
        gnutls_free(base64url_challenge);
        gnutls_free(rpid);
        gnutls_free(user_verification);
        goto early_error;
    }
    strcpy(origin, "https://");
    strcat(origin, priv->server_domain);

    json_t* client_data = json_object();

    /* type */
    json_t* type_json = json_string("webauthn.get");
    ret = json_object_set(client_data, "type", type_json);
    if (ret < 0) {
        gnutls_assert();
        ret = GNUTLS_E_INTERNAL_ERROR;
        goto late_error;
    }

    /* challenge */
    json_t* base64url_challenge_json = json_string(base64url_challenge);
    ret = json_object_set(client_data, "challenge", base64url_challenge_json);
    if (ret < 0) {
        gnutls_assert();
        ret = GNUTLS_E_INTERNAL_ERROR;
        json_decref(type_json);
        goto late_error;
    }

    /* origin */
    json_t* origin_json = json_string(origin);
    ret = json_object_set(client_data, "origin", origin_json);
    if (ret < 0) {
        gnutls_assert();
        ret = GNUTLS_E_INTERNAL_ERROR;
        json_decref(type_json);
        json_decref(base64url_challenge_json);
        goto late_error;
    }

    char* client_data_raw = json_dumps(client_data, 0);
    priv->client_data_json = client_data_raw;

    /* SHA256 hash over client data */
    uint8_t client_data_hash[32]; /* always produces 32 Bytes */
    ret = gnutls_hash_fast(GNUTLS_DIG_SHA256, (void*) client_data_raw, strlen(client_data_raw), (void*) client_data_hash);
    if (ret < 0) {
        gnutls_assert();
        json_decref(type_json);
        json_decref(base64url_challenge_json);
        json_decref(origin_json);
        goto late_error;
    }

    ret = fido_assert_setup((unsigned char*) client_data_hash, rpid, user_verification);
    if (ret < 0) {
        gnutls_assert();
        ret = GNUTLS_E_INTERNAL_ERROR;
        json_decref(type_json);
        json_decref(base64url_challenge_json);
        json_decref(origin_json);
        goto late_error;
        goto late_error;
    }
    goto end;    
    

    early_error:
        _gnutls_buffer_clear(&buf);
        fido_assert_deinit();
        return ret;

    alert:
        gnutls_free(base64url_challenge);
        gnutls_free(rpid);
        _gnutls_buffer_clear(&buf);
        fido_assert_deinit();
        ret = gnutls_alert_send(session, GNUTLS_AL_FATAL, GNUTLS_A_FIDO2_BAD_REQUEST);
        gnutls_assert();
        if (ret < 0) {
            return ret;
        }
        return GNUTLS_E_FIDO2_BAD_REQUEST;

    late_error:
        gnutls_free(base64url_challenge);
        gnutls_free(rpid);
        gnutls_free(user_verification);
        gnutls_free(origin);
        json_decref(client_data);
        _gnutls_buffer_clear(&buf);
        fido_assert_deinit();
        return ret;

    end:
        gnutls_free(base64url_challenge);
        gnutls_free(rpid);
        gnutls_free(user_verification);
        gnutls_free(origin);
        json_decref(client_data);
        json_decref(type_json);
        json_decref(base64url_challenge_json);
        json_decref(origin_json);
        _gnutls_buffer_clear(&buf);
        priv->assertion_set = 1;
        return ret;
}

int parse_extensions(gnutls_buffer_st *buf)
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

        if (length > 31) {
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

        /* Extension information is not processed. 
         * You could deal with it here in later versions.
         */
    }
    return 0;
}

int set_allow_credentials(gnutls_buffer_st *buf, json_t *aC_json)
{
    int ret;
    size_t index;
    json_t* value_json;
    json_t* id_json;
    json_t* type_json;
    char* id_base64url = NULL;
    char* type = NULL;
    struct base64_decode_ctx ctx;
    size_t decode_length;

    base64url_decode_init(&ctx);

    size_t number = json_array_size(aC_json);
    size_t transports_number = 0;
    ret = _gnutls_buffer_append_data(buf, &number, 1);
    if (ret < 0) {
        gnutls_assert();
        return ret;
    }

    /* transports are ignored for purpose of simplicity !! */
    json_array_foreach(aC_json, index, value_json) {
        id_json = json_object_get(value_json, "id");
        type_json = json_object_get(value_json, "type");

        id_base64url = json_string_value(id_json);
        type = json_string_value(type_json);

        decode_length = BASE64_DECODE_LENGTH(strlen(id_base64url));
        uint8_t* id = gnutls_malloc(decode_length);
        if (id == NULL) {
            gnutls_assert();
            ret = GNUTLS_E_MEMORY_ERROR;
            return ret;
        }
        base64_decode_update(&ctx, &decode_length, id, strlen(id_base64url), id_base64url);

        ret = _gnutls_buffer_append_data_prefix(buf, 16, (void*) id, decode_length);
        if (ret < 0) {
            gnutls_assert();
            gnutls_free(id);
            return ret;
        }
        ret = _gnutls_buffer_append_data_prefix(buf, 8, (void*) type, strlen(type));
        if (ret < 0) {
            gnutls_assert();
            gnutls_free(id);
            return ret;
        }

        ret =_gnutls_buffer_append_data(buf, &transports_number, 1); /* no transports */
        if (ret < 0) {
            gnutls_assert();
            gnutls_free(id);
            return ret;
        }
        
        gnutls_free(id);
    }
    return ret;
}

int parse_allow_credentials(gnutls_buffer_st *buf, gnutls_session_t session)
{
    size_t number;
    size_t length;
    size_t id_length;
    uint8_t* id;
    char* type; 
    int ret = 0;

    number = buf->data[0];
    DECR_LEN(buf->length, 1);
    buf->data++;

    if (number > 63) {
        gnutls_assert();
        return GNUTLS_E_UNEXPECTED_PACKET_LENGTH;
    }

    for (size_t i = 0; i < number; i++) {
        length = _gnutls_read_uint16(buf->data);
        DECR_LEN(buf->length, 2);
        buf->data += 2;

        id = gnutls_malloc(length);
        if (id == NULL) {
            gnutls_assert();
            return GNUTLS_E_MEMORY_ERROR;
        }
        memcpy(id, buf->data, length);
        DECR_LENGTH_COM(buf->length, length, ret = GNUTLS_E_UNEXPECTED_PACKET_LENGTH);
        if (ret < 0) {
            goto error;
        }
        buf->data += length;
        id_length = length;

        length = buf->data[0];
        DECR_LENGTH_COM(buf->length, 1, ret = GNUTLS_E_UNEXPECTED_PACKET_LENGTH);
        if (ret < 0) {
            goto error;
        }
        buf->data++;

        type = gnutls_malloc(length+1);
        if (type == NULL) {
            gnutls_assert();
            gnutls_free(id);
            return GNUTLS_E_MEMORY_ERROR;
        }
        memcpy(type, buf->data, length);
        type[length] = '\0'; /* NULL termination */
        DECR_LENGTH_COM(buf->length, length, ret = GNUTLS_E_UNEXPECTED_PACKET_LENGTH);
        if (ret < 0) {
            gnutls_free(type);
            goto error;
        }
        buf->data += length;

        if (strcmp(type, "public-key") != 0) {
            gnutls_free(id);
            gnutls_free(type);
            ret =  gnutls_alert_send(session, GNUTLS_AL_FATAL, GNUTLS_A_FIDO2_BAD_REQUEST);
            gnutls_assert();
            if (ret < 0) {
                return ret;
            }
            return GNUTLS_E_FIDO2_BAD_REQUEST;
        }
        gnutls_free(type);

        /* no transports processed, usb authenticator assumed */
        size_t tr_number = buf->data[0];
        DECR_LENGTH_COM(buf->length, 1, ret = GNUTLS_E_UNEXPECTED_PACKET_LENGTH);
        if (ret < 0) {
            goto error;
        }
        buf->data++;
        if (tr_number > 63) {
            gnutls_free(id);
            gnutls_assert();
            return GNUTLS_E_UNEXPECTED_PACKET_LENGTH;
        }

        for (size_t j = 0; j < tr_number; j++) {
            length = buf->data[0];
            DECR_LENGTH_COM(buf->length, 1, ret = GNUTLS_E_UNEXPECTED_PACKET_LENGTH);
            if (ret < 0) {
                goto error;
            }
            buf->data++;

            DECR_LENGTH_COM(buf->length, length, ret = GNUTLS_E_UNEXPECTED_PACKET_LENGTH);
            if (ret < 0) {
                goto error;
            }
            buf->data += length;
        }

        ret = fido_assert_add_allow_credential((unsigned char*) id, id_length);
        if (ret < 0) {
            gnutls_assert();
            gnutls_free(id);
            ret = GNUTLS_E_INTERNAL_ERROR;
            return ret;
        }

        gnutls_free(id);
    }

    return ret;

    error:
        gnutls_free(id);
        return ret;
}

int send_random_assertion_request(gnutls_session_t session, fido2_server_ext_st *priv)
{
    int ret = 0;
    gnutls_buffer_st buf;
    uint8_t flags = GNUTLS_FIDO2_RP_ID_SET | GNUTLS_FIDO2_ALLOW_CREDENTIALS_SET |
        GNUTLS_FIDO2_USER_VERIFICATION_SET | GNUTLS_FIDO2_EPH_USER_NAME_SERVER_SHARE_SET;
    char challenge[CHALLENGE_LENGTH];
    uint8_t aCid[ALLOWCREDENTIAL_ID_LENGTH];
    char* user_verification = "preferred";
    size_t aC_number = 1;
    size_t transports_number = 0;
    
    ret = _gnutls_buffer_init_handshake_mbuffer(&buf);
    if (ret < 0) {
        gnutls_assert();
        _gnutls_buffer_clear(&buf);
        return ret;
    }

    ret = _gnutls_buffer_append_data(&buf, &flags, 1);
    if (ret < 0) {
        gnutls_assert();
        _gnutls_buffer_clear(&buf);
        return ret;
    }

    /* challenge */
    srand(time(NULL));
    rand_string(challenge, sizeof(challenge));

    ret = _gnutls_buffer_append_data_prefix(&buf, 16, (void*) challenge, sizeof(challenge));
    if (ret < 0) {
        gnutls_assert();
        _gnutls_buffer_clear(&buf);
        return ret;
    }

    /* RP-ID */
    ret = _gnutls_buffer_append_data_prefix(&buf, 8, (void*) priv->rpid, strlen(priv->rpid));
    if (ret < 0) {
        gnutls_assert();
        _gnutls_buffer_clear(&buf);
        return ret;
    }

    /* allow credentials */
    uint8_t* seed = gnutls_malloc(strlen(priv->username) + sizeof(priv->secret));
    if (seed == NULL) {
        gnutls_assert();
        _gnutls_buffer_clear(&buf);
        return GNUTLS_E_MEMORY_ERROR;
    }
    memcpy(seed, priv->username, strlen(priv->username));
    memcpy(seed + strlen(priv->username), priv->secret, sizeof(priv->secret));

    /* sha3shake256 function */
    struct sha3_256_ctx hash_ctx;
    sha3_256_init(&hash_ctx);
    sha3_256_update(&hash_ctx, strlen(priv->username) + sizeof(priv->secret), seed);

    sha3_256_shake(&hash_ctx, sizeof(aCid), aCid);

    ret = _gnutls_buffer_append_data(&buf, &aC_number, 1);
    if (ret < 0) {
        goto error;
    }

    ret = _gnutls_buffer_append_data_prefix(&buf, 16, aCid, ALLOWCREDENTIAL_ID_LENGTH);
    if (ret < 0) {
        goto error;
    }

    ret = _gnutls_buffer_append_data_prefix(&buf, 8, (void*) "public-key", strlen("public-key"));
    if (ret < 0) {
        goto error;
    }

    ret = _gnutls_buffer_append_data(&buf, &transports_number, 1);
    if (ret < 0) {
        goto error;
    }

    /* user verification */
    ret = _gnutls_buffer_append_data_prefix(&buf, 8, (void*) user_verification, strlen(user_verification));
    if (ret < 0) {
        goto error;
    }

    /* server share for ephemeral user name */
    ret = _gnutls13_fido2_set_eph_user_name_server_share(&buf, priv);
    if (ret < 0) {
        goto error;
    }


    mbuffer_st* bufel = _gnutls_buffer_to_mbuffer(&buf);
    ret = _gnutls_send_handshake(session, bufel, GNUTLS_HANDSHAKE_FIDO2_ASSERTION_REQUEST);
    
    _gnutls_buffer_clear(&buf);
    gnutls_free(seed);
    return ret;

    error:
        gnutls_assert();
        gnutls_free(seed);
        _gnutls_buffer_clear(&buf);
        return ret;
}

char *rand_string(char *str, size_t size)
{
    /* random base64url encoded challenge */
    const char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ-_0123456789";
    if (size) {
        --size;
        for (size_t n = 0; n < size; n++) {
            int key = rand() % (int) (sizeof charset -1);
            str[n] = charset[key];
        }
    }
    return str;
}
