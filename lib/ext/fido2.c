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
#include <ext/fido2.h>
#include "errors.h"
#include <num.h>
#include <hello_ext.h>
#include <sqlite3.h>
#include <time.h>
#include "tls13/fido2_rp.h"

int _gnutls_fido2_recv_params(gnutls_session_t session,
					   const uint8_t * data,
					   size_t data_size);
int _gnutls_fido2_send_params(gnutls_session_t session,
					   gnutls_buffer_st * extdata);
int _gnutls_fido2_check_eph_user_name(gnutls_session_t session,
             fido2_server_ext_st * priv);
void _gnutls_fido2_deinit_data(gnutls_ext_priv_data_t epriv);
int _gnutls_fido2_pack(gnutls_ext_priv_data_t epriv, gnutls_buffer_st *ps);
int _gnutls_fido2_unpack(gnutls_buffer_st *ps, gnutls_ext_priv_data_t *epriv);


const hello_ext_entry_st ext_mod_fido2 = {
	.name = "FIDO2",
	.tls_id = 55,
	.gid = GNUTLS_EXTENSION_FIDO2,
	.client_parse_point = GNUTLS_EXT_TLS,
  .server_parse_point = GNUTLS_EXT_TLS,
	.validity = GNUTLS_EXT_FLAG_CLIENT_HELLO | GNUTLS_EXT_FLAG_TLS,
	.recv_func = _gnutls_fido2_recv_params,
	.send_func = _gnutls_fido2_send_params,
	.pack_func = _gnutls_fido2_pack, 
	.unpack_func = _gnutls_fido2_unpack, 
	.deinit_func = _gnutls_fido2_deinit_data, 
	.cannot_be_overriden = 1
};

/**
 * gnutls_fido2_set_client:
 * @session: is a #gnutls_session_t type
 * @name: is either a proper username, an ephemeral username or NULL in case of FI mode
 * @name_type: is the type of name
 * @server_domain: is the domain of the server to connect to
 * 
 * This function sets up the FIDO2 extension for the client. In the handshake the client will
 * send the FIDO2 client hello extension in order to authenticate itself via FIDO2. If you
 * want to use the FI mode you have to set @name to NULL and @name_type to NONE.
 * If you want to use the FN mode and have an ephemeral username you have to set @name up
 * with the pointer to the ephemeral username (usually uint8_t*) and set @name_type to
 * %GNUTLS_FIDO2_EPH_USER_NAME.
 * If you want to use FN mode and do not have an ephemeral username you set @name to the longterm
 * username (usually char*) and set @name_type to %GNUTLS_FIDO2_USER_NAME.
 * 
 * Returns: On success, %GNUTLS_E_SUCCESS (0) is returned, otherwise an error code is returned.
 **/ 
int
gnutls_fido2_set_client(gnutls_session_t session,
                  uint8_t* name,
                  gnutls_fido2_name_t name_type,
                  const char* server_domain)
{
  fido2_client_ext_st *priv;
  gnutls_ext_priv_data_t epriv;

  if (session->security_parameters.entity == GNUTLS_SERVER) {
    gnutls_assert();
    return GNUTLS_E_INVALID_REQUEST;
  }
	priv = gnutls_calloc(1, sizeof(*priv));
	if (priv == NULL) {
		gnutls_assert();
		return GNUTLS_E_MEMORY_ERROR;
	}
	epriv = priv;
		_gnutls_hello_ext_set_priv(session,
					     GNUTLS_EXTENSION_FIDO2, epriv);

  priv->entity = GNUTLS_CLIENT;
  
  priv->server_domain = gnutls_malloc(strlen(server_domain) + 1);
  if (priv->server_domain == NULL) {
    gnutls_assert();
    return GNUTLS_E_MEMORY_ERROR;
  }
  strcpy(priv->server_domain, server_domain);


  switch (name_type) {
    case NONE:
      priv->mode = GNUTLS_FIDO2_MODE_FI;
      return 0;
    case GNUTLS_FIDO2_EPH_USER_NAME:
      memcpy(priv->eph_user_name, name, 32);
      priv->mode = GNUTLS_FIDO2_MODE_FN;
      priv->eph_user_name_set = 1;
      return 0;
    case GNUTLS_FIDO2_USER_NAME:
      priv->mode = GNUTLS_FIDO2_MODE_FN;
      priv->username = gnutls_malloc(strlen((char*) name)+1);
      if (priv->username == NULL) {
        gnutls_assert();
        return GNUTLS_E_MEMORY_ERROR;
      }
      memcpy(priv->username, name, strlen((char*) name)+1);
      return 0;
    default:
      gnutls_assert();
      return GNUTLS_E_ILLEGAL_PARAMETER;
  }

}

/**
 * gnutls_fido2_set_server:
 * @session: is a #gnutls_session_t type
 * @config: is the configuration how to handle fido2 client hello extensions
 * @rp_session: is a pointer to #gnutls_session_t type
 * @rp_ip: is the ip of the WebAuthn server/ RP server
 * @rp_port: is the port of the WebAuthn server/ RP server
 * @db_location: is a path to a sqlite3 db
 * @rpid: is the RP-ID to be used for fido2 operations
 * @secret: is a secret (32 Bytes recommended)
 * 
 * This function will set up the server for the FIDO2 extension. The @config can be set
 * to #GNUTLS_FIDO2_CONFIG_DISABLED, #GNUTLS_FIDO2_CONFIG_ALLOWED and 
 * #GNUTLS_FIDO2_CONFIG_REQUIRED. If you choose to disable fido2 (it is disabled by default)
 * the other parameters can be ignored. The @secret is used for generating random allow credentials
 * if no user is registered under the provided username.
 * 
 * Returns: On success, %GNUTLS_E_SUCCESS (0) is returned, otherwise an error code is returned.
 **/
int gnutls_fido2_set_server(gnutls_session_t session, gnutls_fido2_config_t config,
								gnutls_session_t* rp_session, const char* rp_ip, const char* rp_port,
									const char* db_location, const char* rpid, const uint8_t *secret)
{
  if (session->security_parameters.entity == GNUTLS_CLIENT) {
    gnutls_assert();
    return GNUTLS_E_INVALID_REQUEST;
  }

  session->internals.fido2_config = config;

  if (session->internals.fido2_config >= GNUTLS_FIDO2_CONFIG_ALLOWED) { /* if allowed or even required */
    fido2_server_ext_st *priv;
    gnutls_ext_priv_data_t epriv;

    priv = gnutls_calloc(1, sizeof(*priv));
    if (priv == NULL) {
      gnutls_assert();
      return GNUTLS_E_MEMORY_ERROR;
    }

    epriv = priv;
    _gnutls_hello_ext_set_priv(session,
                GNUTLS_EXTENSION_FIDO2, epriv);

    priv->entity = GNUTLS_SERVER;
    
    /* set rp session */
    priv->rp_session = rp_session;

    /* set RP IP */
    priv->rp_ip = gnutls_malloc(strlen(rp_ip)+1);
    if (priv->rp_ip == NULL) {
      gnutls_assert();
      return GNUTLS_E_MEMORY_ERROR;
    }
    strcpy(priv->rp_ip, rp_ip);

    /* set RP Port */
    priv->rp_port = gnutls_malloc(strlen(rp_port)+1);
    if (priv->rp_port == NULL) {
      gnutls_assert();
      return GNUTLS_E_MEMORY_ERROR;
    }
    strcpy(priv->rp_port, rp_port);

    /* set location of db */
    priv->db_location = gnutls_malloc(strlen(db_location)+1);
    if (priv->db_location == NULL) {
      gnutls_assert();
      return GNUTLS_E_MEMORY_ERROR;
    }
    strcpy(priv->db_location, db_location);

    /* set RP-ID */
    priv->rpid = gnutls_malloc(strlen(rpid)+1);
    if (priv->rpid == NULL) {
      gnutls_assert();
      return GNUTLS_E_MEMORY_ERROR;
    }
    strcpy(priv->rpid, rpid);

    /* set secret */
    memcpy(priv->secret, secret, 32);

    
  }

  return 0;
}

int 
_gnutls_fido2_recv_params (gnutls_session_t session,
                            const uint8_t * data,
                            size_t data_size)
{
  uint8_t *eph_user_name;
  uint8_t flags;
  int ret;
  if (session->security_parameters.entity == GNUTLS_SERVER){
    if (session->internals.fido2_config == GNUTLS_FIDO2_CONFIG_DISABLED) {
      return 0; /* ignore */
    }

    if (data_size > 0) {
      fido2_server_ext_st *priv;
      gnutls_ext_priv_data_t epriv;

      ret = _gnutls_hello_ext_get_priv(session, GNUTLS_EXTENSION_FIDO2, &epriv);
      if (ret < 0){
        return 0;
      }
      priv = epriv;

      uint8_t flags = data[0];
      DECR_LEN(data_size, 1);
      data++;

      if (flags & GNUTLS_FIDO2_MODE_FI) {
        priv->mode = GNUTLS_FIDO2_MODE_FI;
        session->internals.fido2_status = GNUTLS_FIDO2_STATUS_ACTIVE;
        return 0;
      } else if (flags & GNUTLS_FIDO2_MODE_FN) {
        priv->mode = GNUTLS_FIDO2_MODE_FN;
        session->internals.fido2_status = GNUTLS_FIDO2_STATUS_ACTIVE;
      } else {
        return gnutls_assert_val(GNUTLS_E_ILLEGAL_PARAMETER);
      }

      if (flags & GNUTLS_FIDO2_EPH_USER_NAME_GIVEN) {
        if (data_size != 32){
          return gnutls_assert_val(GNUTLS_E_UNEXPECTED_PACKET_LENGTH);
        }
        eph_user_name = data;
        memcpy(priv->eph_user_name, eph_user_name, 32);

        ret = _gnutls_fido2_check_eph_user_name(session, priv);
        if (ret < 0) {
          gnutls_assert();
          return ret;
        }

        priv->eph_user_name_set = 1;
        return 0;
      }
    }
    return 0;
  } else {
    return 0; /* ignore */
  }
    
}

int
_gnutls_fido2_check_eph_user_name(gnutls_session_t session,
                                    fido2_server_ext_st * priv)
{
  int ret;
  sqlite3* db;
  sqlite3_stmt* res_select;
  sqlite3_stmt* res_delete;

  ret = sqlite3_open(priv->db_location, &db);
  if (ret != SQLITE_OK) {
    gnutls_assert();
    return GNUTLS_E_INTERNAL_ERROR;
  }

  ret = sqlite3_prepare_v2(db, SQL_QUERY_SELECT, -1, &res_select, NULL);
  if (ret != SQLITE_OK) {
       goto error;
  }

  ret = sqlite3_prepare_v2(db, SQL_QUERY_DELETE, -1, &res_delete, NULL);
  if (ret != SQLITE_OK) {
       sqlite3_finalize(res_select);
       goto error;
  }

  ret = sqlite3_bind_blob(res_select, 1, (void*) priv->eph_user_name, sizeof(priv->eph_user_name), SQLITE_STATIC);
  if (ret != SQLITE_OK) {
      sqlite3_finalize(res_select);
      sqlite3_finalize(res_delete);
      goto error;
  }

  ret = sqlite3_step(res_select);
  if (ret == SQLITE_ROW) {
    priv->username = gnutls_malloc(sqlite3_column_bytes(res_select, 0)+1);
    if (priv->username == NULL) {
      sqlite3_close(db);
      gnutls_assert();
      return GNUTLS_E_MEMORY_ERROR;
    }

    strcpy(priv->username, sqlite3_column_text(res_select, 0));

    ret = sqlite3_bind_blob(res_delete, 1, (void*) priv->eph_user_name, sizeof(priv->eph_user_name), SQLITE_STATIC);
    if (ret != SQLITE_OK) {
      sqlite3_finalize(res_select);
      sqlite3_finalize(res_delete);
      goto error;
    }

    time_t expiration_time = (time_t) sqlite3_column_int64(res_select, 1);
    sqlite3_finalize(res_select);
    time_t current_time;
    time(&current_time);
    if (current_time > expiration_time) {
      ret = sqlite3_step(res_delete);
      if (ret != SQLITE_DONE) {
        sqlite3_finalize(res_delete);
        goto error;
      }
      goto alert; /* ephemeral username expired */
    }
    ret = sqlite3_step(res_delete);
    if (ret != SQLITE_DONE) {
      sqlite3_finalize(res_delete);
      goto error;
    }

    sqlite3_finalize(res_delete);
    sqlite3_close(db);
    memset(priv->eph_user_name, 0, 32);
    return 0;

  } else {
    sqlite3_finalize(res_select);
    goto alert; /* ephemeral username not stored */
  }

  error:
    sqlite3_close(db);
    gnutls_assert();
    return GNUTLS_E_INTERNAL_ERROR;
  alert:
    sqlite3_finalize(res_delete);
    sqlite3_close(db);
    ret = gnutls_alert_send(session, GNUTLS_AL_FATAL, GNUTLS_A_FIDO2_BAD_REQUEST);
    gnutls_assert();
    if (ret < 0) {
      return ret;
    }
    return GNUTLS_E_FIDO2_BAD_REQUEST;
    
}

int
_gnutls_fido2_send_params (gnutls_session_t session,
                            gnutls_buffer_st * extdata)
{
  int ret;
  fido2_client_ext_st *priv;
  gnutls_ext_priv_data_t epriv;

  ret = _gnutls_hello_ext_get_priv(session, GNUTLS_EXTENSION_FIDO2, &epriv);
  if (ret < 0){
    return 0;
  }
  priv = epriv;

  if (session->security_parameters.entity == GNUTLS_CLIENT){
    /* set flags */
    uint8_t flags;

    flags = priv->mode;
    if (priv->eph_user_name_set == 1) {
      flags = flags | GNUTLS_FIDO2_EPH_USER_NAME_GIVEN;
    }

    /* append to extdata */
    ret = _gnutls_buffer_append_data(extdata, &flags, 1);
    if (ret < 0){
      return gnutls_assert_val(ret);
    }

    if (priv->eph_user_name_set == 1) {
      ret = _gnutls_buffer_append_data(extdata, priv->eph_user_name, 32);
      if ( ret < 0) {
        return gnutls_assert_val(ret);
      } 
    }
    
    session->internals.fido2_status = GNUTLS_FIDO2_STATUS_ACTIVE;
    return 1;
  } else {
    return 0; /* server functionality only */
  }  
}

/**
 * gnutls_fido2_active:
 * @session: is a #gnutls_session_t type
 * 
 * Returns: Returns %true if FIDO2 is used/ was used for authentication in this @session,
 * otherwise %false.
 **/
bool gnutls_fido2_active(gnutls_session_t session)
{
  return session->internals.fido2_status == GNUTLS_FIDO2_STATUS_ACTIVE;
}

/**
 * gnutls_fido2_client_authenticated:
 * @session: is a #gnutls_session_t type
 * 
 * This function can be used to check whether the client could get authenticated within
 * the @session.
 * 
 * Returns: If yes %GNUTLS_E_SUCCESS (0) is returned, otherwise -1 is returned.
 * On an error a negative error code is returned.
 **/
int gnutls_fido2_client_authenticated(gnutls_session_t session)
{
  if (session->security_parameters.entity == GNUTLS_CLIENT) {
    gnutls_assert();
    return GNUTLS_E_INVALID_REQUEST;
  }

  int ret = 0;

  fido2_server_ext_st *priv;
  gnutls_ext_priv_data_t epriv;

  ret = _gnutls_hello_ext_get_priv(session, GNUTLS_EXTENSION_FIDO2, &epriv);
  if (ret < 0) {
    gnutls_assert();
    return GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE;
  }

  priv = epriv;

  if (priv->client_authenticated == 1) {
    return 0;
  }

  return -1;
}

/**
 * gnutls_fido2_get_eph_user_name:
 * @session: is a #gnutls_session_t type
 * @eph_user_name: is a #uint8_t* pointer of at least 32 Bytes
 * 
 * This function stores the negotiated ephemeral username in @eph_user_name. You should only
 * use this function when FIDO2 is active and after the handshake is finished.
 * 
 * Returns: On success, %GNUTLS_E_SUCCESS (0) is returned, otherwise an error code is returned.
 **/
int gnutls_fido2_get_eph_user_name(gnutls_session_t session, uint8_t* eph_user_name)
{
  if (session->security_parameters.entity == GNUTLS_SERVER) {
    gnutls_assert();
    return GNUTLS_E_INVALID_REQUEST;
  }

  int ret = 0;

  fido2_client_ext_st *priv;
  gnutls_ext_priv_data_t epriv;

  ret = _gnutls_hello_ext_get_priv(session, GNUTLS_EXTENSION_FIDO2, &epriv);
  if (ret < 0) {
    gnutls_assert();
    return GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE;
  }

  priv = epriv;

  memcpy(eph_user_name, priv->eph_user_name, 32);

  return ret;
}

/**
 * gnutls_fido2_generate_secret:
 * @secret: is a #uint8_t* pointer of at least 32 Bytes
 * 
 * This function can be used to generate a 32 Byte random secret and store it in
 * @secret.
 * 
 * Returns: On success, %GNUTLS_E_SUCCESS (0) is returned, otherwise an error code is returned.
 **/
int gnutls_fido2_generate_secret(uint8_t* secret)
{
  return (gnutls_rnd(GNUTLS_RND_RANDOM, (void*) secret, 32));
}

/**
 * gnutls_fido2_get_auth_info:
 * @session: is a #gnutls_session_t type
 * 
 * This function returns authentication information and returns it as a pointer to
 * #gnutls_fido2_info_t.
 * 
 * Returns: On success, the #gnutls_fido2_info_t* is returned, otherwise NULL is returned.
 **/
gnutls_fido2_info_t * gnutls_fido2_get_auth_info(gnutls_session_t session)
{
  int ret;
  gnutls_fido2_info_t* info;
  if (session->security_parameters.entity == GNUTLS_CLIENT) {
    gnutls_assert();
    return NULL;
  }

  fido2_server_ext_st *priv;
  gnutls_ext_priv_data_t epriv;

  ret = _gnutls_hello_ext_get_priv(session, GNUTLS_EXTENSION_FIDO2, &epriv);
  if (ret < 0) {
    gnutls_assert();
    return NULL;
  }

  priv = epriv;

  if (priv->client_authenticated != 1) {
    gnutls_assert();
    return NULL;
  }

  info = gnutls_calloc(1, sizeof(*info));
  if (info == NULL) {
    gnutls_assert();
    return NULL;
  }

  info->mode = priv->mode;

  info->user_id = gnutls_malloc(strlen(priv->user_id)+1);
  if (info->user_id == NULL) {
    gnutls_assert();
    return NULL;
  }
  strcpy(info->user_id, priv->user_id);

  info->request_id = gnutls_malloc(strlen(priv->request_id)+1);
  if (info->request_id == NULL) {
    gnutls_assert();
    return NULL;
  }
  strcpy(info->request_id, priv->request_id);

  return info;

}

/**
 * gnutls_fido2_deinit_auth_info:
 * @info: is a pointer to a #gnutls_session_t type
 * 
 * This function deallocates the authentication info.
 **/
void gnutls_fido2_deinit_auth_info(gnutls_fido2_info_t* info)
{
  gnutls_free(info->user_id);
  gnutls_free(info->request_id);
  gnutls_free(info);
}

/**
 * gnutls_fido2_perform_handshake:
 * @session: is a pointer to #gnutls_session_t type
 * @name: is either a proper username, an ephemeral username or NULL in case of FI mode
 * @name_type: is the type of name
 * @server_domain: is the domain of the server to connect to
 * @sd: is a pointer to a socket descriptor
 * @ip: is the ip of the server to connect to
 * @port: is the port to the server to connect to
 * @verify_cert: is a flag whether the server certificate shall be verified
 * 
 * This function performs the single or doubled handshake for the client and
 * can be seen as a wrapper for better usibility. Certificate credentials are 
 * allocated for the handshake in order unlock the (ec)dhe-groups and be able
 * to verifiy the server certificate. The authentication is done via FIDO2 (if
 * the server allows it). If @verifiy_cert is set to a value !0, the certificate of the server
 * will get verified.
 * 
 * Returns: On success, %GNUTLS_E_SUCCESS (0) is returned, otherwise
 * an error code is returned.
 **/
int gnutls_fido2_perform_handshake(gnutls_session_t *session, uint8_t* name,
                                    gnutls_fido2_name_t name_type, const char* server_domain,
                                      int* sd, const char* ip, const char* port, int verify_cert)
{
  int ret;
  gnutls_certificate_credentials_t xcred;

  ret = gnutls_certificate_allocate_credentials(&xcred);
  if (ret < 0) {
    gnutls_assert();
    return ret;
  }

  ret = gnutls_certificate_set_x509_system_trust(xcred);
  if (ret < 0) {
    gnutls_assert();
    goto end;
  }

  /* default priorities */
  ret = gnutls_set_default_priority(*session);
  if (ret < 0) {
    gnutls_assert();
    goto end;
  }

  /* x509 credentials for (ec)dh-groups and gaining the eventual server cert */
  ret = gnutls_credentials_set(*session, GNUTLS_CRD_CERTIFICATE, xcred);
  if (ret < 0) {
    gnutls_assert();
    goto end;
  }

  if (verify_cert) {
    ret = gnutls_server_name_set(*session, GNUTLS_NAME_DNS,
                                  server_domain, strlen(server_domain));
    if (ret < 0) {
      gnutls_assert();
      goto end;
    }

    gnutls_session_set_verify_cert(*session, server_domain, 0);
  }


  *sd = tcp_connect(ip, port);
  if (*sd  < 0) {
    ret = GNUTLS_E_SOCKETS_INIT_ERROR;
    gnutls_assert();
    goto end;
  }

  gnutls_transport_set_int(*session, *sd);
  gnutls_handshake_set_timeout(*session, GNUTLS_DEFAULT_HANDSHAKE_TIMEOUT);

  ret = gnutls_fido2_set_client(*session, name, name_type, server_domain);
  if (ret < 0) {
    gnutls_assert();
    goto end;
  }

  do {
    ret = gnutls_handshake(*session);
  }
  while (ret < 0 && gnutls_error_is_fatal(ret) == 0);
  if (ret < 0) {
    gnutls_assert();
    goto end;
  }

  if (name_type == GNUTLS_FIDO2_USER_NAME && gnutls_fido2_active(*session)) {
    uint8_t* eph_user_name = gnutls_malloc(32);
    if (eph_user_name == NULL) {
      gnutls_assert();
      ret = GNUTLS_E_MEMORY_ERROR;
      goto end;
    }
    ret = gnutls_fido2_get_eph_user_name(*session, eph_user_name);
    if (ret < 0) {
      gnutls_free(eph_user_name);
      gnutls_assert();
      goto end;
    }

    ret = gnutls_bye(*session, GNUTLS_SHUT_RDWR);
    if (ret < 0) {
      gnutls_free(eph_user_name);
      gnutls_assert();
      goto end;
    }
    tcp_close(*sd);
    gnutls_deinit(*session);

    gnutls_session_t new_session;
    *session = new_session;

    ret = gnutls_init(session, GNUTLS_CLIENT);
    if (ret < 0) {
      gnutls_free(eph_user_name);
      gnutls_assert();
      goto end;
    }

    ret = gnutls_set_default_priority(*session);
    if (ret < 0) {
      gnutls_free(eph_user_name);
      gnutls_assert();
      goto end;
    }

    ret = gnutls_credentials_set(*session, GNUTLS_CRD_CERTIFICATE, xcred);
    if (ret < 0) {
      gnutls_free(eph_user_name);
      gnutls_assert();
      goto end;
    }

    if (verify_cert) {
      ret = gnutls_server_name_set(*session, GNUTLS_NAME_DNS,
                                    server_domain, strlen(server_domain));
      if (ret < 0) {
        gnutls_assert();
        goto end;
      }

      gnutls_session_set_verify_cert(*session, server_domain, 0);
    }
    
    /* FIDO2 */
    gnutls_fido2_set_client(*session, eph_user_name, GNUTLS_FIDO2_EPH_USER_NAME, server_domain);
    gnutls_free(eph_user_name);

    *sd = tcp_connect(ip, port);
    if (*sd < 0) {
      ret = GNUTLS_E_SOCKETS_INIT_ERROR;
      gnutls_assert();
      goto end;
    }

    gnutls_transport_set_int(*session, *sd);
    gnutls_handshake_set_timeout(*session, GNUTLS_DEFAULT_HANDSHAKE_TIMEOUT);

    do {
      ret = gnutls_handshake(*session);
    }
    while (ret < 0 && gnutls_error_is_fatal(ret) == 0);
    if (ret < 0) {
      gnutls_assert();
      goto end;
    }
  }

  end:
    gnutls_certificate_free_credentials(xcred);
    return ret;
}


void _gnutls_fido2_deinit_data (gnutls_ext_priv_data_t epriv)
{
  fido2_server_ext_st* priv_server = epriv;
  fido2_client_ext_st* priv_client = epriv;

  if (priv_server->entity == GNUTLS_SERVER) {
    FREE(priv_server->rpid);
    FREE(priv_server->username);
    FREE(priv_server->user_id);
    FREE(priv_server->rp_ip);
    FREE(priv_server->rp_port);
    FREE(priv_server->rp_data.data);
    FREE(priv_server->db_location);
    FREE(priv_server->request_id);
    gnutls_free(priv_server);
  } else {
    FREE(priv_client->username);
    FREE(priv_client->server_domain);
    FREE(priv_client->client_data_json);
    gnutls_free(priv_client);
  }
}

int _gnutls_fido2_pack(gnutls_ext_priv_data_t epriv, gnutls_buffer_st *ps)
{
  fido2_server_ext_st* priv_server = epriv;
  fido2_client_ext_st* priv_client = epriv;
  int ret;

  if (!priv_server->entity) {
    return 0;
  }

  if (priv_server->entity == GNUTLS_SERVER) {
    ret = _gnutls_buffer_append_data(ps, (void*) &priv_server->entity, sizeof(unsigned int));
    if (ret < 0) {
      goto error;
    }
    ret = _gnutls_buffer_append_data(ps, (void*) &priv_server->mode, sizeof(gnutls_fido2_mode_t));
    if (ret < 0) {
      goto error;
    }
    ret = _gnutls_buffer_append_data_prefix(ps, 8, (void*) priv_server->user_id, strlen(priv_server->user_id)+1);
    if (ret < 0) {
      goto error;
    }
    ret = _gnutls_buffer_append_data_prefix(ps, 8, (void*) priv_server->request_id, strlen(priv_server->request_id)+1);
    if (ret < 0) {
      goto error;
    }
  } else {
    ret = _gnutls_buffer_append_data(ps, (void*) &priv_client->entity, sizeof(unsigned int));
    if (ret < 0) {
      goto error;
    }
  }

  error:
    gnutls_assert();
    return ret;
}

int _gnutls_fido2_unpack(gnutls_buffer_st *ps, gnutls_ext_priv_data_t *epriv) {
  fido2_server_ext_st* priv;
  unsigned int entity;
  size_t length;

  if (ps->length < 32) {
    return 0;
  }

  entity = _gnutls_read_uint32(ps->data);
  DECR_LEN(ps->length, 4);
  ps->data += 4;

  if (entity == GNUTLS_SERVER) {
    priv = gnutls_calloc(1, sizeof(*priv));
    if (priv == NULL) {
      gnutls_assert();
      return GNUTLS_E_MEMORY_ERROR;
    }
    priv->client_authenticated = 1;

    /* entity */
    priv->entity = entity;

    /* fido2 mode */
    priv->mode = _gnutls_read_uint32(ps->data);
    DECR_LEN(ps->length, 4);
    ps->data += 4;

    /* user_id */
    length = ps->data[0];
    DECR_LEN(ps->length, 1);
    ps->data++;

    priv->user_id = gnutls_malloc(length);
    if (priv->user_id == NULL) {
      gnutls_assert();
      return GNUTLS_E_MEMORY_ERROR;
    }
    memcpy(priv->user_id, ps->data, length);
    DECR_LEN(ps->length, length);
    ps->data += length;

    /*request id*/
    length = ps->data[0];
    DECR_LEN(ps->length, 1);
    ps->data++;

    priv->request_id = gnutls_malloc(length);
    if (priv->request_id == NULL) {
      gnutls_assert();
      return GNUTLS_E_MEMORY_ERROR;
    }
    memcpy(priv->request_id, ps->data, length);
    DECR_LEN(ps->length, length);
    ps->data += length;

    epriv = priv;
    return 0;
  } else {
    return 0;
  }
}
