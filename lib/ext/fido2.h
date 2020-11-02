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

#ifndef GNUTLS_LIB_EXT_FIDO2_H
#define GNUTLS_LIB_EXT_FIDO2_H

#include <hello_ext.h>

#define SQL_QUERY_SELECT "SELECT Username, Expiration_time FROM Users WHERE Ephemeral_username = ?;"
#define SQL_QUERY_DELETE "DELETE FROM Users WHERE Ephemeral_username = ?;"
#define FREE(x) if (x) {gnutls_free(x);}

extern const hello_ext_entry_st ext_mod_fido2;

typedef struct {
	gnutls_fido2_mode_t mode;
	unsigned int entity;
	uint8_t eph_user_name_client_share[32];
	uint8_t eph_user_name[32];
	unsigned eph_user_name_set;
	unsigned assertion_set;
	char* username;
	char* server_domain;
	char* client_data_json;
} fido2_client_ext_st;

typedef struct {
	gnutls_fido2_mode_t mode;
	unsigned int entity;
	char* rpid;
	uint8_t secret[32];
	uint8_t eph_user_name_server_share[32];
	uint8_t eph_user_name[32];
	unsigned eph_user_name_set;
	char* username;
	char* user_id;
	char* rp_ip;
	char* rp_port;
	gnutls_session_t *rp_session;
	gnutls_datum_t rp_data;
	char* db_location;
	char* request_id;
	unsigned client_authenticated;
} fido2_server_ext_st;

#endif /* GNUTLS_LIB_EXT_FIDO2_H */