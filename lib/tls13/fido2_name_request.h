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

#ifndef GNUTLS_LIB_TLS13_FIDO2_NAME_REQUEST_H
#define GNUTLS_LIB_TLS13_FIDO2_NAME_REQUEST_H

#include "ext/fido2.h"

int _gnutls13_send_fido2_name_request(gnutls_session_t session, fido2_server_ext_st* priv);
int _gnutls13_recv_fido2_name_request(gnutls_session_t session, fido2_client_ext_st* priv);

#endif /* GNUTLS_LIB_TLS13_FIDO2_NAME_REQUEST_H */