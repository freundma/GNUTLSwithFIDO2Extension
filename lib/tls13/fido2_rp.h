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

#ifndef GNUTLS_LIB_TLS13_FIDO2_RP_H
#define GNUTLS_LIB_TLS13_FIDO2_RP_H

#include "gnutls_int.h"

int _gnutls13_fido2_rp_connect(gnutls_session_t *rp_session, const char *rp_ip, const char *rp_port,
                                gnutls_datum_t *rp_data, int *rp_sd, gnutls_certificate_credentials_t *rp_xcred);
int _gnutls13_fido2_rp_pack(gnutls_session_t *rp_session, gnutls_datum_t *rp_data, int *rp_sd);
void _gnutls13_fido2_rp_shutdown(gnutls_session_t *rp_session, int *rp_sd);
int tcp_connect(const char *ip, const char *port);
void tcp_close(int sd);

#endif /* GNUTLS_LIB_TLS13_FIDO2_RP_H */