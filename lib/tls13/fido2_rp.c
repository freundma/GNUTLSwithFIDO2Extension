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

#include "tls13/fido2_rp.h"
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <unistd.h>

int _gnutls13_fido2_rp_connect(gnutls_session_t *rp_session, const char *rp_ip, const char *rp_port,
                                gnutls_datum_t *rp_data, int *rp_sd, gnutls_certificate_credentials_t *rp_xcred)
{
    int ret;

    ret = gnutls_init(rp_session, GNUTLS_CLIENT);
    if (ret < 0) {
        gnutls_assert();
        return ret;
    }

    ret = gnutls_certificate_allocate_credentials(rp_xcred);
    if (ret < 0) {
        gnutls_assert();
        return ret;
    }
    ret = gnutls_certificate_set_x509_system_trust(*rp_xcred);
    if (ret < 0) {
        gnutls_assert();
        gnutls_certificate_free_credentials(*rp_xcred);
        return ret;
    }

    ret = gnutls_set_default_priority(*rp_session);
    if (ret < 0) {
        gnutls_assert();
        gnutls_certificate_free_credentials(*rp_xcred);
        return ret;
    }

    ret = gnutls_credentials_set(*rp_session, GNUTLS_CRD_CERTIFICATE, *rp_xcred);
    if (ret < 0) {
        gnutls_assert();
        gnutls_certificate_free_credentials(*rp_xcred);
        return ret;
    }

    /* connect to rp server */
    *rp_sd = tcp_connect(rp_ip, rp_port);

    gnutls_transport_set_int(*rp_session, *rp_sd);
    gnutls_handshake_set_timeout(*rp_session,
                                    GNUTLS_DEFAULT_HANDSHAKE_TIMEOUT);

    if (rp_data) {
        ret = gnutls_session_set_data(*rp_session, rp_data->data,
                                        rp_data->size);
        if (ret < 0) {
            gnutls_assert();
            gnutls_certificate_free_credentials(*rp_xcred);
            return ret;
        }
        gnutls_free(rp_data->data);
    }
        
    /* Perform the TLS handshake */
    do {
        ret = gnutls_handshake(*rp_session);
    }
    while (ret < 0 && gnutls_error_is_fatal(ret) == 0);

    if (ret < 0) {
        gnutls_certificate_free_credentials(*rp_xcred);
        tcp_close(*rp_sd);
        gnutls_deinit(*rp_session);
    } 

    return ret;
}

int _gnutls13_fido2_rp_pack(gnutls_session_t *rp_session, gnutls_datum_t *rp_data, int *rp_sd)
{
    int ret;
    
    ret = gnutls_session_get_data2(*rp_session, rp_data);

    gnutls_bye(*rp_session, GNUTLS_SHUT_RDWR);
    tcp_close(*rp_sd);
    gnutls_deinit(*rp_session);

    return ret;
}

void _gnutls13_fido2_rp_shutdown(gnutls_session_t *rp_session, int *rp_sd)
{
    gnutls_bye(*rp_session, GNUTLS_SHUT_RDWR);
    tcp_close(*rp_sd);
    gnutls_deinit(*rp_session);
}

int tcp_connect(const char *ip, const char *port)
{
    int ret, sd;
    struct sockaddr_in sa;

    sd = socket(AF_INET, SOCK_STREAM, 0);

    memset(&sa, '\0', sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons(atoi(port));
    inet_pton(AF_INET, ip, &sa.sin_addr);

    ret = connect(sd, (struct sockaddr *) &sa, sizeof(sa));
    if (ret < 0) {
        return ret;
    }

    return sd;
}

void tcp_close(int sd)
{
    shutdown(sd, SHUT_RDWR);        
    close(sd);
}
