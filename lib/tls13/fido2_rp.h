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