/* This example code is placed in the public domain. */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <string.h>
#include <unistd.h>
#include <gnutls/gnutls.h>
#include <assert.h>
#include <stdbool.h>
#include <signal.h>

#define KEYFILE "/home/mario/GNUTls/gnutls/tests/suite/tls-fuzzer/tlsfuzzer/tests/serverX509Key.pem"
#define CERTFILE "/home/mario/GNUTls/gnutls/tests/suite/tls-fuzzer/tlsfuzzer/tests/serverX509Cert.pem"
#define CAFILE "/etc/ssl/certs/ca-certificates.crt"
#define CRLFILE "/home/mario/GNUTls/gnutls/devel/openssl/test/testcrl.pem"

#define CHECK(x) assert((x)>=0)
#define LOOP_CHECK(rval, cmd) \
        do { \
                rval = cmd; \
        } while(rval == GNUTLS_E_AGAIN || rval == GNUTLS_E_INTERRUPTED)

/* The OCSP status file contains up to date information about revocation
 * of the server's certificate. That can be periodically be updated
 * using:
 * $ ocsptool --ask --load-cert your_cert.pem --load-issuer your_issuer.pem
 *            --load-signer your_issuer.pem --outfile ocsp-status.der
 */
//#define OCSP_STATUS_FILE "ocsp-status.der"

/* This is a sample TLS 1.0 echo server, using X.509 authentication and
 * OCSP stapling support.
 */

#define MAX_BUF 1024
#define LISTEN_PORT 5556               /* listen to 5556 port */
#define RP_IP "127.0.0.1"        /* ip address of rp server */
#define RP_PORT "8443"            /* port of rp server */

int main(void)
{
        int listen_sd;
        int sd, ret;
        gnutls_certificate_credentials_t x509_cred;
        gnutls_priority_t priority_cache;
        struct sockaddr_in sa_serv;
        struct sockaddr_in sa_cli;
        socklen_t client_len;
        char topbuf[512];
        gnutls_session_t session;
        gnutls_session_t rp_session;
        int rp_sd;
        char buffer[MAX_BUF + 1];
        int optval = 1;
        uint8_t secret[32];

        /* for backwards compatibility with gnutls < 3.3.0 */
        CHECK(gnutls_global_init());

        /*gnutls_global_set_log_level(10);
        gnutls_global_set_log_function(&logging);*/

        CHECK(gnutls_certificate_allocate_credentials(&x509_cred));

        CHECK(gnutls_certificate_set_x509_trust_file(x509_cred, CAFILE,
                                                     GNUTLS_X509_FMT_PEM));

        CHECK(gnutls_certificate_set_x509_crl_file(x509_cred, CRLFILE,
                                                   GNUTLS_X509_FMT_PEM));

        /* The following code sets the certificate key pair as well as, 
         * an OCSP response which corresponds to it. It is possible
         * to set multiple key-pairs and multiple OCSP status responses
         * (the latter since 3.5.6). See the manual pages of the individual
         * functions for more information.
         */
        CHECK(gnutls_certificate_set_x509_key_file(x509_cred, CERTFILE,
                                                   KEYFILE,
                                                   GNUTLS_X509_FMT_PEM));

        /*CHECK(gnutls_certificate_set_ocsp_status_request_file(x509_cred,
                                                              OCSP_STATUS_FILE,
                                                              0));*/

        CHECK(gnutls_priority_init(&priority_cache, NULL, NULL));
        /* Instead of the default options as shown above one could specify
         * additional options such as server precedence in ciphersuite selection
         * as follows:
         * gnutls_priority_init2(&priority_cache,
         *                       "%SERVER_PRECEDENCE",
         *                       NULL, GNUTLS_PRIORITY_INIT_DEF_APPEND);
	 */
        /*CHECK(gnutls_priority_init2(&priority_cache,
                                        "-ECDHE-PSK:-DHE-PSK:-PSK",
                                        NULL, GNUTLS_PRIORITY_INIT_DEF_APPEND));*/

#if GNUTLS_VERSION_NUMBER >= 0x030506
        /* only available since GnuTLS 3.5.6, on previous versions see
         * gnutls_certificate_set_dh_params(). */
        gnutls_certificate_set_known_dh_params(x509_cred, GNUTLS_SEC_PARAM_MEDIUM);
#endif

        /* Socket operations
         */
        listen_sd = socket(AF_INET, SOCK_STREAM, 0);

        memset(&sa_serv, '\0', sizeof(sa_serv));
        sa_serv.sin_family = AF_INET;
        sa_serv.sin_addr.s_addr = INADDR_ANY;
        sa_serv.sin_port = htons(LISTEN_PORT); /* Server Port number */

        setsockopt(listen_sd, SOL_SOCKET, SO_REUSEADDR, (void *) &optval,
                   sizeof(int));

        bind(listen_sd, (struct sockaddr *) &sa_serv, sizeof(sa_serv));

        listen(listen_sd, 1024);

        /* establish rp session */

        printf("Server ready. Listening to port '%d'.\n\n", LISTEN_PORT);

        CHECK(gnutls_fido2_generate_secret(secret));

        client_len = sizeof(sa_cli);
        for (;;) {
                CHECK(gnutls_init(&session, GNUTLS_SERVER));
                CHECK(gnutls_priority_set(session, priority_cache));
                CHECK(gnutls_credentials_set(session, GNUTLS_CRD_CERTIFICATE,
                                             x509_cred));

                /* We don't request any certificate from the client.
                 * If we did we would need to verify it. One way of
                 * doing that is shown in the "Verifying a certificate"
                 * example.
                 */
                gnutls_certificate_server_set_request(session,
                                                      GNUTLS_CERT_IGNORE);
                gnutls_handshake_set_timeout(session,
                                             GNUTLS_DEFAULT_HANDSHAKE_TIMEOUT);
                /* FIDO2 */
                CHECK(gnutls_fido2_set_server(session, GNUTLS_FIDO2_CONFIG_REQUIRED, &rp_session, RP_IP, RP_PORT,
                                                "user.db", "localhost", secret)); 

                sd = accept(listen_sd, (struct sockaddr *) &sa_cli,
                            &client_len);

                printf("- connection from %s, port %d\n",
                       inet_ntop(AF_INET, &sa_cli.sin_addr, topbuf,
                                 sizeof(topbuf)), ntohs(sa_cli.sin_port));

                gnutls_transport_set_int(session, sd);

                LOOP_CHECK(ret, gnutls_handshake(session));
                if (ret < 0) {
                        close(sd);
                        gnutls_deinit(session);
                        fprintf(stderr,
                                "*** Handshake has failed (%s)\n\n",
                                gnutls_strerror(ret));
                        continue;
                }
                printf("- Handshake was completed\n");

                if (gnutls_fido2_active(session) && gnutls_fido2_client_authenticated(session) < 0) {
                    goto end;
                }

                gnutls_fido2_info_t* auth_info = gnutls_fido2_get_auth_info(session);
                printf("- Client authenticated using FIDO2:\n");
                if (auth_info->mode == GNUTLS_FIDO2_MODE_FI) {
                        printf("  -- mode: FI\n");
                } else {
                        printf("  -- mode: FN\n");
                }
                printf("  -- user ID: %s\n", auth_info->user_id);
                printf("  -- request ID: %s\n", auth_info->request_id);

                gnutls_fido2_deinit_auth_info(auth_info);

                /* see the Getting peer's information example */
                /* print_info(session); */

                for (;;) {
                        LOOP_CHECK(ret, gnutls_record_recv(session, buffer, MAX_BUF));

                        if (ret == 0) {
                                printf
                                    ("\n- Peer has closed the GnuTLS connection\n");
                                break;
                        } else if (ret < 0
                                   && gnutls_error_is_fatal(ret) == 0) {
                                fprintf(stderr, "*** Warning: %s\n",
                                        gnutls_strerror(ret));
                        } else if (ret < 0) {
                                fprintf(stderr, "\n*** Received corrupted "
                                        "data(%d). Closing the connection.\n\n",
                                        ret);
                                break;
                        } else if (ret > 0) {
                                /* echo data back to the client
                                 */
                                CHECK(gnutls_record_send(session, buffer, ret));
                        }
                }
                printf("\n");
                /* do not wait for the peer to close the connection.
                 */

                end:
                    LOOP_CHECK(ret, gnutls_bye(session, GNUTLS_SHUT_WR));
  
                    close(sd);
                    gnutls_deinit(session);

        }
        absolute_end:
                close(listen_sd);

                gnutls_certificate_free_credentials(x509_cred);
                gnutls_priority_deinit(priority_cache);

                gnutls_global_deinit();

                return 0;

}