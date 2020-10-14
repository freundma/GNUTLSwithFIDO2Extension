/* This example code is placed in the public domain. */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <assert.h>
#include <gnutls/gnutls.h>

/* A very basic TLS client, with FIDO2 authentication.
 */

#define CHECK(x) assert((x)>=0)
#define LOOP_CHECK(rval, cmd) \
        do { \
                rval = cmd; \
        } while(rval == GNUTLS_E_AGAIN || rval == GNUTLS_E_INTERRUPTED); \
        assert(rval >= 0)

#define MAX_BUF 1024
#define MSG "GET / HTTP/1.0\r\n\r\n"

extern int tcp_connect(const char *SERVER, const char *PORT);
extern void tcp_close(int sd);

void logging (int level, const char* message) {
        printf("Level: %i, Message: %s \n",level,message);
}

int main(void)
{
        int ret, sd, ii;
        gnutls_session_t session;
        char buffer[MAX_BUF + 1];
        const char *err;

        if (gnutls_check_version("3.6.3") == NULL) {
                fprintf(stderr, "GnuTLS 3.6.3 or later is required for this example\n");
                exit(1);
        }

        CHECK(gnutls_global_init());

        /* LOG */
        /*gnutls_global_set_log_level(10);
        gnutls_global_set_log_function(&logging);*/

        /* Initialize TLS session
         */
        CHECK(gnutls_init(&session, GNUTLS_CLIENT));
        
        /* Perform TFE-Handshake:
         * Executes the simpel or doubled handshake with default priorities.
         * To unlock the (ec)dhe groups for the handshake certificate credentials are
         * allocated within the function. The authentication is done via FIDO2 though!
         * Note that this is only a wrapper to improve usibility. In fido2.c you can
         * change it in any way you want. In this case be aware that PSK authentication is
         * only allowed in the first handshake in FN mode.
         */
        ret = gnutls_fido2_perform_handshake(&session, NULL, NONE,
                                        "localhost", &sd, "127.0.0.1", "5556", 0);

        if (ret < 0) {
                fprintf(stderr, "*** Handshake failed\n");
                gnutls_perror(ret);
                goto end;
        } else {
                char *desc;

                desc = gnutls_session_get_desc(session);
                printf("- Session info: %s\n", desc);
                gnutls_free(desc);
        }

        LOOP_CHECK(ret, gnutls_record_send(session, MSG, strlen(MSG)));

        LOOP_CHECK(ret, gnutls_record_recv(session, buffer, MAX_BUF));
        if (ret == 0) {
                printf("- Peer has closed the TLS connection\n");
                goto end;
        } else if (ret < 0 && gnutls_error_is_fatal(ret) == 0) {
                fprintf(stderr, "*** Warning: %s\n", gnutls_strerror(ret));
        } else if (ret < 0) {
                fprintf(stderr, "*** Error: %s\n", gnutls_strerror(ret));
                goto end;
        }

        if (ret > 0) {
                printf("- Received %d bytes: ", ret);
                for (ii = 0; ii < ret; ii++) {
                        fputc(buffer[ii], stdout);
                }
                fputs("\n", stdout);
        }

        CHECK(gnutls_bye(session, GNUTLS_SHUT_RDWR));

      end:
      
        tcp_close(sd);

        gnutls_deinit(session);

        gnutls_global_deinit();

        return 0;
}
