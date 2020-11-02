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

#include <fido.h>
#include <string.h>
#include <stdio.h>
#include <termios.h> /* for obtaining pin */

fido_assert_t *assertion;

fido_dev_t *device;

int uV;

int fido_assert_init();

void fido_assert_deinit();

int fido_assert_add_allow_credential(const unsigned char *id, size_t len);

int fido_assert_setup(const unsigned char *client_data_hash, const char *rpid,
                    const char *user_verification, const char *authenticator_location);

int fido_assert_generate();

size_t fido_assert_get_authenticator_data_length();

int fido_assert_get_authenticator_data(unsigned char **auth_data);

size_t fido_assert_get_signature_length();

int fido_assert_get_signature(unsigned char **sig);

size_t fido_assert_get_user_handle_length();

int fido_assert_get_user_handle(unsigned char **user_handle);

size_t fido_assert_get_selected_credential_length();

int fido_assert_get_selected_credential(unsigned char **selected_credential);

void fido_assert_free_dev();

size_t get_pin (char **lineptr, size_t *n, FILE *stream)
{
  struct termios old, new;
  int nread;

  /* Turn echoing off and fail if we can’t. */
  if (tcgetattr(fileno (stream), &old) != 0)
    return -1;
  new = old;
  new.c_lflag &= ~ECHO;
  if (tcsetattr(fileno (stream), TCSAFLUSH, &new) != 0)
    return -1;

  /* Read the passphrase */
  nread = getline(lineptr, n, stream);

  /* Restore terminal. */
  (void) tcsetattr(fileno (stream), TCSAFLUSH, &old);

  return nread;
}
    

extern int fido_assert_init(void)
{
    fido_init(0);
    assertion = fido_assert_new();
    if (assertion == NULL) {
        return -1;
    }
    return 0;
}

extern void fido_assert_deinit(void)
{
    fido_assert_free(&assertion);
}

extern int fido_assert_add_allow_credential(const unsigned char *id, size_t len)
{
    int ret;

    ret = fido_assert_allow_cred(assertion, id, len);
    if (ret != FIDO_OK) {
        return -1;
    }

    return ret;
}

extern int fido_assert_setup(const unsigned char *client_data_hash, const char *rpid,
                                const char *user_verification, const char *authenticator_location)
{
    int ret;

    ret = fido_assert_set_clientdata_hash(assertion, client_data_hash, 32);
    if (ret != FIDO_OK) {
        return -1;
    }

    ret = fido_assert_set_rp(assertion, rpid);
    if (ret != FIDO_OK) {
        return -1;
    }

    if (strcmp(user_verification, "preferred") == 0 || strcmp(user_verification, "required") == 0){
        ret = fido_assert_set_uv(assertion, FIDO_OPT_TRUE);
        uV = 1;
    } else {
        ret = fido_assert_set_uv(assertion, FIDO_OPT_FALSE);
        uV = 0;
    }
    if (ret != FIDO_OK) {
        return -1;
    }

    return ret;
}

extern int fido_assert_generate(void)
{
    int ret;

    fido_dev_info_t *devlist;
    size_t ndevs;

    devlist = fido_dev_info_new(1);
    if (devlist == NULL) {
        return -1;
    }

    ret = fido_dev_info_manifest(devlist, 1, &ndevs);
    if (ret != FIDO_OK) {
        fido_dev_info_free(&devlist, ndevs);
        return -1;
    }

    fido_dev_info_t* di = fido_dev_info_ptr(devlist, 0);
    
    device = fido_dev_new();
    if (device == NULL) {
        fido_dev_info_free(&devlist, ndevs);
        return -1;
    }

    ret = fido_dev_open(device, fido_dev_info_path(di));
    fido_dev_info_free(&devlist, ndevs);
    if (ret != FIDO_OK) {
        return -1;
    }

    char* pin = NULL;
    if (uV == 1) {
        size_t n = 0;
        printf("PIN: ");
        size_t len = get_pin(&pin, &n, stdin);
        pin[len-1] = '\0';
        printf("\n");
    }
    
    ret = fido_dev_get_assert(device, assertion, pin);
    int ret2 = fido_dev_close(device);
    if (ret2 != FIDO_OK) {
        ret = ret2;
        goto end;
    }
    if (ret != FIDO_OK) {
        if (ret == FIDO_ERR_ACTION_TIMEOUT) {
            ret = -2;
            goto end;
        }
        ret = -1;
        goto end;
    }

    end: 
        if (uV == 1) {
            free(pin);
        }
        return ret;
}

extern size_t fido_assert_get_authenticator_data_length(void)
{
    return fido_assert_authdata_len(assertion, 0); 
}

extern int fido_assert_get_authenticator_data(unsigned char **auth_data)
{
    memcpy(*auth_data, fido_assert_authdata_ptr(assertion, 0), fido_assert_authdata_len(assertion, 0));
    if (*auth_data == NULL) {
        return -1;
    }

    return 0;
}

extern size_t fido_assert_get_signature_length(void)
{
    return fido_assert_sig_len(assertion, 0);
}

extern int fido_assert_get_signature(unsigned char **sig)
{
    memcpy(*sig, fido_assert_sig_ptr(assertion, 0), fido_assert_sig_len(assertion, 0));
    if (*sig == NULL) {
        return -1;
    }

    return 0;
}

extern size_t fido_assert_get_user_handle_length(void)
{
    return fido_assert_user_id_len(assertion, 0);
}

extern int fido_assert_get_user_handle(unsigned char **user_handle)
{
    memcpy(*user_handle, fido_assert_user_id_ptr(assertion, 0), fido_assert_user_id_len(assertion, 0));
    if (*user_handle == NULL) {
        return -1;
    }

    return 0;
}

extern void fido_assert_free_dev(void) 
{
    fido_dev_free(&device);
}

extern size_t fido_assert_get_selected_credential_length(void)
{
    return fido_assert_id_len(assertion, 0);
}

extern int fido_assert_get_selected_credential(unsigned char **selected_credential)
{
    memcpy(*selected_credential, fido_assert_id_ptr(assertion, 0), fido_assert_id_len(assertion, 0));
    if (*selected_credential == NULL) {
        return -1;
    }

    return 0;
}

    


