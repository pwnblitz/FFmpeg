/*
 * HTTP authentication
 * Copyright (c) 2010 Martin Storsjo
 *
 * This file is part of FFmpeg.
 *
 * FFmpeg is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * FFmpeg is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with FFmpeg; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include "httpauth.h"
#include "libavutil/base64.h"
#include "libavutil/avstring.h"
#include "libavutil/mem.h"
#include "internal.h"
#include "libavutil/random_seed.h"
#include "libavutil/md5.h"
#include "libavutil/sha.h"
#include "libavutil/sha512.h"
#include "urldecode.h"

static void handle_basic_params(HTTPAuthState *state, const char *key,
                                int key_len, char **dest, int *dest_len)
{
    if (!strncmp(key, "realm=", key_len)) {
        *dest     =        state->realm;
        *dest_len = sizeof(state->realm);
    }
}

static void handle_digest_params(HTTPAuthState *state, const char *key,
                                 int key_len, char **dest, int *dest_len)
{
    DigestParams *digest = &state->digest_params;

    if (!strncmp(key, "realm=", key_len)) {
        *dest     =        state->realm;
        *dest_len = sizeof(state->realm);
    } else if (!strncmp(key, "nonce=", key_len)) {
        *dest     =        digest->nonce;
        *dest_len = sizeof(digest->nonce);
    } else if (!strncmp(key, "opaque=", key_len)) {
        *dest     =        digest->opaque;
        *dest_len = sizeof(digest->opaque);
    } else if (!strncmp(key, "algorithm=", key_len)) {
        *dest     =        digest->algorithm;
        *dest_len = sizeof(digest->algorithm);
    } else if (!strncmp(key, "qop=", key_len)) {
        *dest     =        digest->qop;
        *dest_len = sizeof(digest->qop);
    } else if (!strncmp(key, "stale=", key_len)) {
        *dest     =        digest->stale;
        *dest_len = sizeof(digest->stale);
    }
}

static void handle_digest_update(HTTPAuthState *state, const char *key,
                                 int key_len, char **dest, int *dest_len)
{
    DigestParams *digest = &state->digest_params;

    if (!strncmp(key, "nextnonce=", key_len)) {
        *dest     =        digest->nonce;
        *dest_len = sizeof(digest->nonce);
    }
}

static void choose_qop(char *qop, int size)
{
    char *ptr = strstr(qop, "auth");
    char *end = ptr + strlen("auth");

    if (ptr && (!*end || av_isspace(*end) || *end == ',') &&
        (ptr == qop || av_isspace(ptr[-1]) || ptr[-1] == ',')) {
        av_strlcpy(qop, "auth", size);
    } else {
        qop[0] = 0;
    }
}

void ff_http_auth_handle_header(HTTPAuthState *state, const char *key,
                                const char *value)
{
    if (!av_strcasecmp(key, "WWW-Authenticate") || !av_strcasecmp(key, "Proxy-Authenticate")) {
        const char *p;
        if (av_stristart(value, "Basic ", &p) &&
            state->auth_type <= HTTP_AUTH_BASIC) {
            state->auth_type = HTTP_AUTH_BASIC;
            state->realm[0] = 0;
            state->stale = 0;
            ff_parse_key_value(p, (ff_parse_key_val_cb) handle_basic_params,
                               state);
        } else if (av_stristart(value, "Digest ", &p) &&
                   state->auth_type <= HTTP_AUTH_DIGEST) {
            state->auth_type = HTTP_AUTH_DIGEST;
            memset(&state->digest_params, 0, sizeof(DigestParams));
            state->realm[0] = 0;
            state->stale = 0;
            ff_parse_key_value(p, (ff_parse_key_val_cb) handle_digest_params,
                               state);
            choose_qop(state->digest_params.qop,
                       sizeof(state->digest_params.qop));
            if (!av_strcasecmp(state->digest_params.stale, "true"))
                state->stale = 1;
        }
    } else if (!av_strcasecmp(key, "Authentication-Info")) {
        ff_parse_key_value(value, (ff_parse_key_val_cb) handle_digest_update,
                           state);
    }
}


enum DigestAlgo {
    DIGEST_ALGO_MD5,
    DIGEST_ALGO_MD5_SESS,
    DIGEST_ALGO_SHA256,
    DIGEST_ALGO_SHA256_SESS,
    DIGEST_ALGO_SHA512_256,
    DIGEST_ALGO_SHA512_256_SESS,
    DIGEST_ALGO_UNKNOWN,
};

static enum DigestAlgo get_digest_algo(const char *algorithm)
{
    if (!strcmp(algorithm, "") || !strcmp(algorithm, "MD5"))
        return DIGEST_ALGO_MD5;
    if (!strcmp(algorithm, "MD5-sess"))
        return DIGEST_ALGO_MD5_SESS;
    if (!strcmp(algorithm, "SHA-256"))
        return DIGEST_ALGO_SHA256;
    if (!strcmp(algorithm, "SHA-256-sess"))
        return DIGEST_ALGO_SHA256_SESS;
    if (!strcmp(algorithm, "SHA-512-256"))
        return DIGEST_ALGO_SHA512_256;
    if (!strcmp(algorithm, "SHA-512-256-sess"))
        return DIGEST_ALGO_SHA512_256_SESS;
    return DIGEST_ALGO_UNKNOWN;
}

static int digest_is_sess(enum DigestAlgo algo)
{
    return algo == DIGEST_ALGO_MD5_SESS ||
           algo == DIGEST_ALGO_SHA256_SESS ||
           algo == DIGEST_ALGO_SHA512_256_SESS;
}

/**
 * Hash context wrapper that abstracts over MD5, SHA-256, and SHA-512/256.
 */
typedef struct DigestHashContext {
    enum DigestAlgo algo;
    int hash_len;           /* digest output length in bytes */
    union {
        struct AVMD5    *md5;
        struct AVSHA    *sha256;
        struct AVSHA512 *sha512;
    } ctx;
} DigestHashContext;

static int digest_hash_alloc(DigestHashContext *h, enum DigestAlgo algo)
{
    h->algo = algo;
    switch (algo) {
    case DIGEST_ALGO_MD5:
    case DIGEST_ALGO_MD5_SESS:
        h->hash_len = 16;
        h->ctx.md5 = av_md5_alloc();
        return h->ctx.md5 ? 0 : -1;
    case DIGEST_ALGO_SHA256:
    case DIGEST_ALGO_SHA256_SESS:
        h->hash_len = 32;
        h->ctx.sha256 = av_sha_alloc();
        return h->ctx.sha256 ? 0 : -1;
    case DIGEST_ALGO_SHA512_256:
    case DIGEST_ALGO_SHA512_256_SESS:
        h->hash_len = 32;
        h->ctx.sha512 = av_sha512_alloc();
        return h->ctx.sha512 ? 0 : -1;
    default:
        return -1;
    }
}

static void digest_hash_init(DigestHashContext *h)
{
    switch (h->algo) {
    case DIGEST_ALGO_MD5:
    case DIGEST_ALGO_MD5_SESS:
        av_md5_init(h->ctx.md5);
        break;
    case DIGEST_ALGO_SHA256:
    case DIGEST_ALGO_SHA256_SESS:
        av_sha_init(h->ctx.sha256, 256);
        break;
    case DIGEST_ALGO_SHA512_256:
    case DIGEST_ALGO_SHA512_256_SESS:
        av_sha512_init(h->ctx.sha512, 256);
        break;
    default:
        break;
    }
}

static void digest_hash_update(DigestHashContext *h, const uint8_t *data, size_t len)
{
    switch (h->algo) {
    case DIGEST_ALGO_MD5:
    case DIGEST_ALGO_MD5_SESS:
        av_md5_update(h->ctx.md5, data, len);
        break;
    case DIGEST_ALGO_SHA256:
    case DIGEST_ALGO_SHA256_SESS:
        av_sha_update(h->ctx.sha256, data, len);
        break;
    case DIGEST_ALGO_SHA512_256:
    case DIGEST_ALGO_SHA512_256_SESS:
        av_sha512_update(h->ctx.sha512, data, len);
        break;
    default:
        break;
    }
}

static void digest_hash_final(DigestHashContext *h, uint8_t *digest)
{
    switch (h->algo) {
    case DIGEST_ALGO_MD5:
    case DIGEST_ALGO_MD5_SESS:
        av_md5_final(h->ctx.md5, digest);
        break;
    case DIGEST_ALGO_SHA256:
    case DIGEST_ALGO_SHA256_SESS:
        av_sha_final(h->ctx.sha256, digest);
        break;
    case DIGEST_ALGO_SHA512_256:
    case DIGEST_ALGO_SHA512_256_SESS:
        av_sha512_final(h->ctx.sha512, digest);
        break;
    default:
        break;
    }
}

static void digest_hash_free(DigestHashContext *h)
{
    switch (h->algo) {
    case DIGEST_ALGO_MD5:
    case DIGEST_ALGO_MD5_SESS:
        av_free(h->ctx.md5);
        break;
    case DIGEST_ALGO_SHA256:
    case DIGEST_ALGO_SHA256_SESS:
        av_free(h->ctx.sha256);
        break;
    case DIGEST_ALGO_SHA512_256:
    case DIGEST_ALGO_SHA512_256_SESS:
        av_free(h->ctx.sha512);
        break;
    default:
        break;
    }
}

static void digest_hash_update_strings(DigestHashContext *h, ...)
{
    va_list vl;

    va_start(vl, h);
    while (1) {
        const char *str = va_arg(vl, const char *);
        if (!str)
            break;
        digest_hash_update(h, (const uint8_t *)str, strlen(str));
    }
    va_end(vl);
}

/* Generate a digest reply, according to RFC 2617 / RFC 7616. */
static char *make_digest_auth(HTTPAuthState *state, const char *username,
                              const char *password, const char *uri,
                              const char *method)
{
    DigestParams *digest = &state->digest_params;
    int len;
    uint32_t cnonce_buf[2];
    char cnonce[17];
    char nc[9];
    int i;
    enum DigestAlgo algo;
    DigestHashContext hashctx;
    char A1hash[65], A2hash[65], response[65];
    uint8_t hash[32];
    char *authstr;

    algo = get_digest_algo(digest->algorithm);
    if (algo == DIGEST_ALGO_UNKNOWN)
        return NULL;

    if (digest_hash_alloc(&hashctx, algo) < 0)
        return NULL;

    digest->nc++;
    snprintf(nc, sizeof(nc), "%08x", digest->nc);

    /* Generate a client nonce. */
    for (i = 0; i < 2; i++)
        cnonce_buf[i] = av_get_random_seed();
    ff_data_to_hex(cnonce, (const uint8_t*) cnonce_buf, sizeof(cnonce_buf), 1);

    /* Compute A1 hash: H(username:realm:password) */
    digest_hash_init(&hashctx);
    digest_hash_update_strings(&hashctx, username, ":", state->realm, ":", password, NULL);
    digest_hash_final(&hashctx, hash);
    ff_data_to_hex(A1hash, hash, hashctx.hash_len, 1);

    /* For -sess variants: A1 = H(H(username:realm:password):nonce:cnonce) */
    if (digest_is_sess(algo)) {
        digest_hash_init(&hashctx);
        digest_hash_update_strings(&hashctx, A1hash, ":", digest->nonce, ":", cnonce, NULL);
        digest_hash_final(&hashctx, hash);
        ff_data_to_hex(A1hash, hash, hashctx.hash_len, 1);
    }

    /* Compute A2 hash: H(method:uri) */
    digest_hash_init(&hashctx);
    digest_hash_update_strings(&hashctx, method, ":", uri, NULL);
    digest_hash_final(&hashctx, hash);
    ff_data_to_hex(A2hash, hash, hashctx.hash_len, 1);

    /* Compute response: H(A1hash:nonce[:nc:cnonce:qop]:A2hash) */
    digest_hash_init(&hashctx);
    digest_hash_update_strings(&hashctx, A1hash, ":", digest->nonce, NULL);
    if (!strcmp(digest->qop, "auth") || !strcmp(digest->qop, "auth-int")) {
        digest_hash_update_strings(&hashctx, ":", nc, ":", cnonce, ":", digest->qop, NULL);
    }
    digest_hash_update_strings(&hashctx, ":", A2hash, NULL);
    digest_hash_final(&hashctx, hash);
    ff_data_to_hex(response, hash, hashctx.hash_len, 1);

    digest_hash_free(&hashctx);

    if (!strcmp(digest->qop, "") || !strcmp(digest->qop, "auth")) {
    } else if (!strcmp(digest->qop, "auth-int")) {
        /* qop=auth-int not supported */
        return NULL;
    } else {
        /* Unsupported qop value. */
        return NULL;
    }

    len = strlen(username) + strlen(state->realm) + strlen(digest->nonce) +
              strlen(uri) + strlen(response) + strlen(digest->algorithm) +
              strlen(digest->opaque) + strlen(digest->qop) + strlen(cnonce) +
              strlen(nc) + 150;

    authstr = av_malloc(len);
    if (!authstr)
        return NULL;
    snprintf(authstr, len, "Authorization: Digest ");

    /* TODO: Escape the quoted strings properly. */
    av_strlcatf(authstr, len, "username=\"%s\"",   username);
    av_strlcatf(authstr, len, ", realm=\"%s\"",     state->realm);
    av_strlcatf(authstr, len, ", nonce=\"%s\"",     digest->nonce);
    av_strlcatf(authstr, len, ", uri=\"%s\"",       uri);

    if (digest->algorithm[0])
        av_strlcatf(authstr, len, ", algorithm=%s",  digest->algorithm);

    if (digest->opaque[0])
        av_strlcatf(authstr, len, ", opaque=\"%s\"", digest->opaque);
    if (digest->qop[0]) {
        av_strlcatf(authstr, len, ", qop=%s",    digest->qop);
        av_strlcatf(authstr, len, ", nc=%s",         nc);
        av_strlcatf(authstr, len, ", cnonce=\"%s\"", cnonce);
    }

    av_strlcatf(authstr, len, ", response=\"%s\"",  response);

    av_strlcatf(authstr, len, "\r\n");

    return authstr;
}

char *ff_http_auth_create_response(HTTPAuthState *state, const char *auth,
                                   const char *path, const char *method)
{
    char *authstr = NULL;

    /* Clear the stale flag, we assume the auth is ok now. It is reset
     * by the server headers if there's a new issue. */
    state->stale = 0;
    if (!auth || !strchr(auth, ':'))
        return NULL;

    if (state->auth_type == HTTP_AUTH_BASIC) {
        int auth_b64_len, len;
        char *ptr, *decoded_auth = ff_urldecode(auth, 0);

        if (!decoded_auth)
            return NULL;

        auth_b64_len = AV_BASE64_SIZE(strlen(decoded_auth));
        len = auth_b64_len + 30;

        authstr = av_malloc(len);
        if (!authstr) {
            av_free(decoded_auth);
            return NULL;
        }

        snprintf(authstr, len, "Authorization: Basic ");
        ptr = authstr + strlen(authstr);
        av_base64_encode(ptr, auth_b64_len, decoded_auth, strlen(decoded_auth));
        av_strlcat(ptr, "\r\n", len - (ptr - authstr));
        av_free(decoded_auth);
    } else if (state->auth_type == HTTP_AUTH_DIGEST) {
        char *username = ff_urldecode(auth, 0), *password;

        if (!username)
            return NULL;

        if ((password = strchr(username, ':'))) {
            *password++ = 0;
            authstr = make_digest_auth(state, username, password, path, method);
        }
        av_free(username);
    }
    return authstr;
}
