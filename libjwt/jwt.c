/* Copyright (C) 2015-2016 Ben Collins <ben@cyphre.com>
   This file is part of the JWT C Library

   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with the JWT Library; if not, see
   <http://www.gnu.org/licenses/>.  */

#include <stdlib.h>
#include <string.h>
#include <errno.h>

/*#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/buffer.h>
#include <openssl/pem.h>*/
#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>

#include <jansson.h>

#include <jwt.h>

#if !defined(USE_CMAKE)
#include "config.h"
#endif

static const unsigned char base64_table[65] =
	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/**
 * base64_encode - Base64 encode
 * @src: Data to be encoded
 * @len: Length of the data to be encoded
 * @out: Pointer to output variable
 * @out_len: Pointer to output length variable
 * Returns: 1 on success, 0 on failure
 *
 * The nul terminator is not included in out_len.
 */
int base64_encode(const char * src, size_t len, char * out, size_t * out_len) {
	char * pos;
	const char * end, * in;
	size_t olen;
	int line_len;

	olen = len * 4 / 3 + 4; /* 3-byte blocks to 4-byte */
	olen += olen / 72; /* line feeds */
	olen++; /* nul termination */
	if (olen < len || src == NULL || out == NULL) {
		return 0;
  }

	end = src + len;
	in = src;
	pos = out;
	line_len = 0;
	while (end - in >= 3) {
		*pos++ = base64_table[in[0] >> 2];
		*pos++ = base64_table[((in[0] & 0x03) << 4) | (in[1] >> 4)];
		*pos++ = base64_table[((in[1] & 0x0f) << 2) | (in[2] >> 6)];
		*pos++ = base64_table[in[2] & 0x3f];
		in += 3;
		line_len += 4;
		if (line_len >= 72) {
			line_len = 0;
		}
	}

	if (end - in) {
		*pos++ = base64_table[in[0] >> 2];
		if (end - in == 1) {
			*pos++ = base64_table[(in[0] & 0x03) << 4];
			*pos++ = '=';
		} else {
			*pos++ = base64_table[((in[0] & 0x03) << 4) |
					      (in[1] >> 4)];
			*pos++ = base64_table[(in[1] & 0x0f) << 2];
		}
		*pos++ = '=';
		line_len += 4;
	}

	*pos = '\0';
	if (out_len) {
		*out_len = pos - out;
  }
	return 1;
}

/**
 * base64_decode - Base64 decode
 * @src: Data to be decoded
 * @len: Length of the data to be decoded
 * @out: Pointer to output variable
 * @out_len: Pointer to output length variable
 * Returns: 1 on success, 0 on failure
 *
 * The nul terminator is not included in out_len.
 */
int base64_decode(const char *src, size_t len, char * out, size_t * out_len) {
	char dtable[256], *pos = out, block[4], tmp;
	size_t i, count;
	int pad = 0;

	memset(dtable, 0x80, 256);
	for (i = 0; i < sizeof(base64_table) - 1; i++) {
		dtable[base64_table[i]] = (char) i;
  }
	dtable['='] = 0;

	count = 0;
	for (i = 0; i < len; i++) {
		if (dtable[src[i]] != 0x80) {
			count++;
    }
	}

	if (count == 0 || count % 4 || src == NULL || out == NULL) {
		return 0;
  }

	count = 0;
	for (i = 0; i < len; i++) {
		tmp = dtable[src[i]];
		if (tmp == 0x80) {
			continue;
    }

		if (src[i] == '=') {
			pad++;
    }
		block[count] = tmp;
		count++;
		if (count == 4) {
			*pos++ = (block[0] << 2) | (block[1] >> 4);
			*pos++ = (block[1] << 4) | (block[2] >> 2);
			*pos++ = (block[2] << 6) | block[3];
			count = 0;
			if (pad) {
				if (pad == 1) {
					pos--;
        } else if (pad == 2) {
					pos -= 2;
        } else {
					/* Invalid padding */
					return 0;
				}
				break;
			}
		}
	}

	*out_len = pos - out;
	return 1;
}

/* functions to make libjwt backward compatible with OpenSSL version < 1.1.0
 * See https://wiki.openssl.org/index.php/1.1_API_Changes
 
#if OPENSSL_VERSION_NUMBER < 0x10100000L

static void ECDSA_SIG_get0(const ECDSA_SIG *sig, const BIGNUM **pr, const BIGNUM **ps)
{
	if (pr != NULL)
		*pr = sig->r;
	if (ps != NULL)
		*ps = sig->s;
}

static int ECDSA_SIG_set0(ECDSA_SIG *sig, BIGNUM *r, BIGNUM *s)
{
	if (r == NULL || s == NULL)
		return 0;

	BN_clear_free(sig->r);
	BN_clear_free(sig->s);
	sig->r = r;
	sig->s = s;

	return 1;
}

#endif*/

struct jwt {
	jwt_alg_t alg;
	unsigned char *key;
	int key_len;
	json_t *grants;
};

static const char *jwt_alg_str(jwt_alg_t alg)
{
	switch (alg) {
	case JWT_ALG_NONE:
		return "none";
	case JWT_ALG_HS256:
		return "HS256";
	case JWT_ALG_HS384:
		return "HS384";
	case JWT_ALG_HS512:
		return "HS512";
	case JWT_ALG_RS256:
		return "RS256";
	case JWT_ALG_RS384:
		return "RS384";
	case JWT_ALG_RS512:
		return "RS512";
	case JWT_ALG_ES256:
		return "ES256";
	case JWT_ALG_ES384:
		return "ES384";
	case JWT_ALG_ES512:
		return "ES512";
	default:
		return NULL;
	}
}

static int jwt_str_alg(jwt_t *jwt, const char *alg)
{
	if (alg == NULL)
		return EINVAL;

	if (!strcasecmp(alg, "none"))
		jwt->alg = JWT_ALG_NONE;
	else if (!strcasecmp(alg, "HS256"))
		jwt->alg = JWT_ALG_HS256;
	else if (!strcasecmp(alg, "HS384"))
		jwt->alg = JWT_ALG_HS384;
	else if (!strcasecmp(alg, "HS512"))
		jwt->alg = JWT_ALG_HS512;
	else if (!strcasecmp(alg, "RS256"))
		jwt->alg = JWT_ALG_RS256;
	else if (!strcasecmp(alg, "RS384"))
		jwt->alg = JWT_ALG_RS384;
	else if (!strcasecmp(alg, "RS512"))
		jwt->alg = JWT_ALG_RS512;
	else if (!strcasecmp(alg, "ES256"))
		jwt->alg = JWT_ALG_ES256;
	else if (!strcasecmp(alg, "ES384"))
		jwt->alg = JWT_ALG_ES384;
	else if (!strcasecmp(alg, "ES512"))
		jwt->alg = JWT_ALG_ES512;
	else
		return EINVAL;

	return 0;
}

static void jwt_scrub_key(jwt_t *jwt)
{
	if (jwt->key) {
		/* Overwrite it so it's gone from memory. */
		memset(jwt->key, 0, jwt->key_len);

		free(jwt->key);
		jwt->key = NULL;
	}

	jwt->key_len = 0;
	jwt->alg = JWT_ALG_NONE;
}

int jwt_set_alg(jwt_t *jwt, jwt_alg_t alg, const unsigned char *key, int len)
{
	/* No matter what happens here, we do this. */
	jwt_scrub_key(jwt);

	if (alg < JWT_ALG_NONE || alg >= JWT_ALG_TERM)
		return EINVAL;

	switch (alg) {
	case JWT_ALG_NONE:
		if (key || len)
			return EINVAL;
		break;

	default:
		if (!key || len <= 0)
			return EINVAL;

		jwt->key = malloc(len);
		if (!jwt->key)
			return ENOMEM;

		memcpy(jwt->key, key, len);
	}

	jwt->alg = alg;
	jwt->key_len = len;

	return 0;
}

jwt_alg_t jwt_get_alg(jwt_t *jwt)
{
	return jwt->alg;
}

int jwt_new(jwt_t **jwt)
{
	if (!jwt)
		return EINVAL;

	*jwt = malloc(sizeof(jwt_t));
	if (!*jwt)
		return ENOMEM;

	memset(*jwt, 0, sizeof(jwt_t));

	(*jwt)->grants = json_object();
	if (!(*jwt)->grants) {
		free(*jwt);
		*jwt = NULL;
		return ENOMEM;
	}

	return 0;
}

void jwt_free(jwt_t *jwt)
{
	if (!jwt)
		return;

	jwt_scrub_key(jwt);

	json_decref(jwt->grants);

	free(jwt);
}

jwt_t *jwt_dup(jwt_t *jwt)
{
	jwt_t *new = NULL;

	if (!jwt) {
		errno = EINVAL;
		goto dup_fail;
	}

	errno = 0;

	new = malloc(sizeof(jwt_t));
	if (!new) {
		errno = ENOMEM;
		return NULL;
	}

	memset(new, 0, sizeof(jwt_t));

	if (jwt->key_len) {
		new->alg = jwt->alg;
		new->key = malloc(jwt->key_len);
		if (!new->key) {
			errno = ENOMEM;
			goto dup_fail;
		}
		memcpy(new->key, jwt->key, jwt->key_len);
		new->key_len = jwt->key_len;
	}

	new->grants = json_deep_copy(jwt->grants);
	if (!new->grants)
		errno = ENOMEM;

dup_fail:
	if (errno) {
		jwt_free(new);
		new = NULL;
	}

	return new;
}

static const char *get_js_string(json_t *js, const char *key)
{
	const char *val = NULL;
	json_t *js_val;

	js_val = json_object_get(js, key);
	if (js_val)
		val = json_string_value(js_val);

	return val;
}

static long get_js_int(json_t *js, const char *key)
{
	long val = -1;
	json_t *js_val;

	js_val = json_object_get(js, key);
	if (js_val)
		val = (long)json_integer_value(js_val);

	return val;
}

static void *jwt_b64_decode(const char *src, int *ret_len)
{
	/*BIO *b64, *bmem;
	void *buf;
	char *new;
	int len, i, z;*/

	/* Decode based on RFC-4648 URI safe encoding. */
	/*len = strlen(src);
	new = alloca(len + 4);
	if (!new)
		return NULL;

	for (i = 0; i < len; i++) {
		switch (src[i]) {
		case '-':
			new[i] = '+';
			break;
		case '_':
			new[i] = '/';
			break;
		default:
			new[i] = src[i];
		}
	}
	z = 4 - (i % 4);
	if (z < 4) {
		while (z--)
			new[i++] = '=';
	}
	new[i] = '\0';*/

	/* Setup the OpenSSL base64 decoder. */
	/*b64 = BIO_new(BIO_f_base64());
	bmem = BIO_new_mem_buf(new, strlen(new));
	if (!b64 || !bmem)
		return NULL;

	BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
	BIO_push(b64, bmem);

	len = BIO_pending(b64);
	if (len <= 0) {
		BIO_free_all(b64);
		return NULL;
	}

	buf = malloc(len + 1);
	if (!buf) {
		BIO_free_all(b64);
		return NULL;
	}

	*ret_len = BIO_read(b64, buf, len);
	BIO_free_all(b64);

	return buf;*/
  return NULL;
}


static json_t *jwt_b64_decode_json(char *src)
{
	json_t *js;
	char *buf;
	int len;

	buf = jwt_b64_decode(src, &len);

	if (buf == NULL)
		return NULL;

	buf[len] = '\0';

	js = json_loads(buf, 0, NULL);

	free(buf);

	return js;
}

static void base64uri_encode(char *str)
{
	int len = strlen(str);
	int i, t;

	for (i = t = 0; i < len; i++) {
		switch (str[i]) {
		case '+':
			str[t++] = '-';
			break;
		case '/':
			str[t++] = '_';
			break;
		case '=':
			break;
		default:
			str[t++] = str[i];
		}
	}

	str[t] = '\0';
}

/*static int jwt_sign_sha_hmac(jwt_t *jwt, BIO *out, const EVP_MD *alg,
			     const char *str)
{
	unsigned char res[EVP_MAX_MD_SIZE];
	unsigned int res_len;

	HMAC(alg, jwt->key, jwt->key_len,
	     (const unsigned char *)str, strlen(str), res, &res_len);

	BIO_write(out, res, res_len);

	BIO_flush(out);

	return 0;
}

static int jwt_verify_sha_hmac(jwt_t *jwt, const EVP_MD *alg, const char *head,
			       const char *sig)
{
	unsigned char res[EVP_MAX_MD_SIZE];
	BIO *bmem = NULL, *b64 = NULL;
	unsigned int res_len;
	char *buf;
	int len, ret = EINVAL;

	b64 = BIO_new(BIO_f_base64());
	if (b64 == NULL)
		return ENOMEM;

	bmem = BIO_new(BIO_s_mem());
	if (bmem == NULL) {
		BIO_free(b64);
		return ENOMEM;
	}

	BIO_push(b64, bmem);
	BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);

	HMAC(alg, jwt->key, jwt->key_len,
	     (const unsigned char *)head, strlen(head), res, &res_len);

	BIO_write(b64, res, res_len);

	BIO_flush(b64);

	len = BIO_pending(bmem);
	if (len < 0)
		goto jwt_verify_hmac_done;

	buf = alloca(len + 1);
	if (!buf) {
		ret = ENOMEM;
		goto jwt_verify_hmac_done;
	}

	len = BIO_read(bmem, buf, len);
	buf[len] = '\0';

	base64uri_encode(buf);

	ret = strcmp(buf, sig) ? EINVAL : 0;

jwt_verify_hmac_done:
	BIO_free_all(b64);

	return ret;
}*/

#define SIGN_ERROR(__err) ({ ret = __err; goto jwt_sign_sha_pem_done; })

/*static int jwt_sign_sha_pem(jwt_t *jwt, BIO *out, const EVP_MD *alg,
			    const char *str, int type)
{
	EVP_MD_CTX *mdctx = NULL;
	ECDSA_SIG *ec_sig = NULL;
	const BIGNUM *ec_sig_r = NULL;
	const BIGNUM *ec_sig_s = NULL;
	BIO *bufkey = NULL;
	EVP_PKEY *pkey = NULL;
	int pkey_type;
	unsigned char *sig;
	int ret = 0;
	size_t slen;

	bufkey = BIO_new_mem_buf(jwt->key, jwt->key_len);
	if (bufkey == NULL)
		SIGN_ERROR(ENOMEM);

	pkey = PEM_read_bio_PrivateKey(bufkey, NULL, NULL, NULL);
	if (pkey == NULL)
		SIGN_ERROR(EINVAL);

	pkey_type = EVP_PKEY_id(pkey);
	if (pkey_type != type)
		SIGN_ERROR(EINVAL);

	mdctx = EVP_MD_CTX_create();
	if (mdctx == NULL)
		SIGN_ERROR(ENOMEM);

	if (EVP_DigestSignInit(mdctx, NULL, alg, NULL, pkey) != 1)
		SIGN_ERROR(EINVAL);

	if (EVP_DigestSignUpdate(mdctx, str, strlen(str)) != 1)
		SIGN_ERROR(EINVAL);

	if (EVP_DigestSignFinal(mdctx, NULL, &slen) != 1)
		SIGN_ERROR(EINVAL);

	sig = alloca(slen);
	if (sig == NULL)
		SIGN_ERROR(ENOMEM);

	if (EVP_DigestSignFinal(mdctx, sig, &slen) != 1)
		SIGN_ERROR(EINVAL);

	if (pkey_type != EVP_PKEY_EC) {
		BIO_write(out, sig, slen);
		BIO_flush(out);
	} else {
		unsigned int degree, bn_len, r_len, s_len, buf_len;
		unsigned char *raw_buf;
		EC_KEY *ec_key;

		ec_key = EVP_PKEY_get1_EC_KEY(pkey);
		if (ec_key == NULL)
			SIGN_ERROR(ENOMEM);

		degree = EC_GROUP_get_degree(EC_KEY_get0_group(ec_key));

		EC_KEY_free(ec_key);

		ec_sig = d2i_ECDSA_SIG(NULL, (const unsigned char **)&sig, slen);
		if (ec_sig == NULL)
			SIGN_ERROR(ENOMEM);

		ECDSA_SIG_get0(ec_sig, &ec_sig_r, &ec_sig_s);
		r_len = BN_num_bytes(ec_sig_r);
		s_len = BN_num_bytes(ec_sig_s);
		bn_len = (degree + 7) / 8;
		if ((r_len > bn_len) || (s_len > bn_len))
			SIGN_ERROR(EINVAL);

		buf_len = 2 * bn_len;
		raw_buf = alloca(buf_len);
		if (raw_buf == NULL)
			SIGN_ERROR(ENOMEM);

		memset(raw_buf, 0, buf_len);
		BN_bn2bin(ec_sig_r, raw_buf + bn_len - r_len);
		BN_bn2bin(ec_sig_s, raw_buf + buf_len - s_len);

		BIO_write(out, raw_buf, buf_len);
		BIO_flush(out);
	}

jwt_sign_sha_pem_done:
	if (bufkey)
		BIO_free(bufkey);
	if (pkey)
		EVP_PKEY_free(pkey);
	if (mdctx)
		EVP_MD_CTX_destroy(mdctx);
	if (ec_sig)
		ECDSA_SIG_free(ec_sig);

	return ret;
}*/

#define VERIFY_ERROR(__err) ({ ret = __err; goto jwt_verify_sha_pem_done; })

/*static int jwt_verify_sha_pem(jwt_t *jwt, const EVP_MD *alg, int type,
			      const char *head, const char *sig_b64)
{
	unsigned char *sig = NULL;
	EVP_MD_CTX *mdctx = NULL;
	ECDSA_SIG *ec_sig = NULL;
	BIGNUM *ec_sig_r = NULL;
	BIGNUM *ec_sig_s = NULL;
	EVP_PKEY *pkey = NULL;
	int pkey_type;
	BIO *bufkey = NULL;
	int ret = 0;
	int slen;

	sig = jwt_b64_decode(sig_b64, &slen);
	if (sig == NULL)
		VERIFY_ERROR(EINVAL);

	bufkey = BIO_new_mem_buf(jwt->key, jwt->key_len);
	if (bufkey == NULL)
		VERIFY_ERROR(ENOMEM);

	pkey = PEM_read_bio_PUBKEY(bufkey, NULL, NULL, NULL);
	if (pkey == NULL)
		VERIFY_ERROR(EINVAL);

	pkey_type = EVP_PKEY_id(pkey);
	if (pkey_type != type)
		VERIFY_ERROR(EINVAL);

	if (pkey_type == EVP_PKEY_EC) {
		unsigned int degree, bn_len;
		unsigned char *p;
		EC_KEY *ec_key;

		ec_sig = ECDSA_SIG_new();
		if (ec_sig == NULL)
			VERIFY_ERROR(ENOMEM);

		ec_key = EVP_PKEY_get1_EC_KEY(pkey);
		if (ec_key == NULL)
			VERIFY_ERROR(ENOMEM);

		degree = EC_GROUP_get_degree(EC_KEY_get0_group(ec_key));

		EC_KEY_free(ec_key);

		bn_len = (degree + 7) / 8;
		if ((bn_len * 2) != slen)
			VERIFY_ERROR(EINVAL);

		ec_sig_r = BN_bin2bn(sig, bn_len, NULL);
		ec_sig_s = BN_bin2bn(sig + bn_len, bn_len, NULL);
		if (ec_sig_r  == NULL || ec_sig_s == NULL)
			VERIFY_ERROR(EINVAL);

		ECDSA_SIG_set0(ec_sig, ec_sig_r, ec_sig_s);
		free(sig);

		slen = i2d_ECDSA_SIG(ec_sig, NULL);
		sig = malloc(slen);
		if (sig == NULL)
			VERIFY_ERROR(ENOMEM);

		p = sig;
		slen = i2d_ECDSA_SIG(ec_sig, &p);

		if (slen == 0)
			VERIFY_ERROR(EINVAL);
	}

	mdctx = EVP_MD_CTX_create();
	if (mdctx == NULL)
		VERIFY_ERROR(ENOMEM);

	if (EVP_DigestVerifyInit(mdctx, NULL, alg, NULL, pkey) != 1)
		VERIFY_ERROR(EINVAL);

	if (EVP_DigestVerifyUpdate(mdctx, head, strlen(head)) != 1)
		VERIFY_ERROR(EINVAL);

	if (EVP_DigestVerifyFinal(mdctx, sig, slen) != 1)
		VERIFY_ERROR(EINVAL);

jwt_verify_sha_pem_done:
	if (bufkey)
		BIO_free(bufkey);
	if (pkey)
		EVP_PKEY_free(pkey);
	if (mdctx)
		EVP_MD_CTX_destroy(mdctx);
	if (sig)
		free(sig);
	if (ec_sig)
		ECDSA_SIG_free(ec_sig);

	return ret;
}*/

/*static int jwt_sign(jwt_t *jwt, BIO *out, const char *str)
{
	switch (jwt->alg) {
	case JWT_ALG_HS256:
		return jwt_sign_sha_hmac(jwt, out, EVP_sha256(), str);
	case JWT_ALG_HS384:
		return jwt_sign_sha_hmac(jwt, out, EVP_sha384(), str);
	case JWT_ALG_HS512:
		return jwt_sign_sha_hmac(jwt, out, EVP_sha512(), str);

	case JWT_ALG_RS256:
		return jwt_sign_sha_pem(jwt, out, EVP_sha256(), str,
					EVP_PKEY_RSA);
	case JWT_ALG_RS384:
		return jwt_sign_sha_pem(jwt, out, EVP_sha384(), str,
					EVP_PKEY_RSA);
	case JWT_ALG_RS512:
		return jwt_sign_sha_pem(jwt, out, EVP_sha512(), str,
					EVP_PKEY_RSA);

	case JWT_ALG_ES256:
		return jwt_sign_sha_pem(jwt, out, EVP_sha256(), str,
					EVP_PKEY_EC);
	case JWT_ALG_ES384:
		return jwt_sign_sha_pem(jwt, out, EVP_sha384(), str,
					EVP_PKEY_EC);
	case JWT_ALG_ES512:
		return jwt_sign_sha_pem(jwt, out, EVP_sha512(), str,
					EVP_PKEY_EC);

	default:
		return EINVAL;
	}
}*/

static int jwt_verify(jwt_t *jwt, const char *head, const char *sig)
{
	switch (jwt->alg) {
	/*case JWT_ALG_HS256:
		return jwt_verify_sha_hmac(jwt, EVP_sha256(), head, sig);
	case JWT_ALG_HS384:
		return jwt_verify_sha_hmac(jwt, EVP_sha384(), head, sig);
	case JWT_ALG_HS512:
		return jwt_verify_sha_hmac(jwt, EVP_sha512(), head, sig);

	case JWT_ALG_RS256:
		return jwt_verify_sha_pem(jwt, EVP_sha256(), EVP_PKEY_RSA,
					  head, sig);
	case JWT_ALG_RS384:
		return jwt_verify_sha_pem(jwt, EVP_sha384(), EVP_PKEY_RSA,
					  head, sig);
	case JWT_ALG_RS512:
		return jwt_verify_sha_pem(jwt, EVP_sha512(), EVP_PKEY_RSA,
					  head, sig);

	case JWT_ALG_ES256:
		return jwt_verify_sha_pem(jwt, EVP_sha256(), EVP_PKEY_EC,
					  head, sig);
	case JWT_ALG_ES384:
		return jwt_verify_sha_pem(jwt, EVP_sha384(), EVP_PKEY_EC,
					  head, sig);
	case JWT_ALG_ES512:
		return jwt_verify_sha_pem(jwt, EVP_sha512(), EVP_PKEY_EC,
					  head, sig);*/

	default:
		return EINVAL;
	}
}

static int jwt_parse_body(jwt_t *jwt, char *body)
{
	if (jwt->grants) {
		json_decref(jwt->grants);
		jwt->grants = NULL;
	}

	jwt->grants = jwt_b64_decode_json(body);
	if (!jwt->grants)
		return EINVAL;

	return 0;
}

static int jwt_verify_head(jwt_t *jwt, char *head)
{
	json_t *js = NULL;
	const char *val;
	int ret;

	js = jwt_b64_decode_json(head);
	if (!js)
		return EINVAL;

	val = get_js_string(js, "alg");
	ret = jwt_str_alg(jwt, val);
	if (ret)
		goto verify_head_done;

	if (jwt->alg != JWT_ALG_NONE) {
		/* If alg is not NONE, there may be a typ. */
		val = get_js_string(js, "typ");
		if (val && strcasecmp(val, "JWT"))
			ret = EINVAL;

		if (jwt->key) {
			if (jwt->key_len <= 0)
				ret = EINVAL;
		} else {
			jwt_scrub_key(jwt);
		}
	} else {
		/* If alg is NONE, there should not be a key */
		if (jwt->key){
			ret = EINVAL;
		}
	}

verify_head_done:
	if (js)
		json_decref(js);

	return ret;
}

int jwt_decode(jwt_t **jwt, const char *token, const unsigned char *key,
	       int key_len)
{
	char *head = strdup(token);
	jwt_t *new = NULL;
	char *body, *sig;
	int ret = EINVAL;

	if (!jwt)
		return EINVAL;

	*jwt = NULL;

	if (!head)
		return ENOMEM;

	/* Find the components. */
	for (body = head; body[0] != '.'; body++) {
		if (body[0] == '\0')
			goto decode_done;
	}

	body[0] = '\0';
	body++;

	for (sig = body; sig[0] != '.'; sig++) {
		if (sig[0] == '\0')
			goto decode_done;
	}

	sig[0] = '\0';
	sig++;

	/* Now that we have everything split up, let's check out the
	 * header. */
	ret = jwt_new(&new);
	if (ret) {
		goto decode_done;
	}

	/* Copy the key over for verify_head. */
	if (key_len) {
		new->key = malloc(key_len);
		if (new->key == NULL)
			goto decode_done;
		memcpy(new->key, key, key_len);
		new->key_len = key_len;
	}

	ret = jwt_verify_head(new, head);
	if (ret)
		goto decode_done;

	ret = jwt_parse_body(new, body);
	if (ret)
		goto decode_done;

	/* Check the signature, if needed. */
	if (new->alg != JWT_ALG_NONE) {
		/* Re-add this since it's part of the verified data. */
		body[-1] = '.';
		ret = jwt_verify(new, head, sig);
	} else {
		ret = 0;
	}

decode_done:
	if (ret)
		jwt_free(new);
	else
		*jwt = new;

	free(head);

	return ret;
}

const char *jwt_get_grant(jwt_t *jwt, const char *grant)
{
	if (!jwt || !grant || !strlen(grant)) {
		errno = EINVAL;
		return NULL;
	}

	errno = 0;

	return get_js_string(jwt->grants, grant);
}

long jwt_get_grant_int(jwt_t *jwt, const char *grant)
{
	if (!jwt || !grant || !strlen(grant)) {
		errno = EINVAL;
		return 0;
	}

	errno = 0;

	return get_js_int(jwt->grants, grant);
}

char *jwt_get_grants_json(jwt_t *jwt, const char *grant)
{
	json_t *js_val = NULL;

	errno = EINVAL;

	if (!jwt)
		return NULL;

	if (grant && strlen(grant))
		js_val = json_object_get(jwt->grants, grant);
	else
		js_val = jwt->grants;

	if (js_val == NULL)
		return NULL;

	errno = 0;

	return json_dumps(js_val, JSON_SORT_KEYS | JSON_COMPACT | JSON_ENCODE_ANY);
}

int jwt_add_grant(jwt_t *jwt, const char *grant, const char *val)
{
	if (!jwt || !grant || !strlen(grant) || !val)
		return EINVAL;

	if (get_js_string(jwt->grants, grant) != NULL)
		return EEXIST;

	if (json_object_set_new(jwt->grants, grant, json_string(val)))
		return EINVAL;

	return 0;
}

int jwt_add_grant_int(jwt_t *jwt, const char *grant, long val)
{
	if (!jwt || !grant || !strlen(grant))
		return EINVAL;

	if (get_js_int(jwt->grants, grant) != -1)
		return EEXIST;

	if (json_object_set_new(jwt->grants, grant, json_integer((json_int_t)val)))
		return EINVAL;

	return 0;
}

int jwt_add_grants_json(jwt_t *jwt, const char *json)
{
	json_t *js_val;
	int ret = -1;

	if (!jwt)
		return EINVAL;

	js_val = json_loads(json, JSON_REJECT_DUPLICATES, NULL);

	if (json_is_object(js_val))
		ret = json_object_update(jwt->grants, js_val);

	json_decref(js_val);

	return ret ? EINVAL : 0;
}

int jwt_del_grants(jwt_t *jwt, const char *grant)
{
	if (!jwt)
		return EINVAL;

	if (grant == NULL || !strlen(grant))
		json_object_clear(jwt->grants);
	else
		json_object_del(jwt->grants, grant);

	return 0;
}

#ifdef NO_WEAK_ALIASES
int jwt_del_grant(jwt_t *jwt, const char *grant)
{
	return jwt_del_grants(jwt, grant);
}
#else
int jwt_del_grant(jwt_t *jwt, const char *grant)
	__attribute__ ((weak, alias ("jwt_del_grants")));
#endif

/*static void jwt_write_bio_head(jwt_t *jwt, BIO *bio, int pretty)
{
	BIO_puts(bio, "{");

	if (pretty)
		BIO_puts(bio, "\n");

	if (jwt->alg != JWT_ALG_NONE) {
		if (pretty)
			BIO_puts(bio, "    ");

		BIO_printf(bio, "\"typ\":%s\"JWT\",", pretty?" ":"");

		if (pretty)
			BIO_puts(bio, "\n");
	}

	if (pretty)
		BIO_puts(bio, "    ");

	BIO_printf(bio, "\"alg\":%s\"%s\"", pretty?" ":"",
		   jwt_alg_str(jwt->alg));

	if (pretty)
		BIO_puts(bio, "\n");

	BIO_puts(bio, "}");

	if (pretty)
		BIO_puts(bio, "\n");

	BIO_flush(bio);
}*/

/*static void jwt_write_bio_body(jwt_t *jwt, BIO *bio, int pretty)
{
	size_t flags = JSON_SORT_KEYS;
	char *serial;

	if (pretty) {
		BIO_puts(bio, "\n");
		flags |= JSON_INDENT(4);
	} else {
		flags |= JSON_COMPACT;
	}

	serial = json_dumps(jwt->grants, flags);

	BIO_puts(bio, serial);

	free(serial);

	if (pretty)
		BIO_puts(bio, "\n");

	BIO_flush(bio);
}

static void jwt_dump_bio(jwt_t *jwt, BIO *out, int pretty)
{
	jwt_write_bio_head(jwt, out, pretty);
	BIO_puts(out, ".");
	jwt_write_bio_body(jwt, out, pretty);
}

int jwt_dump_fp(jwt_t *jwt, FILE *fp, int pretty)
{
	BIO *bio;

	bio = BIO_new_fp(fp, BIO_NOCLOSE);
	if (!bio)
		return ENOMEM;

	jwt_dump_bio(jwt, bio, pretty);

	BIO_free_all(bio);

	return 0;
}

char *jwt_dump_str(jwt_t *jwt, int pretty)
{
	BIO *bmem = BIO_new(BIO_s_mem());
	char *out;
	int len;

	if (!bmem) {
		errno = ENOMEM;
		return NULL;
	}

	jwt_dump_bio(jwt, bmem, pretty);

	len = BIO_pending(bmem);
	out = malloc(len + 1);
	if (!out) {
		BIO_free_all(bmem);
		errno = ENOMEM;
		return NULL;
	}

	len = BIO_read(bmem, out, len);
	out[len] = '\0';

	BIO_free_all(bmem);
	errno = 0;

	return out;
}
*/
/*static int jwt_encode_bio(jwt_t *jwt, BIO *out)
{
	BIO *b64, *bmem;
	char *buf;
	int len, len2, ret;

	b64 = BIO_new(BIO_f_base64());
	bmem = BIO_new(BIO_s_mem());
	if (!b64 || !bmem)
		return ENOMEM;

	BIO_push(b64, bmem);
	BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);

	jwt_write_bio_head(jwt, b64, 0);

	BIO_puts(bmem, ".");

	jwt_write_bio_body(jwt, b64, 0);

	len = BIO_pending(bmem);
	buf = alloca(len + 1);
	if (!buf) {
		BIO_free_all(b64);
		return ENOMEM;
	}

	len = BIO_read(bmem, buf, len);
	buf[len] = '\0';

	base64uri_encode(buf);

	BIO_puts(out, buf);
	BIO_puts(out, ".");

	if (jwt->alg == JWT_ALG_NONE)
		goto encode_bio_success;

	ret = jwt_sign(jwt, b64, buf);
	if (ret)
		goto encode_bio_done;

	len2 = BIO_pending(bmem);
	if (len2 > len) {
		buf = alloca(len2 + 1);
		if (!buf) {
			ret = ENOMEM;
			goto encode_bio_done;
		}
	} else if (len2 < 0) {
		ret = EINVAL;
		goto encode_bio_done;
	}

	len2 = BIO_read(bmem, buf, len2);
	buf[len2] = '\0';

	base64uri_encode(buf);

	BIO_puts(out, buf);

encode_bio_success:
	BIO_flush(out);

	ret = 0;

encode_bio_done:
	BIO_free_all(b64);

	return ret;
}*/

char * dump_head(jwt_t * jwt, int pretty) {
  if (jwt != NULL) {
    json_t * j_header = json_pack("{ssss}", "typ", "jwt", "alg", jwt_alg_str(jwt->alg));
    char * str_header = json_dumps(j_header, pretty?JSON_INDENT(2):JSON_COMPACT);
    json_decref(j_header);
    return str_header;
  } else {
    return NULL;
  }
}

int jwt_encode_fp(jwt_t *jwt, FILE *fp)
{
	/*BIO *bfp = BIO_new_fp(fp, BIO_NOCLOSE);
	int ret;

	if (!bfp)
		return ENOMEM;

	ret = jwt_encode_bio(jwt, bfp);
	BIO_free_all(bfp);

	return ret;*/
  return 0;
}

char *jwt_encode_str(jwt_t *jwt) {
  char * str_header = NULL, * str_payload = NULL, * b64_header = NULL, * b64_payload = NULL, * str_sig = NULL, * b64_sig = NULL, * tmp = NULL, * out = NULL;
  size_t b64_header_len, b64_payload_len, b64_sig_len, tmp_s, out_len;
  
  str_header = dump_head(jwt, 0);
  b64_header = malloc((2*strlen(str_header)+1) * sizeof(char));
  base64_encode(str_header, strlen(str_header), b64_header, &b64_header_len);
  base64uri_encode(b64_header);
  str_payload = json_dumps(jwt->grants, JSON_COMPACT);
  b64_payload = malloc((2*strlen(str_payload)+1) * sizeof(char));
  base64_encode(str_payload, strlen(str_payload), b64_payload, &b64_payload_len);
  base64uri_encode(b64_payload);
  
  if (jwt->alg == JWT_ALG_NONE) {
    b64_sig = strdup("");
    b64_sig_len = 0;
  } else if (jwt->alg == JWT_ALG_ES256) {
    // TODO
  } else if (jwt->alg == JWT_ALG_ES384) {
    // TODO
  } else if (jwt->alg == JWT_ALG_ES512) {
    // TODO
  } else if (jwt->alg == JWT_ALG_RS256) {
    // TODO
  } else if (jwt->alg == JWT_ALG_RS384) {
    // TODO
  } else if (jwt->alg == JWT_ALG_RS512) {
    // TODO
  } else if (jwt->alg == JWT_ALG_HS256) {
    tmp_s = snprintf(NULL, 0, "%s.%s", b64_header, b64_payload);
    tmp = malloc((tmp_s+1)*sizeof(char));
    snprintf(tmp, (tmp_s+1), "%s.%s", b64_header, b64_payload);
    str_sig = malloc(gnutls_hmac_get_len(GNUTLS_DIG_SHA256)*sizeof(char));
    gnutls_hmac_fast(GNUTLS_DIG_SHA256, jwt->key, jwt->key_len, tmp, strlen(tmp), str_sig);
    b64_sig = malloc(2*gnutls_hmac_get_len(GNUTLS_DIG_SHA256)*sizeof(char));
    base64_encode(str_sig, gnutls_hmac_get_len(GNUTLS_DIG_SHA256), b64_sig, &b64_sig_len);
    base64uri_encode(b64_sig);
  } else if (jwt->alg == JWT_ALG_HS384) {
    tmp_s = snprintf(NULL, 0, "%s.%s", b64_header, b64_payload);
    tmp = malloc((tmp_s+1)*sizeof(char));
    snprintf(tmp, (tmp_s+1), "%s.%s", b64_header, b64_payload);
    str_sig = malloc(gnutls_hmac_get_len(GNUTLS_DIG_SHA384)*sizeof(char));
    gnutls_hmac_fast(GNUTLS_DIG_SHA384, jwt->key, jwt->key_len, tmp, strlen(tmp), str_sig);
    b64_sig = malloc(2*gnutls_hmac_get_len(GNUTLS_DIG_SHA384)*sizeof(char));
    base64_encode(str_sig, gnutls_hmac_get_len(GNUTLS_DIG_SHA384), b64_sig, &b64_sig_len);
    base64uri_encode(b64_sig);
  } else if (jwt->alg == JWT_ALG_HS512) {
    tmp_s = snprintf(NULL, 0, "%s.%s", b64_header, b64_payload);
    tmp = malloc((tmp_s+1)*sizeof(char));
    snprintf(tmp, (tmp_s+1), "%s.%s", b64_header, b64_payload);
    str_sig = malloc(gnutls_hmac_get_len(GNUTLS_DIG_SHA512)*sizeof(char));
    gnutls_hmac_fast(GNUTLS_DIG_SHA512, jwt->key, jwt->key_len, tmp, strlen(tmp), str_sig);
    b64_sig = malloc(2*gnutls_hmac_get_len(GNUTLS_DIG_SHA512)*sizeof(char));
    base64_encode(str_sig, gnutls_hmac_get_len(GNUTLS_DIG_SHA512), b64_sig, &b64_sig_len);
    base64uri_encode(b64_sig);
  }
  
  out_len = snprintf(NULL, 0, "%s.%s.%s", b64_header, b64_payload, b64_sig);
  out = malloc((out_len + 1)*sizeof(char));
  snprintf(out, (out_len + 1), "%s.%s.%s", b64_header, b64_payload, b64_sig);
  free(str_header);
  free(str_payload);
  free(b64_header);
  free(b64_payload);
  free(str_sig);
  free(b64_sig);
  free(tmp);
  return out;
}
