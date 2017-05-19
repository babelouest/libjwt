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
#include <gnutls/x509.h>
#include <gnutls/abstract.h>

#include <jansson.h>

#include <jwt.h>

#if !defined(USE_CMAKE)
#include "config.h"
#endif

static const char base64_table[65] =
	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/**
 * o_base64_encode - Base64 encode
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

static const char base64_chars[] =
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static const char base64_digits[] =
  { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 62, 0, 0, 0, 63, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61,
    0, 0, 0, -1, 0, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13,
    14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 0, 0, 0, 0, 0, 0, 26,
    27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44,
    45, 46, 47, 48, 49, 50, 51, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };


char * base64_decode(const char* src, size_t * len)
{
  size_t in_len = strlen (src), out_len;
  char* dest;
  char* result;

  if (in_len % 4)
    {
      /* Wrong base64 string length */
      return NULL;
    }
  out_len = (in_len / 4 * 3 + 1);
  if (len != NULL) {
    *len = out_len;
  }
  result = dest = malloc(out_len);
  if (result == NULL)
    return NULL; /* out of memory */
  while (*src) {
    char a = base64_digits[(unsigned char)*(src++)];
    char b = base64_digits[(unsigned char)*(src++)];
    char c = base64_digits[(unsigned char)*(src++)];
    char d = base64_digits[(unsigned char)*(src++)];
    *(dest++) = (a << 2) | ((b & 0x30) >> 4);
    if (c == (char)-1)
      break;
    *(dest++) = ((b & 0x0f) << 4) | ((c & 0x3c) >> 2);
    if (d == (char)-1)
      break;
    *(dest++) = ((c & 0x03) << 6) | d;
  }
  *dest = 0;
  return result;
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

static void *jwt_b64_decode(const char *src, size_t *ret_len)
{
	char *new, * to_return;
	int len, i, z;

	/* Decode based on RFC-4648 URI safe encoding. */
	len = strlen(src);
	new = alloca(len + 4);
  *ret_len = 0;
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
	new[i] = '\0';
  
  to_return = base64_decode(new, NULL);
  if (to_return != NULL) {
    *ret_len = strlen(to_return);
  }
  return to_return;
}

static json_t *jwt_b64_decode_json(char *src)
{
	json_t *js;
	char *buf;
	size_t len = 0;

	buf = jwt_b64_decode(src, &len);

	if (buf == NULL)
		return NULL;

	buf[len] = '\0';

	js = json_loads(buf, 0, NULL);

	free(buf);

	return js;
}

char * dump_head(jwt_t * jwt, int pretty) {
  json_t * j_header;
  char * str_header;
  
  if (jwt != NULL) {
    if (jwt->alg != JWT_ALG_NONE) {
      j_header = json_pack("{ssss}", "typ", "JWT", "alg", jwt_alg_str(jwt->alg));
    } else {
      j_header = json_pack("{ss}", "alg", jwt_alg_str(jwt->alg));
    }
    str_header = json_dumps(j_header, (pretty?JSON_INDENT(2):JSON_COMPACT) | JSON_PRESERVE_ORDER);
    json_decref(j_header);
    return str_header;
  } else {
    return NULL;
  }
}

char * jwt_generate_signature_ec(jwt_t *jwt, const char * b64_header, const char * b64_payload) {
  char * b64_sig = NULL;
  gnutls_x509_privkey_t key;
  gnutls_privkey_t privkey;
  char * body_full;
  size_t body_full_len, b64_len;
  gnutls_datum_t key_dat = {(void *) jwt->key, jwt->key_len}, body_dat, sig_dat;
  gnutls_digest_algorithm_t hash = GNUTLS_DIG_NULL;
  
  body_full_len = snprintf(NULL, 0, "%s.%s", b64_header, b64_payload);
  body_full = malloc((body_full_len+1)*sizeof(char));
  snprintf(body_full, (body_full_len + 1), "%s.%s", b64_header, b64_payload);
  body_dat.data = (void*)body_full;
  body_dat.size = strlen(body_full);
  if (jwt != NULL) {
    if (jwt->alg == JWT_ALG_RS256) {
      hash = GNUTLS_DIG_SHA256;
    } else if (jwt->alg == JWT_ALG_RS384) {
      hash = GNUTLS_DIG_SHA384;
    } else if (jwt->alg == JWT_ALG_RS512) {
      hash = GNUTLS_DIG_SHA512;
    }
    if (hash != GNUTLS_DIG_NULL) {
      gnutls_x509_privkey_init(&key);
      gnutls_x509_privkey_import(key, &key_dat, GNUTLS_X509_FMT_PEM);
      gnutls_privkey_init(&privkey);
      gnutls_privkey_import_x509(privkey, key, 0);
      gnutls_privkey_sign_data(privkey, hash, 0, &body_dat, &sig_dat);
      b64_sig = malloc(2*sig_dat.size*sizeof(char));
      base64_encode((char *)sig_dat.data, sig_dat.size, b64_sig, &b64_len);
      base64uri_encode(b64_sig);
      gnutls_x509_privkey_deinit(key);
      gnutls_privkey_deinit(privkey);
    }
  }
  
  free(body_full);
  return b64_sig;
}

char * jwt_generate_signature_rsa(jwt_t *jwt, const char * b64_header, const char * b64_payload) {
  char * b64_sig = NULL;
  gnutls_x509_privkey_t key;
  gnutls_privkey_t privkey;
  char * body_full;
  size_t body_full_len, b64_len;
  gnutls_datum_t key_dat = {(void *) jwt->key, jwt->key_len}, body_dat, sig_dat;
  gnutls_digest_algorithm_t hash = GNUTLS_DIG_NULL;
  
  body_full_len = snprintf(NULL, 0, "%s.%s", b64_header, b64_payload);
  body_full = malloc((body_full_len+1)*sizeof(char));
  snprintf(body_full, (body_full_len + 1), "%s.%s", b64_header, b64_payload);
  body_dat.data = (void*)body_full;
  body_dat.size = strlen(body_full);
  if (jwt != NULL) {
    if (jwt->alg == JWT_ALG_RS256) {
      hash = GNUTLS_DIG_SHA256;
    } else if (jwt->alg == JWT_ALG_RS384) {
      hash = GNUTLS_DIG_SHA384;
    } else if (jwt->alg == JWT_ALG_RS512) {
      hash = GNUTLS_DIG_SHA512;
    }
    if (hash != GNUTLS_DIG_NULL) {
      gnutls_x509_privkey_init(&key);
      gnutls_x509_privkey_import(key, &key_dat, GNUTLS_X509_FMT_PEM);
      gnutls_privkey_init(&privkey);
      gnutls_privkey_import_x509(privkey, key, 0);
      gnutls_privkey_sign_data(privkey, hash, 0, &body_dat, &sig_dat);
      b64_sig = malloc(2*sig_dat.size*sizeof(char));
      base64_encode((char *)sig_dat.data, sig_dat.size, b64_sig, &b64_len);
      base64uri_encode(b64_sig);
      gnutls_x509_privkey_deinit(key);
      gnutls_privkey_deinit(privkey);
    }
  }
  
  free(body_full);
  return b64_sig;
}

char * jwt_generate_signature(jwt_t *jwt, const int pretty, const char * encoded_header, const char * encoded_payload) {
  char * str_header = NULL, * str_payload = NULL, * b64_header = NULL, * b64_payload = NULL, * str_sig = NULL, * b64_sig = NULL, * tmp = NULL;
  size_t b64_header_len, b64_payload_len, b64_sig_len, tmp_s;
  
  if (encoded_header == NULL) {
    str_header = dump_head(jwt, pretty);
    b64_header = malloc((2*strlen(str_header)+1) * sizeof(char));
    base64_encode(str_header, strlen(str_header), b64_header, &b64_header_len);
    base64uri_encode(b64_header);
  } else {
    b64_header = strdup(encoded_header);
  }
  
  if (encoded_payload == NULL) {
    str_payload = json_dumps(jwt->grants, (pretty?JSON_INDENT(2):JSON_COMPACT) | JSON_SORT_KEYS);
    b64_payload = malloc((2*strlen(str_payload)+1) * sizeof(char));
    base64_encode(str_payload, strlen(str_payload), b64_payload, &b64_payload_len);
    base64uri_encode(b64_payload);
  } else {
    b64_payload = strdup(encoded_payload);
  }
  
  if (jwt != NULL) {
    if (jwt->alg == JWT_ALG_NONE) {
      b64_sig = strdup("");
      b64_sig_len = 0;
    } else if (jwt->alg == JWT_ALG_ES256) {
      // TODO
    } else if (jwt->alg == JWT_ALG_ES384) {
      // TODO
    } else if (jwt->alg == JWT_ALG_ES512) {
      b64_sig = jwt_generate_signature_ec(jwt, b64_header, b64_payload);
    } else if (jwt->alg == JWT_ALG_RS256) {
      b64_sig = jwt_generate_signature_rsa(jwt, b64_header, b64_payload);
    } else if (jwt->alg == JWT_ALG_RS384) {
      b64_sig = jwt_generate_signature_rsa(jwt, b64_header, b64_payload);
    } else if (jwt->alg == JWT_ALG_RS512) {
      b64_sig = jwt_generate_signature_rsa(jwt, b64_header, b64_payload);
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
  }
  
  free(str_header);
  free(str_payload);
  free(b64_header);
  free(b64_payload);
  free(str_sig);
  free(tmp);
  return b64_sig;
}

void base64uri_decode(char * b64) {
  int i, z;
  size_t len;
  if (b64 != NULL) {
    len = strlen(b64);
    for (i = 0; i < len; i++) {
      switch (b64[i]) {
      case '-':
        b64[i] = '+';
        break;
      case '_':
        b64[i] = '/';
        break;
      default:
        b64[i] = b64[i];
      }
    }
    z = 4 - (i % 4);
    if (z < 4) {
      while (z--)
        b64[i++] = '=';
    }
    b64[i] = '\0';
  }
  
}

static int jwt_verify_sha_pem(jwt_t *jwt, const gnutls_digest_algorithm_t alg, const char *head, const char *sig_b64) {
  char * tmp;
  size_t tmp_len, sig_len;
  int res = EINVAL;
  gnutls_pubkey_t pubkey;
  char * sig_b64_dup = strdup(sig_b64);
  char * sig_dec;
  gnutls_datum_t cert_dat = {(void *) jwt->key, jwt->key_len}, data, sig;
  
  printf("grut 0\n");
  base64uri_decode(sig_b64_dup);
  sig_dec = base64_decode(sig_b64_dup, &sig_len);
  sig.data = (void*)sig_dec;
  sig.size = sig_len;
  printf("grut 1 %s\n", head);
  free(sig_b64_dup);
  
  if (head != NULL) {
    tmp = strdup(head);
    tmp_len = strlen(tmp);
  } else if (jwt != NULL) {
    char * str_header, * b64_header, * str_payload, * b64_payload;
    size_t b64_payload_len, b64_header_len;
    
    str_header = dump_head(jwt, 0);
    b64_header = malloc((2*strlen(str_header)+1) * sizeof(char));
    base64_encode(str_header, strlen(str_header), b64_header, &b64_header_len);
    base64uri_encode(b64_header);
    str_payload = json_dumps(jwt->grants, JSON_COMPACT | JSON_SORT_KEYS);
    b64_payload = malloc((2*strlen(str_payload)+1) * sizeof(char));
    base64_encode(str_payload, strlen(str_payload), b64_payload, &b64_payload_len);
    base64uri_encode(b64_payload);
    tmp_len = snprintf(NULL, 0, "%s.%s", b64_header, b64_payload);
    tmp = malloc((tmp_len + 1)*sizeof(char));
    snprintf(tmp, (tmp_len + 1), "%s.%s", b64_header, b64_payload);
  } else {
    return EINVAL;
  }
  data.data = (void*)tmp;
  data.size = tmp_len;
  gnutls_pubkey_init(&pubkey);
  res = gnutls_pubkey_import(pubkey, &cert_dat, GNUTLS_X509_FMT_PEM);
  //printf("head is %s\nsig is %s\n", tmp, sig_b64);
  if (res) {
    printf("fail gnutls_pubkey_import: %s\n", gnutls_strerror(res));
  }
  res = gnutls_pubkey_verify_data2(pubkey, alg, 0, &data, &sig);
  printf("res is %d: %s\n", res, gnutls_strerror(res));
  free(tmp);
  gnutls_pubkey_deinit(pubkey);
  return res;
}

static int jwt_verify_sha_hmac(jwt_t *jwt, const gnutls_digest_algorithm_t alg, const char *head, const char *sig_check) {
  char * tmp, * str_sig, * b64_sig;
  size_t  b64_sig_len, tmp_len;
  int res = EINVAL;
  
  if (head != NULL) {
    tmp = strdup(head);
  } else if (jwt != NULL) {
    char * str_header, * b64_header, * str_payload, * b64_payload;
    size_t b64_payload_len, b64_header_len;
    
    str_header = dump_head(jwt, 0);
    b64_header = malloc((2*strlen(str_header)+1) * sizeof(char));
    base64_encode(str_header, strlen(str_header), b64_header, &b64_header_len);
    base64uri_encode(b64_header);
    str_payload = json_dumps(jwt->grants, JSON_COMPACT | JSON_SORT_KEYS);
    b64_payload = malloc((2*strlen(str_payload)+1) * sizeof(char));
    base64_encode(str_payload, strlen(str_payload), b64_payload, &b64_payload_len);
    base64uri_encode(b64_payload);
    tmp_len = snprintf(NULL, 0, "%s.%s", b64_header, b64_payload);
    tmp = malloc((tmp_len + 1)*sizeof(char));
    snprintf(tmp, (tmp_len + 1), "%s.%s", b64_header, b64_payload);
  } else {
    return EINVAL;
  }
  str_sig = malloc(gnutls_hmac_get_len(alg)*sizeof(char));
  gnutls_hmac_fast(alg, jwt->key, jwt->key_len, tmp, strlen(tmp), str_sig);
  b64_sig = malloc(2*gnutls_hmac_get_len(alg)*sizeof(char));
  base64_encode(str_sig, gnutls_hmac_get_len(alg)*sizeof(char), b64_sig, &b64_sig_len);
  base64uri_encode(b64_sig);
  res = strcmp(b64_sig, sig_check);
  free(tmp);
  free(str_sig);
  free(b64_sig);
  return res;
}

#define SIGN_ERROR(__err) ({ ret = __err; goto jwt_sign_sha_pem_done; })

#define VERIFY_ERROR(__err) ({ ret = __err; goto jwt_verify_sha_pem_done; })

static int jwt_verify(jwt_t *jwt, const char *head, const char *sig)
{
	switch (jwt->alg) {
	case JWT_ALG_HS256:
		return jwt_verify_sha_hmac(jwt, GNUTLS_DIG_SHA256, head, sig);
	case JWT_ALG_HS384:
		return jwt_verify_sha_hmac(jwt, GNUTLS_DIG_SHA384, head, sig);
	case JWT_ALG_HS512:
		return jwt_verify_sha_hmac(jwt, GNUTLS_DIG_SHA512, head, sig);

	case JWT_ALG_RS256:
		return jwt_verify_sha_pem(jwt, GNUTLS_DIG_SHA256, head, sig);
	case JWT_ALG_RS384:
		return jwt_verify_sha_pem(jwt, GNUTLS_DIG_SHA384, head, sig);
	case JWT_ALG_RS512:
		return jwt_verify_sha_pem(jwt, GNUTLS_DIG_SHA512, head, sig);

	/*case JWT_ALG_ES256:
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

int jwt_dump_fp(jwt_t *jwt, FILE *fp, int pretty)
{
  int res;
  char * dump_str;
  
  if (jwt != NULL && fp != NULL) {
    dump_str = jwt_dump_str(jwt, pretty);
    res = fputs(dump_str, fp);
    free(dump_str);
    if (res == EOF) {
      return ENOMEM;
    } else {
      return 0;
    }
  } else {
    return ENOMEM;
  }
}

char *jwt_dump_str(jwt_t *jwt, int pretty)
{
  char * str_header = NULL, * str_payload = NULL, * b64_header = NULL, * b64_payload = NULL, * b64_sig = NULL, * out = NULL;
  size_t b64_header_len, b64_payload_len, out_len;
  
  str_header = dump_head(jwt, pretty);
  b64_header = malloc((2*strlen(str_header)+1) * sizeof(char));
  base64_encode(str_header, strlen(str_header), b64_header, &b64_header_len);
  base64uri_encode(b64_header);
  str_payload = json_dumps(jwt->grants, (pretty?JSON_INDENT(2):JSON_COMPACT) | JSON_SORT_KEYS);
  b64_payload = malloc((2*strlen(str_payload)+1) * sizeof(char));
  base64_encode(str_payload, strlen(str_payload), b64_payload, &b64_payload_len);
  base64uri_encode(b64_payload);
  
  b64_sig = jwt_generate_signature(jwt, pretty, b64_header, b64_payload);
  
  out_len = snprintf(NULL, 0, "%s.%s.%s", b64_header, b64_payload, b64_sig);
  out = malloc((out_len + 1)*sizeof(char));
  snprintf(out, (out_len + 1), "%s.%s.%s", b64_header, b64_payload, b64_sig);
  free(str_header);
  free(str_payload);
  free(b64_header);
  free(b64_payload);
  free(b64_sig);
  return out;
}

int jwt_encode_fp(jwt_t *jwt, FILE *fp)
{
  return jwt_dump_fp(jwt, fp, 0);
}

char *jwt_encode_str(jwt_t *jwt) {
  return jwt_dump_str(jwt, 0);
}
