// SPDX-License-Identifier: CDDL-1.0
/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * https://opensource.org/license/CDDL-1.0.
 */

/*
 * Copyright (c) 2017, Datto, Inc. All rights reserved.
 * Copyright 2020 Joyent, Inc.
 * Copyright 2026 Oxide Computer Company
 */

#include <sys/fs/zfs.h>
#include <sys/dsl_crypt.h>
#include <termios.h>
#include <signal.h>
#include <errno.h>
#include <openssl/evp.h>
#if LIBFETCH_DYNAMIC
#include <dlfcn.h>
#endif
#if LIBFETCH_IS_FETCH
#include <sys/param.h>
#include <stdio.h>
#include <fetch.h>
#elif LIBFETCH_IS_LIBCURL
#include <curl/curl.h>
#endif
#include <libzfs.h>
#include <libzutil.h>
#include "libzfs_impl.h"
#include "zfeature_common.h"

/*
 * User keys are used to decrypt the master encryption keys of a dataset. This
 * indirection allows a user to change his / her access key without having to
 * re-encrypt the entire dataset. User keys can be provided in one of several
 * ways. Raw keys are simply given to the kernel as is. Similarly, hex keys
 * are converted to binary and passed into the kernel. Password based keys are
 * a bit more complicated. Passwords alone do not provide suitable entropy for
 * encryption and may be too short or too long to be used. In order to derive
 * a more appropriate key we use a PBKDF2 function. This function is designed
 * to take a (relatively) long time to calculate in order to discourage
 * attackers from guessing from a list of common passwords. PBKDF2 requires
 * 2 additional parameters. The first is the number of iterations to run, which
 * will ultimately determine how long it takes to derive the resulting key from
 * the password. The second parameter is a salt that is randomly generated for
 * each dataset. The salt is used to "tweak" PBKDF2 such that a group of
 * attackers cannot reasonably generate a table of commonly known passwords to
 * their output keys and expect it work for all past and future PBKDF2 users.
 * We store the salt as a hidden property of the dataset (although it is
 * technically ok if the salt is known to the attacker).
 */

#define	MIN_PASSPHRASE_LEN 8
#define	MAX_PASSPHRASE_LEN 512
#define	MAX_KEY_PROMPT_ATTEMPTS 3

static int caught_interrupt;

static int get_key_material_file(libzfs_handle_t *, const char *, const char *,
    zfs_keyformat_t, boolean_t, uint8_t **, size_t *);
static int get_key_material_https(libzfs_handle_t *, const char *, const char *,
    zfs_keyformat_t, boolean_t, uint8_t **, size_t *);

static zfs_uri_handler_t uri_handlers[] = {
	{ "file", get_key_material_file },
	{ "https", get_key_material_https },
	{ "http", get_key_material_https },
	{ NULL, NULL }
};

static int
pkcs11_get_urandom(uint8_t *buf, size_t bytes)
{
	int rand;
	ssize_t bytes_read = 0;

	rand = open("/dev/urandom", O_RDONLY | O_CLOEXEC);

	if (rand < 0)
		return (rand);

	while (bytes_read < bytes) {
		ssize_t rc = read(rand, buf + bytes_read, bytes - bytes_read);
		if (rc < 0)
			break;
		bytes_read += rc;
	}

	(void) close(rand);

	return (bytes_read);
}

static int
zfs_prop_parse_keylocation(libzfs_handle_t *restrict hdl, const char *str,
    zfs_keylocation_t *restrict locp, char **restrict schemep)
{
	*locp = ZFS_KEYLOCATION_NONE;
	*schemep = NULL;

	if (strcmp("prompt", str) == 0) {
		*locp = ZFS_KEYLOCATION_PROMPT;
		return (0);
	}

	regmatch_t pmatch[2];

	if (regexec(&hdl->libzfs_urire, str, ARRAY_SIZE(pmatch),
	    pmatch, 0) == 0) {
		size_t scheme_len;

		if (pmatch[1].rm_so == -1) {
			zfs_error_aux(hdl,
			    "Invalid URI");
			return (EINVAL);
		}

		scheme_len = pmatch[1].rm_eo - pmatch[1].rm_so;

		*schemep = calloc(1, scheme_len + 1);
		if (*schemep == NULL) {
			int ret = errno;

			errno = 0;
			zfs_error_aux(hdl,
			    "Invalid URI");
			return (ret);
		}

		(void) memcpy(*schemep, str + pmatch[1].rm_so, scheme_len);
		*locp = ZFS_KEYLOCATION_URI;
		return (0);
	}

	zfs_error_aux(hdl, "Invalid keylocation");
	return (EINVAL);
}

static int
hex_key_to_raw(char *hex, int hexlen, uint8_t *out)
{
	int ret, i;
	unsigned int c;

	for (i = 0; i < hexlen; i += 2) {
		if (!isxdigit(hex[i]) || !isxdigit(hex[i + 1])) {
			ret = EINVAL;
			goto error;
		}

		ret = sscanf(&hex[i], "%02x", &c);
		if (ret != 1) {
			ret = EINVAL;
			goto error;
		}

		out[i / 2] = c;
	}

	return (0);

error:
	return (ret);
}


static void
catch_signal(int sig)
{
	caught_interrupt = sig;
}

static const char *
get_format_prompt_string(zfs_keyformat_t format)
{
	switch (format) {
	case ZFS_KEYFORMAT_RAW:
		return ("raw key");
	case ZFS_KEYFORMAT_HEX:
		return ("hex key");
	case ZFS_KEYFORMAT_PASSPHRASE:
		return ("passphrase");
	default:
		/* shouldn't happen */
		return (NULL);
	}
}

/* do basic validation of the key material */
static int
validate_key(libzfs_handle_t *hdl, zfs_keyformat_t keyformat,
    const char *key, size_t keylen, boolean_t do_verify)
{
	switch (keyformat) {
	case ZFS_KEYFORMAT_RAW:
		/* verify the key length is correct */
		if (keylen < WRAPPING_KEY_LEN) {
			zfs_error_aux(hdl,
			    "Raw key too short (expected %u).",
			    WRAPPING_KEY_LEN);
			return (EINVAL);
		}

		if (keylen > WRAPPING_KEY_LEN) {
			zfs_error_aux(hdl,
			    "Raw key too long (expected %u).",
			    WRAPPING_KEY_LEN);
			return (EINVAL);
		}
		break;
	case ZFS_KEYFORMAT_HEX:
		/* verify the key length is correct */
		if (keylen < WRAPPING_KEY_LEN * 2) {
			zfs_error_aux(hdl,
			    "Hex key too short (expected %u).",
			    WRAPPING_KEY_LEN * 2);
			return (EINVAL);
		}

		if (keylen > WRAPPING_KEY_LEN * 2) {
			zfs_error_aux(hdl,
			    "Hex key too long (expected %u).",
			    WRAPPING_KEY_LEN * 2);
			return (EINVAL);
		}

		/* check for invalid hex digits */
		for (size_t i = 0; i < WRAPPING_KEY_LEN * 2; i++) {
			if (!isxdigit(key[i])) {
				zfs_error_aux(hdl,
				    "Invalid hex character detected.");
				return (EINVAL);
			}
		}
		break;
	case ZFS_KEYFORMAT_PASSPHRASE:
		/*
		 * Verify the length is within bounds when setting a new key,
		 * but not when loading an existing key.
		 */
		if (!do_verify)
			break;
		if (keylen > MAX_PASSPHRASE_LEN) {
			zfs_error_aux(hdl,
			    "Passphrase too long (max %u).",
			    MAX_PASSPHRASE_LEN);
			return (EINVAL);
		}

		if (keylen < MIN_PASSPHRASE_LEN) {
			zfs_error_aux(hdl,
			    "Passphrase too short (min %u).",
			    MIN_PASSPHRASE_LEN);
			return (EINVAL);
		}
		break;
	default:
		/* can't happen, checked above */
		break;
	}

	return (0);
}

static int
libzfs_getpassphrase(zfs_keyformat_t keyformat, boolean_t is_reenter,
    boolean_t new_key, const char *fsname,
    char **restrict res, size_t *restrict reslen)
{
	FILE *stream = stdin;
	size_t buflen = 0;
	ssize_t bytes;
	int ret = 0;
	struct termios old_term, new_term;
	struct sigaction act, osigint, osigtstp;

	*res = NULL;
	*reslen = 0;

	/*
	 * handle SIGINT and ignore SIGSTP. This is necessary to
	 * restore the state of the terminal.
	 */
	caught_interrupt = 0;
	act.sa_flags = 0;
	(void) sigemptyset(&act.sa_mask);
	act.sa_handler = catch_signal;

	(void) sigaction(SIGINT, &act, &osigint);
	act.sa_handler = SIG_IGN;
	(void) sigaction(SIGTSTP, &act, &osigtstp);

	(void) printf("%s %s%s",
	    is_reenter ? "Re-enter" : "Enter",
	    new_key ? "new " : "",
	    get_format_prompt_string(keyformat));
	if (fsname != NULL)
		(void) printf(" for '%s'", fsname);
	(void) fputc(':', stdout);
	(void) fflush(stdout);

	/* disable the terminal echo for key input */
	(void) tcgetattr(fileno(stream), &old_term);

	new_term = old_term;
	new_term.c_lflag &= ~(ECHO | ECHOE | ECHOK | ECHONL);

	ret = tcsetattr(fileno(stream), TCSAFLUSH, &new_term);
	if (ret != 0) {
		ret = errno;
		errno = 0;
		goto out;
	}

	bytes = getline(res, &buflen, stream);
	if (bytes < 0) {
		ret = errno;
		errno = 0;
		goto out;
	}

	/* trim the ending newline if it exists */
	if (bytes > 0 && (*res)[bytes - 1] == '\n') {
		(*res)[bytes - 1] = '\0';
		bytes--;
	}

	*reslen = bytes;

out:
	/* reset the terminal */
	(void) tcsetattr(fileno(stream), TCSAFLUSH, &old_term);
	(void) sigaction(SIGINT, &osigint, NULL);
	(void) sigaction(SIGTSTP, &osigtstp, NULL);

	/* if we caught a signal, re-throw it now */
	if (caught_interrupt != 0)
		(void) kill(getpid(), caught_interrupt);

	/* print the newline that was not echo'd */
	(void) printf("\n");

	return (ret);
}

static int
get_key_interactive(libzfs_handle_t *restrict hdl, const char *fsname,
    zfs_keyformat_t keyformat, boolean_t confirm_key, boolean_t newkey,
    uint8_t **restrict outbuf, size_t *restrict len_out)
{
	char *buf = NULL, *buf2 = NULL;
	size_t buflen = 0, buf2len = 0;
	int ret = 0;

	ASSERT(isatty(fileno(stdin)));

	/* raw keys cannot be entered on the terminal */
	if (keyformat == ZFS_KEYFORMAT_RAW) {
		ret = EINVAL;
		zfs_error_aux(hdl,
		    "Cannot enter raw keys on the terminal");
		goto out;
	}

	/* prompt for the key */
	if ((ret = libzfs_getpassphrase(keyformat, B_FALSE, newkey, fsname,
	    &buf, &buflen)) != 0) {
		free(buf);
		buf = NULL;
		buflen = 0;
		goto out;
	}

	if (!confirm_key)
		goto out;

	if ((ret = validate_key(hdl, keyformat, buf, buflen, confirm_key)) !=
	    0) {
		free(buf);
		return (ret);
	}

	ret = libzfs_getpassphrase(keyformat, B_TRUE, newkey, fsname, &buf2,
	    &buf2len);
	if (ret != 0) {
		free(buf);
		free(buf2);
		buf = buf2 = NULL;
		buflen = buf2len = 0;
		goto out;
	}

	if (buflen != buf2len || strcmp(buf, buf2) != 0) {
		free(buf);
		buf = NULL;
		buflen = 0;

		ret = EINVAL;
		zfs_error_aux(hdl,
		    "Provided keys do not match.");
	}

	free(buf2);

out:
	*outbuf = (uint8_t *)buf;
	*len_out = buflen;
	return (ret);
}

static int
get_key_material_stream(FILE *stream, zfs_keyformat_t keyformat,
    uint8_t **buf, size_t *len_out)
{
	int ret = 0;
	size_t buflen = 0;

	*len_out = 0;

	/* read the key material */
	if (keyformat != ZFS_KEYFORMAT_RAW) {
		ssize_t bytes;

		bytes = getline((char **)buf, &buflen, stream);
		if (bytes < 0) {
			ret = errno;
			errno = 0;
			goto out;
		}

		/* trim the ending newline if it exists */
		if (bytes > 0 && (*buf)[bytes - 1] == '\n') {
			(*buf)[bytes - 1] = '\0';
			bytes--;
		}

		*len_out = bytes;
	} else {
		size_t n;

		/*
		 * Raw keys may have newline characters in them and so can't
		 * use getline(). Here we attempt to read 33 bytes so that we
		 * can properly check the key length (the file should only have
		 * 32 bytes).
		 */
		*buf = malloc((WRAPPING_KEY_LEN + 1) * sizeof (uint8_t));
		if (*buf == NULL) {
			ret = ENOMEM;
			goto out;
		}

		n = fread(*buf, 1, WRAPPING_KEY_LEN + 1, stream);
		if (n == 0 || ferror(stream)) {
			/* size errors are handled by the calling function */
			free(*buf);
			*buf = NULL;
			ret = errno;
			errno = 0;
			goto out;
		}

		*len_out = n;
	}
out:
	return (ret);
}

static int
get_key_material_file(libzfs_handle_t *hdl, const char *uri,
    const char *fsname, zfs_keyformat_t keyformat, boolean_t newkey,
    uint8_t **restrict buf, size_t *restrict len_out)
{
	(void) fsname, (void) newkey;
	FILE *stream = NULL;
	int ret = 0;

	if (strlen(uri) < 7)
		return (EINVAL);

	if ((stream = fopen(uri + 7, "re")) == NULL) {
		ret = errno;
		errno = 0;
		zfs_error_aux(hdl,
		    "Failed to open key material file: %s", zfs_strerror(ret));
		return (ret);
	}

	ret = get_key_material_stream(stream, keyformat, buf, len_out);

	(void) fclose(stream);

	return (ret);
}

static int
get_key_material_https(libzfs_handle_t *hdl, const char *uri,
    const char *fsname, zfs_keyformat_t keyformat, boolean_t newkey,
    uint8_t **restrict buf, size_t *restrict len_out)
{
	(void) fsname, (void) newkey;
	int ret = 0;
	FILE *stream = NULL;
	boolean_t is_http = strncmp(uri, "http:", strlen("http:")) == 0;

	if (strlen(uri) < (is_http ? 7 : 8)) {
		ret = EINVAL;
		goto end;
	}

#if LIBFETCH_DYNAMIC
#define	LOAD_FUNCTION(func) \
	__typeof__(func) *func = dlsym(hdl->libfetch, #func);

	if (hdl->libfetch == NULL)
		hdl->libfetch = dlopen(LIBFETCH_SONAME, RTLD_LAZY);

	if (hdl->libfetch == NULL) {
		hdl->libfetch = (void *)-1;
		char *err = dlerror();
		if (err)
			hdl->libfetch_load_error = strdup(err);
	}

	if (hdl->libfetch == (void *)-1) {
		ret = ENOSYS;
		zfs_error_aux(hdl,
		    "Couldn't load %s: %s",
		    LIBFETCH_SONAME, hdl->libfetch_load_error ?: "(?)");
		goto end;
	}

	boolean_t ok;
#if LIBFETCH_IS_FETCH
	LOAD_FUNCTION(fetchGetURL);
	char *fetchLastErrString = dlsym(hdl->libfetch, "fetchLastErrString");

	ok = fetchGetURL && fetchLastErrString;
#elif LIBFETCH_IS_LIBCURL
	LOAD_FUNCTION(curl_easy_init);
	LOAD_FUNCTION(curl_easy_setopt);
	LOAD_FUNCTION(curl_easy_perform);
	LOAD_FUNCTION(curl_easy_cleanup);
	LOAD_FUNCTION(curl_easy_strerror);
	LOAD_FUNCTION(curl_easy_getinfo);

	ok = curl_easy_init && curl_easy_setopt && curl_easy_perform &&
	    curl_easy_cleanup && curl_easy_strerror && curl_easy_getinfo;
#endif
	if (!ok) {
		zfs_error_aux(hdl,
		    "keylocation=%s back-end %s missing symbols.",
		    is_http ? "http://" : "https://", LIBFETCH_SONAME);
		ret = ENOSYS;
		goto end;
	}
#endif

#if LIBFETCH_IS_FETCH
	stream = fetchGetURL(uri, "");
	if (stream == NULL) {
		zfs_error_aux(hdl,
		    "Couldn't GET %s: %s",
		    uri, fetchLastErrString);
		ret = ENETDOWN;
	}
#elif LIBFETCH_IS_LIBCURL
	CURL *curl = curl_easy_init();
	if (curl == NULL) {
		ret = ENOTSUP;
		goto end;
	}

	/* max len + optional newline + terminator */
	char keybuf[MAX_PASSPHRASE_LEN+2];
	memset(keybuf, 0, sizeof (keybuf));

	/*
	 * Open a stream over keybuf. The "length" of the stream is
	 * WRAPPING_KEY_LEN for raw keys, which is checked and enforced in
	 * get_key_material_stream() and validate_key(). For "line" formats,
	 * the entire buffer is allowed, which has enough room for the
	 * longest possible passphrase, newline and terminator.
	 */
	if ((stream = fmemopen(keybuf,
	    keyformat == ZFS_KEYFORMAT_RAW ?
	    WRAPPING_KEY_LEN : sizeof (keybuf), "r+")) == NULL) {
		ret = errno;
		zfs_error_aux(hdl,
		    "Couldn't open memory stream: %s", zfs_strerror(ret));
		goto end;
	}

	/*
	 * Disable buffering on in-memory stream, so that curl sees errors
	 * (eg writing past the end) immediately.
	 */
	setbuf(stream, NULL);

	char errbuf[CURL_ERROR_SIZE] = "";
	char *cainfo = getenv("SSL_CA_CERT_FILE"); /* matches fetch(3) */
	char *capath = getenv("SSL_CA_CERT_PATH"); /* matches fetch(3) */
	char *clcert = getenv("SSL_CLIENT_CERT_FILE"); /* matches fetch(3) */
	char *clkey  = getenv("SSL_CLIENT_KEY_FILE"); /* matches fetch(3) */
	(void) curl_easy_setopt(curl, CURLOPT_URL, uri);
	(void) curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
	(void) curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, 30000L);
	(void) curl_easy_setopt(curl, CURLOPT_WRITEDATA, stream);
	(void) curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, errbuf);
	if (cainfo != NULL)
		(void) curl_easy_setopt(curl, CURLOPT_CAINFO, cainfo);
	if (capath != NULL)
		(void) curl_easy_setopt(curl, CURLOPT_CAPATH, capath);
	if (clcert != NULL)
		(void) curl_easy_setopt(curl, CURLOPT_SSLCERT, clcert);
	if (clkey != NULL)
		(void) curl_easy_setopt(curl, CURLOPT_SSLKEY, clkey);

	CURLcode res = curl_easy_perform(curl);

	if (res != CURLE_OK) {
		zfs_error_aux(hdl,
		    "Failed to connect to %s: %s",
		    uri, strlen(errbuf) ? errbuf : curl_easy_strerror(res));
		ret = ENETDOWN;
	} else {
		long resp = 200;
		(void) curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &resp);

		if (resp < 200 || resp >= 300) {
			zfs_error_aux(hdl,
			    "Couldn't GET %s: %ld",
			    uri, resp);
			ret = ENOENT;
		} else
			rewind(stream);
	}

	curl_easy_cleanup(curl);
#else
	zfs_error_aux(hdl,
	    "No keylocation=%s back-end.", is_http ? "http://" : "https://");
	ret = ENOSYS;
#endif

end:
	if (ret == 0)
		ret = get_key_material_stream(stream, keyformat, buf, len_out);

	if (stream != NULL)
		fclose(stream);

	return (ret);
}

/*
 * Attempts to fetch key material, no matter where it might live. The key
 * material is allocated and returned in km_out. *can_retry_out will be set
 * to B_TRUE if the user is providing the key material interactively, allowing
 * for re-entry attempts.
 */
static int
get_key_material(libzfs_handle_t *hdl, boolean_t do_verify, boolean_t newkey,
    zfs_keyformat_t keyformat, const char *keylocation, const char *fsname,
    uint8_t **km_out, size_t *kmlen_out, boolean_t *can_retry_out)
{
	int ret;
	zfs_keylocation_t keyloc = ZFS_KEYLOCATION_NONE;
	uint8_t *km = NULL;
	size_t kmlen = 0;
	char *uri_scheme = NULL;
	zfs_uri_handler_t *handler = NULL;
	boolean_t can_retry = B_FALSE;

	/* verify and parse the keylocation */
	ret = zfs_prop_parse_keylocation(hdl, keylocation, &keyloc,
	    &uri_scheme);
	if (ret != 0)
		goto error;

	/* open the appropriate file descriptor */
	switch (keyloc) {
	case ZFS_KEYLOCATION_PROMPT:
		if (isatty(fileno(stdin))) {
			can_retry = keyformat != ZFS_KEYFORMAT_RAW;
			ret = get_key_interactive(hdl, fsname, keyformat,
			    do_verify, newkey, &km, &kmlen);
		} else {
			/* fetch the key material into the buffer */
			ret = get_key_material_stream(stdin, keyformat, &km,
			    &kmlen);
		}

		if (ret != 0)
			goto error;

		break;
	case ZFS_KEYLOCATION_URI:
		ret = ENOTSUP;

		for (handler = uri_handlers; handler->zuh_scheme != NULL;
		    handler++) {
			if (strcmp(handler->zuh_scheme, uri_scheme) != 0)
				continue;

			if ((ret = handler->zuh_handler(hdl, keylocation,
			    fsname, keyformat, newkey, &km, &kmlen)) != 0)
				goto error;

			break;
		}

		if (ret == ENOTSUP) {
			zfs_error_aux(hdl,
			    "URI scheme is not supported");
			goto error;
		}

		break;
	default:
		ret = EINVAL;
		zfs_error_aux(hdl,
		    "Invalid keylocation.");
		goto error;
	}

	if ((ret = validate_key(hdl, keyformat, (const char *)km, kmlen,
	    do_verify)) != 0)
		goto error;

	*km_out = km;
	*kmlen_out = kmlen;
	if (can_retry_out != NULL)
		*can_retry_out = can_retry;

	free(uri_scheme);
	return (0);

error:
	free(km);

	*km_out = NULL;
	*kmlen_out = 0;

	if (can_retry_out != NULL)
		*can_retry_out = can_retry;

	free(uri_scheme);
	return (ret);
}

static int
derive_key(libzfs_handle_t *hdl, zfs_keyformat_t format, uint64_t iters,
    uint8_t *key_material, uint64_t salt,
    uint8_t **key_out)
{
	int ret;
	uint8_t *key;

	*key_out = NULL;

	key = zfs_alloc(hdl, WRAPPING_KEY_LEN);

	switch (format) {
	case ZFS_KEYFORMAT_RAW:
		memcpy(key, key_material, WRAPPING_KEY_LEN);
		break;
	case ZFS_KEYFORMAT_HEX:
		ret = hex_key_to_raw((char *)key_material,
		    WRAPPING_KEY_LEN * 2, key);
		if (ret != 0) {
			zfs_error_aux(hdl,
			    "Invalid hex key provided.");
			goto error;
		}
		break;
	case ZFS_KEYFORMAT_PASSPHRASE:
		salt = LE_64(salt);

		ret = PKCS5_PBKDF2_HMAC_SHA1((char *)key_material,
		    strlen((char *)key_material), ((uint8_t *)&salt),
		    sizeof (uint64_t), iters, WRAPPING_KEY_LEN, key);
		if (ret != 1) {
			ret = EIO;
			zfs_error_aux(hdl,
			    "Failed to generate key from passphrase.");
			goto error;
		}
		break;
	default:
		ret = EINVAL;
		goto error;
	}

	*key_out = key;
	return (0);

error:
	free(key);

	*key_out = NULL;
	return (ret);
}

static boolean_t
feature_is_enabled(zpool_handle_t *zph, spa_feature_t feat)
{
	nvlist_t *features;
	uint64_t feat_refcount;

	/* check that features can be enabled */
	if (zpool_get_prop_int(zph, ZPOOL_PROP_VERSION, NULL)
	    < SPA_VERSION_FEATURES)
		return (B_FALSE);

	features = zpool_get_features(zph);
	if (!features || nvlist_lookup_uint64(features,
	    spa_feature_table[feat].fi_guid, &feat_refcount) != 0)
		return (B_FALSE);

	return (B_TRUE);
}

static boolean_t
encryption_feature_is_enabled(zpool_handle_t *zph)
{
	return (feature_is_enabled(zph, SPA_FEATURE_ENCRYPTION));
}

static int
populate_create_encryption_params_nvlists(libzfs_handle_t *hdl,
    zfs_handle_t *zhp, boolean_t newkey, zfs_keyformat_t keyformat,
    const char *keylocation, nvlist_t *props, uint8_t **wkeydata,
    uint_t *wkeylen)
{
	int ret;
	uint64_t iters = 0, salt = 0;
	uint8_t *key_material = NULL;
	size_t key_material_len = 0;
	uint8_t *key_data = NULL;
	const char *fsname = (zhp) ? zfs_get_name(zhp) : NULL;

	/* get key material from keyformat and keylocation */
	ret = get_key_material(hdl, B_TRUE, newkey, keyformat, keylocation,
	    fsname, &key_material, &key_material_len, NULL);
	if (ret != 0)
		goto error;

	/* passphrase formats require a salt and pbkdf2 iters property */
	if (keyformat == ZFS_KEYFORMAT_PASSPHRASE) {
		/* always generate a new salt */
		ret = pkcs11_get_urandom((uint8_t *)&salt, sizeof (uint64_t));
		if (ret != sizeof (uint64_t)) {
			zfs_error_aux(hdl,
			    "Failed to generate salt.");
			goto error;
		}

		ret = nvlist_add_uint64(props,
		    zfs_prop_to_name(ZFS_PROP_PBKDF2_SALT), salt);
		if (ret != 0) {
			zfs_error_aux(hdl,
			    "Failed to add salt to properties.");
			goto error;
		}

		/*
		 * If not otherwise specified, use the default number of
		 * pbkdf2 iterations. If specified, we have already checked
		 * that the given value is greater than MIN_PBKDF2_ITERATIONS
		 * during zfs_valid_proplist().
		 */
		ret = nvlist_lookup_uint64(props,
		    zfs_prop_to_name(ZFS_PROP_PBKDF2_ITERS), &iters);
		if (ret == ENOENT) {
			iters = DEFAULT_PBKDF2_ITERATIONS;
			ret = nvlist_add_uint64(props,
			    zfs_prop_to_name(ZFS_PROP_PBKDF2_ITERS), iters);
			if (ret != 0)
				goto error;
		} else if (ret != 0) {
			zfs_error_aux(hdl,
			    "Failed to get pbkdf2 iterations.");
			goto error;
		}
	} else {
		/* check that pbkdf2iters was not specified by the user */
		ret = nvlist_lookup_uint64(props,
		    zfs_prop_to_name(ZFS_PROP_PBKDF2_ITERS), &iters);
		if (ret == 0) {
			ret = EINVAL;
			zfs_error_aux(hdl,
			    "Cannot specify pbkdf2iters with a non-passphrase "
			    "keyformat.");
			goto error;
		}
	}

	/* derive a key from the key material */
	ret = derive_key(hdl, keyformat, iters, key_material, salt, &key_data);
	if (ret != 0)
		goto error;

	free(key_material);

	*wkeydata = key_data;
	*wkeylen = WRAPPING_KEY_LEN;
	return (0);

error:
	if (key_material != NULL)
		free(key_material);
	if (key_data != NULL)
		free(key_data);

	*wkeydata = NULL;
	*wkeylen = 0;
	return (ret);
}

static boolean_t
proplist_has_encryption_props(nvlist_t *props)
{
	int ret;
	uint64_t intval;
	const char *strval;

	ret = nvlist_lookup_uint64(props,
	    zfs_prop_to_name(ZFS_PROP_ENCRYPTION), &intval);
	if (ret == 0 && intval != ZIO_CRYPT_OFF)
		return (B_TRUE);

	ret = nvlist_lookup_string(props,
	    zfs_prop_to_name(ZFS_PROP_KEYLOCATION), &strval);
	if (ret == 0 && strcmp(strval, "none") != 0)
		return (B_TRUE);

	ret = nvlist_lookup_uint64(props,
	    zfs_prop_to_name(ZFS_PROP_KEYFORMAT), &intval);
	if (ret == 0)
		return (B_TRUE);

	ret = nvlist_lookup_uint64(props,
	    zfs_prop_to_name(ZFS_PROP_PBKDF2_ITERS), &intval);
	if (ret == 0)
		return (B_TRUE);

	return (B_FALSE);
}

int
zfs_crypto_get_encryption_root(zfs_handle_t *zhp, boolean_t *is_encroot,
    char *buf)
{
	int ret;
	char prop_encroot[MAXNAMELEN];

	/* if the dataset isn't encrypted, just return */
	if (zfs_prop_get_int(zhp, ZFS_PROP_ENCRYPTION) == ZIO_CRYPT_OFF) {
		*is_encroot = B_FALSE;
		if (buf != NULL)
			buf[0] = '\0';
		return (0);
	}

	ret = zfs_prop_get(zhp, ZFS_PROP_ENCRYPTION_ROOT, prop_encroot,
	    sizeof (prop_encroot), NULL, NULL, 0, B_TRUE);
	if (ret != 0) {
		*is_encroot = B_FALSE;
		if (buf != NULL)
			buf[0] = '\0';
		return (ret);
	}

	*is_encroot = strcmp(prop_encroot, zfs_get_name(zhp)) == 0;
	if (buf != NULL)
		strcpy(buf, prop_encroot);

	return (0);
}

/*
 * Return a copy of the encryption root's alternate key slots, keyed by slot
 * number. The stats channel carries them for the encryption root only, so
 * callers must pass a root handle. A root with no slots yields an empty
 * nvlist rather than an error; the copy belongs to the caller.
 */
int
zfs_crypto_get_keyslots(zfs_handle_t *zhp, nvlist_t **keyslots_out)
{
	nvlist_t *slots;

	if (zhp->zfs_props == NULL)
		return (EINVAL);

	if (nvlist_lookup_nvlist(zhp->zfs_props, "keyslots", &slots) != 0)
		return (nvlist_alloc(keyslots_out, NV_UNIQUE_NAME, 0));

	return (nvlist_dup(slots, keyslots_out, 0));
}

int
zfs_crypto_create(libzfs_handle_t *hdl, char *parent_name, nvlist_t *props,
    nvlist_t *pool_props, boolean_t stdin_available, uint8_t **wkeydata_out,
    uint_t *wkeylen_out)
{
	int ret;
	char errbuf[ERRBUFLEN];
	uint64_t crypt = ZIO_CRYPT_INHERIT, pcrypt = ZIO_CRYPT_INHERIT;
	uint64_t keyformat = ZFS_KEYFORMAT_NONE;
	const char *keylocation = NULL;
	zfs_handle_t *pzhp = NULL;
	uint8_t *wkeydata = NULL;
	uint_t wkeylen = 0;
	boolean_t local_crypt = B_TRUE;

	(void) snprintf(errbuf, sizeof (errbuf),
	    "Encryption create error");

	/* lookup crypt from props */
	ret = nvlist_lookup_uint64(props,
	    zfs_prop_to_name(ZFS_PROP_ENCRYPTION), &crypt);
	if (ret != 0)
		local_crypt = B_FALSE;

	/* lookup key location and format from props */
	(void) nvlist_lookup_uint64(props,
	    zfs_prop_to_name(ZFS_PROP_KEYFORMAT), &keyformat);
	(void) nvlist_lookup_string(props,
	    zfs_prop_to_name(ZFS_PROP_KEYLOCATION), &keylocation);

	if (parent_name != NULL) {
		/* get a reference to parent dataset */
		pzhp = make_dataset_handle(hdl, parent_name);
		if (pzhp == NULL) {
			ret = ENOENT;
			zfs_error_aux(hdl,
			    "Failed to lookup parent.");
			goto out;
		}

		/* Lookup parent's crypt */
		pcrypt = zfs_prop_get_int(pzhp, ZFS_PROP_ENCRYPTION);

		/* Params require the encryption feature */
		if (!encryption_feature_is_enabled(pzhp->zpool_hdl)) {
			if (proplist_has_encryption_props(props)) {
				ret = EINVAL;
				zfs_error_aux(hdl,
				    "Encryption feature not enabled.");
				goto out;
			}

			ret = 0;
			goto out;
		}
	} else {
		/*
		 * special case for root dataset where encryption feature
		 * feature won't be on disk yet
		 */
		if (!nvlist_exists(pool_props, "feature@encryption")) {
			if (proplist_has_encryption_props(props)) {
				ret = EINVAL;
				zfs_error_aux(hdl,
				    "Encryption feature not enabled.");
				goto out;
			}

			ret = 0;
			goto out;
		}

		pcrypt = ZIO_CRYPT_OFF;
	}

	/* Get the inherited encryption property if we don't have it locally */
	if (!local_crypt)
		crypt = pcrypt;

	/*
	 * At this point crypt should be the actual encryption value. If
	 * encryption is off just verify that no encryption properties have
	 * been specified and return.
	 */
	if (crypt == ZIO_CRYPT_OFF) {
		if (proplist_has_encryption_props(props)) {
			ret = EINVAL;
			zfs_error_aux(hdl,
			    "Encryption must be turned on to set encryption "
			    "properties.");
			goto out;
		}

		ret = 0;
		goto out;
	}

	/*
	 * If we have a parent crypt it is valid to specify encryption alone.
	 * This will result in a child that is encrypted with the chosen
	 * encryption suite that will also inherit the parent's key. If
	 * the parent is not encrypted we need an encryption suite provided.
	 */
	if (pcrypt == ZIO_CRYPT_OFF && keylocation == NULL &&
	    keyformat == ZFS_KEYFORMAT_NONE) {
		ret = EINVAL;
		zfs_error_aux(hdl,
		    "Keyformat required for new encryption root.");
		goto out;
	}

	/*
	 * Specifying a keylocation implies this will be a new encryption root.
	 * Check that a keyformat is also specified.
	 */
	if (keylocation != NULL && keyformat == ZFS_KEYFORMAT_NONE) {
		ret = EINVAL;
		zfs_error_aux(hdl,
		    "Keyformat required for new encryption root.");
		goto out;
	}

	/* default to prompt if no keylocation is specified */
	if (keyformat != ZFS_KEYFORMAT_NONE && keylocation == NULL) {
		keylocation = (char *)"prompt";
		ret = nvlist_add_string(props,
		    zfs_prop_to_name(ZFS_PROP_KEYLOCATION), keylocation);
		if (ret != 0)
			goto out;
	}

	/*
	 * If a local key is provided, this dataset will be a new
	 * encryption root. Populate the encryption params.
	 */
	if (keylocation != NULL) {
		/*
		 * 'zfs recv -o keylocation=prompt' won't work because stdin
		 * is being used by the send stream, so we disallow it.
		 */
		if (!stdin_available && strcmp(keylocation, "prompt") == 0) {
			ret = EINVAL;
			zfs_error_aux(hdl, "Cannot use "
			    "'prompt' keylocation because stdin is in use.");
			goto out;
		}

		ret = populate_create_encryption_params_nvlists(hdl, NULL,
		    B_TRUE, keyformat, keylocation, props, &wkeydata,
		    &wkeylen);
		if (ret != 0)
			goto out;
	}

	if (pzhp != NULL)
		zfs_close(pzhp);

	*wkeydata_out = wkeydata;
	*wkeylen_out = wkeylen;
	return (0);

out:
	if (pzhp != NULL)
		zfs_close(pzhp);
	if (wkeydata != NULL)
		free(wkeydata);

	*wkeydata_out = NULL;
	*wkeylen_out = 0;
	return (ret);
}

int
zfs_crypto_clone_check(libzfs_handle_t *hdl, zfs_handle_t *origin_zhp,
    char *parent_name, nvlist_t *props)
{
	(void) origin_zhp, (void) parent_name;
	char errbuf[ERRBUFLEN];

	(void) snprintf(errbuf, sizeof (errbuf),
	    "Encryption clone error");

	/*
	 * No encryption properties should be specified. They will all be
	 * inherited from the origin dataset.
	 */
	if (nvlist_exists(props, zfs_prop_to_name(ZFS_PROP_KEYFORMAT)) ||
	    nvlist_exists(props, zfs_prop_to_name(ZFS_PROP_KEYLOCATION)) ||
	    nvlist_exists(props, zfs_prop_to_name(ZFS_PROP_ENCRYPTION)) ||
	    nvlist_exists(props, zfs_prop_to_name(ZFS_PROP_PBKDF2_ITERS))) {
		zfs_error_aux(hdl,
		    "Encryption properties must inherit from origin dataset.");
		return (EINVAL);
	}

	return (0);
}

typedef struct loadkeys_cbdata {
	uint64_t cb_numfailed;
	uint64_t cb_numattempted;
} loadkey_cbdata_t;

static int
load_keys_cb(zfs_handle_t *zhp, void *arg)
{
	int ret;
	boolean_t is_encroot;
	loadkey_cbdata_t *cb = arg;
	uint64_t keystatus = zfs_prop_get_int(zhp, ZFS_PROP_KEYSTATUS);

	/* only attempt to load keys for encryption roots */
	ret = zfs_crypto_get_encryption_root(zhp, &is_encroot, NULL);
	if (ret != 0 || !is_encroot)
		goto out;

	/* don't attempt to load already loaded keys */
	if (keystatus == ZFS_KEYSTATUS_AVAILABLE)
		goto out;

	/* Attempt to load the key. Record status in cb. */
	cb->cb_numattempted++;

	ret = zfs_crypto_load_key(zhp, B_FALSE, NULL);
	if (ret)
		cb->cb_numfailed++;

out:
	(void) zfs_iter_filesystems_v2(zhp, 0, load_keys_cb, cb);
	zfs_close(zhp);

	/* always return 0, since this function is best effort */
	return (0);
}

/*
 * This function is best effort. It attempts to load all the keys for the given
 * filesystem and all of its children.
 */
int
zfs_crypto_attempt_load_keys(libzfs_handle_t *hdl, const char *fsname)
{
	int ret;
	zfs_handle_t *zhp = NULL;
	loadkey_cbdata_t cb = { 0 };

	zhp = zfs_open(hdl, fsname, ZFS_TYPE_FILESYSTEM | ZFS_TYPE_VOLUME);
	if (zhp == NULL) {
		ret = ENOENT;
		goto error;
	}

	ret = load_keys_cb(zfs_handle_dup(zhp), &cb);
	if (ret)
		goto error;

	(void) printf("%llu / %llu keys successfully loaded\n",
	    (u_longlong_t)(cb.cb_numattempted - cb.cb_numfailed),
	    (u_longlong_t)cb.cb_numattempted);

	if (cb.cb_numfailed != 0) {
		ret = -1;
		goto error;
	}

	zfs_close(zhp);
	return (0);

error:
	if (zhp != NULL)
		zfs_close(zhp);
	return (ret);
}

int
zfs_crypto_load_key(zfs_handle_t *zhp, boolean_t noop,
    const char *alt_keylocation)
{
	return (zfs_crypto_load_key_slot(zhp, noop, alt_keylocation,
	    DSL_CRYPTO_KEY_SLOT_PRIMARY));
}

int
zfs_crypto_load_key_slot(zfs_handle_t *zhp, boolean_t noop,
    const char *alt_keylocation, uint64_t slot)
{
	int ret, attempts = 0;
	char errbuf[ERRBUFLEN];
	uint64_t keystatus, iters = 0, salt = 0;
	uint64_t keyformat = ZFS_KEYFORMAT_NONE;
	char prop_keylocation[MAXNAMELEN];
	char prop_encroot[MAXNAMELEN];
	const char *keylocation = NULL;
	uint8_t *key_material = NULL, *key_data = NULL;
	size_t key_material_len;
	boolean_t is_encroot, can_retry = B_FALSE, correctible = B_FALSE;

	(void) snprintf(errbuf, sizeof (errbuf),
	    "Key load error");

	if (slot == 0) {
		zfs_error_aux(zhp->zfs_hdl, "Slot 0 is not a key slot.");
		ret = EINVAL;
		goto error;
	}

	/* check that encryption is enabled for the pool */
	if (!encryption_feature_is_enabled(zhp->zpool_hdl)) {
		zfs_error_aux(zhp->zfs_hdl,
		    "Encryption feature not enabled.");
		ret = EINVAL;
		goto error;
	}

	/* Fetch the keyformat. Check that the dataset is encrypted. */
	keyformat = zfs_prop_get_int(zhp, ZFS_PROP_KEYFORMAT);
	if (keyformat == ZFS_KEYFORMAT_NONE) {
		zfs_error_aux(zhp->zfs_hdl,
		    "'%s' is not encrypted.", zfs_get_name(zhp));
		ret = EINVAL;
		goto error;
	}

	/*
	 * Fetch the key location. Check that we are working with an
	 * encryption root.
	 */
	ret = zfs_crypto_get_encryption_root(zhp, &is_encroot, prop_encroot);
	if (ret != 0) {
		zfs_error_aux(zhp->zfs_hdl,
		    "Failed to get encryption root for '%s'.",
		    zfs_get_name(zhp));
		goto error;
	} else if (!is_encroot) {
		zfs_error_aux(zhp->zfs_hdl,
		    "Keys must be loaded for encryption root of '%s' (%s).",
		    zfs_get_name(zhp), prop_encroot);
		ret = EINVAL;
		goto error;
	}

	/*
	 * A slot above the primary one carries its own derivation parameters,
	 * which the kernel publishes through the "keyslots" stats entry. Check
	 * that the slot exists before prompting for, or fetching, any key.
	 */
	if (slot >= DSL_CRYPTO_KEY_SLOT_PRIMARY + 1) {
		nvlist_t *slots = NULL, *slotnvl = NULL;
		char name[32];

		ret = zfs_crypto_get_keyslots(zhp, &slots);
		if (ret != 0) {
			zfs_error_aux(zhp->zfs_hdl,
			    "Failed to get key slots for '%s'.",
			    zfs_get_name(zhp));
			goto error;
		}

		(void) snprintf(name, sizeof (name), "%llu",
		    (u_longlong_t)slot);
		if (nvlist_lookup_nvlist(slots, name, &slotnvl) != 0) {
			zfs_error_aux(zhp->zfs_hdl,
			    "key slot %llu does not exist",
			    (u_longlong_t)slot);
			nvlist_free(slots);
			ret = ENOENT;
			goto error;
		}

		keyformat = ZFS_KEYFORMAT_NONE;
		(void) nvlist_lookup_uint64(slotnvl, "keyformat", &keyformat);
		(void) nvlist_lookup_uint64(slotnvl, "pbkdf2salt", &salt);
		(void) nvlist_lookup_uint64(slotnvl, "pbkdf2iters", &iters);
		nvlist_free(slots);
	}

	/*
	 * if the caller has elected to override the keylocation property
	 * use that instead
	 */
	if (alt_keylocation != NULL) {
		keylocation = alt_keylocation;
	} else if (slot == DSL_CRYPTO_KEY_SLOT_PRIMARY) {
		ret = zfs_prop_get(zhp, ZFS_PROP_KEYLOCATION, prop_keylocation,
		    sizeof (prop_keylocation), NULL, NULL, 0, B_TRUE);
		if (ret != 0) {
			zfs_error_aux(zhp->zfs_hdl,
			    "Failed to get keylocation for '%s'.",
			    zfs_get_name(zhp));
			goto error;
		}

		keylocation = prop_keylocation;
	} else {
		nvlist_t *props = zfs_get_user_props(zhp);
		nvlist_t *propval;
		const char *loc = NULL;
		char name[40];

		/*
		 * keylocation_<n> is an unregistered property, so it can
		 * only be read out of the user property nvlist.
		 */
		(void) snprintf(name, sizeof (name), "keylocation_%llu",
		    (u_longlong_t)slot);
		if (props != NULL &&
		    nvlist_lookup_nvlist(props, name, &propval) == 0)
			(void) nvlist_lookup_string(propval, ZPROP_VALUE,
			    &loc);

		/* a stored "none" is not a usable source (design P5 §3) */
		if (loc == NULL || strcmp(loc, "none") == 0) {
			zfs_error_aux(zhp->zfs_hdl,
			    "slot %llu has no stored keylocation; "
			    "specify -L", (u_longlong_t)slot);
			ret = EINVAL;
			goto error;
		}

		if (strlen(loc) >= sizeof (prop_keylocation)) {
			zfs_error_aux(zhp->zfs_hdl,
			    "keylocation_%llu is too long", (u_longlong_t)slot);
			ret = EINVAL;
			goto error;
		}

		(void) strlcpy(prop_keylocation, loc,
		    sizeof (prop_keylocation));
		keylocation = prop_keylocation;
	}

	/* check that the key is unloaded unless this is a noop */
	if (!noop) {
		keystatus = zfs_prop_get_int(zhp, ZFS_PROP_KEYSTATUS);
		if (keystatus == ZFS_KEYSTATUS_AVAILABLE) {
			zfs_error_aux(zhp->zfs_hdl,
			    "Key already loaded for '%s'.", zfs_get_name(zhp));
			ret = EEXIST;
			goto error;
		}
	}

	/* passphrase formats require a salt and pbkdf2_iters property */
	if (slot == DSL_CRYPTO_KEY_SLOT_PRIMARY &&
	    keyformat == ZFS_KEYFORMAT_PASSPHRASE) {
		salt = zfs_prop_get_int(zhp, ZFS_PROP_PBKDF2_SALT);
		iters = zfs_prop_get_int(zhp, ZFS_PROP_PBKDF2_ITERS);
	}

try_again:
	/* fetching and deriving the key are correctable errors. set the flag */
	correctible = B_TRUE;

	/* get key material from key format and location */
	ret = get_key_material(zhp->zfs_hdl, B_FALSE, B_FALSE, keyformat,
	    keylocation, zfs_get_name(zhp), &key_material, &key_material_len,
	    &can_retry);
	if (ret != 0)
		goto error;

	/* derive a key from the key material */
	ret = derive_key(zhp->zfs_hdl, keyformat, iters, key_material, salt,
	    &key_data);
	if (ret != 0)
		goto error;

	correctible = B_FALSE;

	/* pass the wrapping key and noop flag to the ioctl */
	ret = lzc_load_key_slot(zhp->zfs_name, noop, key_data,
	    WRAPPING_KEY_LEN, slot);
	if (ret != 0) {
		switch (ret) {
		case EPERM:
			zfs_error_aux(zhp->zfs_hdl,
			    "Permission denied.");
			break;
		case EINVAL:
			zfs_error_aux(zhp->zfs_hdl,
			    "Invalid parameters provided for dataset %s.",
			    zfs_get_name(zhp));
			break;
		case EEXIST:
			zfs_error_aux(zhp->zfs_hdl,
			    "Key already loaded for '%s'.", zfs_get_name(zhp));
			break;
		case EBUSY:
			zfs_error_aux(zhp->zfs_hdl,
			    "'%s' is busy.", zfs_get_name(zhp));
			break;
		case EACCES:
			correctible = B_TRUE;
			zfs_error_aux(zhp->zfs_hdl,
			    "Incorrect key provided for '%s'.",
			    zfs_get_name(zhp));
			break;
		case ENOENT:
			zfs_error_aux(zhp->zfs_hdl,
			    "key slot %llu does not exist",
			    (u_longlong_t)slot);
			break;
		case ENOTSUP:
			zfs_error_aux(zhp->zfs_hdl,
			    "pool does not have the keyslots feature enabled");
			break;
		case ZFS_ERR_CRYPTO_NOTSUP:
			zfs_error_aux(zhp->zfs_hdl,
			    "'%s' uses an unsupported encryption suite.",
			    zfs_get_name(zhp));
			break;
		}
		goto error;
	}

	free(key_material);
	free(key_data);

	return (0);

error:
	zfs_error(zhp->zfs_hdl, EZFS_CRYPTOFAILED, errbuf);
	if (key_material != NULL) {
		free(key_material);
		key_material = NULL;
	}
	if (key_data != NULL) {
		free(key_data);
		key_data = NULL;
	}

	/*
	 * Here we decide if it is ok to allow the user to retry entering their
	 * key. The can_retry flag will be set if the user is entering their
	 * key from an interactive prompt. The correctable flag will only be
	 * set if an error that occurred could be corrected by retrying. Both
	 * flags are needed to allow the user to attempt key entry again
	 */
	attempts++;
	if (can_retry && correctible && attempts < MAX_KEY_PROMPT_ATTEMPTS)
		goto try_again;

	return (ret);
}

/*
 * Convert the raw `-o` nvlist the CLI builds into the typed property nvlist
 * the create path uses. Only the three derivation properties are accepted, as
 * for change-key, and zfs_valid_proplist() converts and validates the values,
 * so a slot's parameters are checked exactly the way zfs create's are.
 */
static int
zfs_crypto_verify_keyslot_nvlist(zfs_handle_t *zhp, nvlist_t *props,
    nvlist_t **props_out, char *errbuf)
{
	nvpair_t *elem = NULL;
	nvlist_t *new_props;

	while ((elem = nvlist_next_nvpair(props, elem)) != NULL) {
		switch (zfs_name_to_prop(nvpair_name(elem))) {
		case ZFS_PROP_KEYFORMAT:
		case ZFS_PROP_KEYLOCATION:
		case ZFS_PROP_PBKDF2_ITERS:
			break;
		default:
			zfs_error_aux(zhp->zfs_hdl,
			    "Only keyformat, keylocation and pbkdf2iters "
			    "may be specified when adding a key slot.");
			return (EINVAL);
		}
	}

	new_props = zfs_valid_proplist(zhp->zfs_hdl, zhp->zfs_type, props,
	    zfs_prop_get_int(zhp, ZFS_PROP_ZONED), zhp, zhp->zpool_hdl,
	    B_TRUE, errbuf);
	if (new_props == NULL)
		return (EINVAL);

	*props_out = new_props;
	return (0);
}

/*
 * Convert the raw `-o` nvlist of a rewrap. Only keylocation and pbkdf2iters are
 * accepted: a slot's type is fixed when it is created, so keyformat is refused
 * here rather than being silently ignored, and the kernel refuses a format that
 * differs from the slot's own. No properties at all is valid, so `props` may be
 * NULL. As for add, zfs_valid_proplist() converts and validates the values.
 */
static int
zfs_crypto_verify_rewrap_keyslot_nvlist(zfs_handle_t *zhp, nvlist_t *props,
    nvlist_t **props_out, char *errbuf)
{
	nvpair_t *elem = NULL;
	nvlist_t *new_props;

	*props_out = NULL;
	if (props == NULL)
		return (0);

	while ((elem = nvlist_next_nvpair(props, elem)) != NULL) {
		switch (zfs_name_to_prop(nvpair_name(elem))) {
		case ZFS_PROP_KEYLOCATION:
		case ZFS_PROP_PBKDF2_ITERS:
			break;
		case ZFS_PROP_KEYFORMAT:
			zfs_error_aux(zhp->zfs_hdl,
			    "A key slot's keyformat is fixed; only "
			    "keylocation and pbkdf2iters may be "
			    "specified when rewrapping a key slot.");
			return (EINVAL);
		default:
			zfs_error_aux(zhp->zfs_hdl,
			    "Only keylocation and pbkdf2iters may be "
			    "specified when rewrapping a key slot.");
			return (EINVAL);
		}
	}

	new_props = zfs_valid_proplist(zhp->zfs_hdl, zhp->zfs_type, props,
	    zfs_prop_get_int(zhp, ZFS_PROP_ZONED), zhp, zhp->zpool_hdl,
	    B_TRUE, errbuf);
	if (new_props == NULL)
		return (EINVAL);

	*props_out = new_props;
	return (0);
}

/*
 * One refusal for any slot verb aimed below the encryption root. The verb and
 * its preposition are the only part that differs, so the sentence lives here
 * rather than being duplicated at each site (design P5 §7).
 */
static void
zfs_crypto_keyslot_root_error(zfs_handle_t *zhp, const char *verb,
    const char *encroot)
{
	zfs_error_aux(zhp->zfs_hdl,
	    "Key slots must be %s the encryption root of '%s' (%s).",
	    verb, zfs_get_name(zhp), encroot);
}

/*
 * Add a key slot to an encryption root. `props` carries the slot's derivation
 * parameters as the CLI's raw `-o` values (keyformat, and optionally
 * keylocation and pbkdf2iters), which are converted and validated here exactly
 * as change-key's are. The secret is obtained and derived by the same helpers
 * zfs create uses, so a slot is created exactly the way a dataset's first key
 * is. On success *slot_out holds the slot that was used.
 */
int
zfs_crypto_add_keyslot(zfs_handle_t *zhp, uint64_t slot, nvlist_t *props,
    uint64_t *slot_out)
{
	int ret;
	char errbuf[ERRBUFLEN];
	char prop_encroot[MAXNAMELEN];
	nvlist_t *typed_props = NULL;
	uint64_t keyformat = ZFS_KEYFORMAT_NONE;
	const char *keylocation = NULL;
	uint8_t *key_data = NULL;
	uint_t key_datalen = 0;
	boolean_t is_encroot;

	(void) snprintf(errbuf, sizeof (errbuf),
	    "Key slot add error");

	/* slot 1 is the compatibility floor; a new slot starts at 2 */
	if (slot == DSL_CRYPTO_KEY_SLOT_PRIMARY) {
		zfs_error_aux(zhp->zfs_hdl,
		    "slot 1 is the primary slot; new slots start at 2");
		ret = EINVAL;
		goto error;
	}

	if (props == NULL) {
		zfs_error_aux(zhp->zfs_hdl,
		    "A keyformat is required to add a key slot.");
		ret = EINVAL;
		goto error;
	}

	if (zfs_prop_get_int(zhp, ZFS_PROP_ENCRYPTION) == ZIO_CRYPT_OFF) {
		zfs_error_aux(zhp->zfs_hdl,
		    "'%s' is not encrypted.", zfs_get_name(zhp));
		ret = EINVAL;
		goto error;
	}

	/*
	 * Take the raw properties and convert them the way the create path
	 * does, so the values are validated in one place rather than in each
	 * caller. The dataset handle is passed so that checks which depend on
	 * the target (such as keylocation='none' on an encrypted dataset)
	 * report the same messages zfs set does.
	 */
	ret = zfs_crypto_verify_keyslot_nvlist(zhp, props, &typed_props,
	    errbuf);
	if (ret != 0)
		goto error;
	props = typed_props;

	/* a keyformat is required: it says how the key is derived */
	ret = nvlist_lookup_uint64(props,
	    zfs_prop_to_name(ZFS_PROP_KEYFORMAT), &keyformat);
	if (ret != 0 || keyformat == ZFS_KEYFORMAT_NONE) {
		zfs_error_aux(zhp->zfs_hdl,
		    "A keyformat is required to add a key slot.");
		ret = EINVAL;
		goto error;
	}

	/* slots live on the encryption root's key object, as for load-key */
	ret = zfs_crypto_get_encryption_root(zhp, &is_encroot, prop_encroot);
	if (ret != 0) {
		zfs_error_aux(zhp->zfs_hdl,
		    "Failed to get encryption root for '%s'.",
		    zfs_get_name(zhp));
		goto error;
	} else if (!is_encroot) {
		zfs_crypto_keyslot_root_error(zhp, "added to", prop_encroot);
		ret = EINVAL;
		goto error;
	}

	/* check the feature and the loaded key before asking for a secret */
	if (!feature_is_enabled(zhp->zpool_hdl, SPA_FEATURE_KEYSLOTS)) {
		zfs_error_aux(zhp->zfs_hdl,
		    "pool does not have the keyslots feature enabled");
		ret = ENOTSUP;
		goto error;
	}

	if (zfs_prop_get_int(zhp, ZFS_PROP_KEYSTATUS) !=
	    ZFS_KEYSTATUS_AVAILABLE) {
		zfs_error_aux(zhp->zfs_hdl, "key must be loaded to add a slot");
		ret = EACCES;
		goto error;
	}

	/* default to prompt if no keylocation is specified, as create does */
	(void) nvlist_lookup_string(props,
	    zfs_prop_to_name(ZFS_PROP_KEYLOCATION), &keylocation);
	if (keylocation == NULL) {
		keylocation = (char *)"prompt";
		ret = nvlist_add_string(props,
		    zfs_prop_to_name(ZFS_PROP_KEYLOCATION), keylocation);
		if (ret != 0)
			goto error;
	}

	/*
	 * Get the secret and derive the slot's wrapping key through the create
	 * path: it prompts or reads the location, checks the key's length,
	 * generates the passphrase salt, defaults the iteration count, and adds
	 * the parameters the kernel records for the slot.
	 */
	ret = populate_create_encryption_params_nvlists(zhp->zfs_hdl, zhp,
	    B_TRUE, keyformat, keylocation, props, &key_data, &key_datalen);
	if (ret != 0)
		goto error;

	ret = lzc_keyslot_add(zhp->zfs_name, slot, props, key_data,
	    key_datalen, slot_out);
	if (ret != 0) {
		switch (ret) {
		case EPERM:
			zfs_error_aux(zhp->zfs_hdl,
			    "Permission denied.");
			break;
		case EACCES:
			zfs_error_aux(zhp->zfs_hdl,
			    "key must be loaded to add a slot");
			break;
		case EEXIST:
			zfs_error_aux(zhp->zfs_hdl,
			    "key slot %llu is already in use",
			    (u_longlong_t)slot);
			break;
		case EINVAL:
			zfs_error_aux(zhp->zfs_hdl,
			    "Invalid parameters provided for dataset %s.",
			    zfs_get_name(zhp));
			break;
		case ENOTSUP:
			/*
			 * The feature is checked above, so ENOTSUP here
			 * means the key object predates the slot format.
			 */
			zfs_error_aux(zhp->zfs_hdl,
			    "'%s' was created with an encryption version that "
			    "cannot hold key slots.", zfs_get_name(zhp));
			break;
		case E2BIG:
			zfs_error_aux(zhp->zfs_hdl,
			    "keylocation is too long");
			break;
		}
		goto error;
	}

	free(key_data);
	nvlist_free(typed_props);

	return (0);

error:
	free(key_data);
	nvlist_free(typed_props);
	zfs_error(zhp->zfs_hdl, EZFS_CRYPTOFAILED, errbuf);

	return (ret);
}

/*
 * Remove a key slot from an encryption root. Slot 1 is the compatibility floor
 * and is never removed. Removal is metadata-only, but it still requires the
 * root's key to be loaded (design P5 section 12), so a recovery slot cannot be
 * removed without the primary key. The kernel deletes the slot's
 * keylocation_<n> in the same transaction.
 */
int
zfs_crypto_remove_keyslot(zfs_handle_t *zhp, uint64_t slot)
{
	int ret;
	char errbuf[ERRBUFLEN];
	char prop_encroot[MAXNAMELEN];
	boolean_t is_encroot;

	(void) snprintf(errbuf, sizeof (errbuf),
	    "Key slot remove error");

	if (slot == 0) {
		zfs_error_aux(zhp->zfs_hdl, "Slot 0 is not a key slot.");
		ret = EINVAL;
		goto error;
	}

	if (slot == DSL_CRYPTO_KEY_SLOT_PRIMARY) {
		zfs_error_aux(zhp->zfs_hdl,
		    "slot 1 is the primary slot and cannot be removed");
		ret = EINVAL;
		goto error;
	}

	if (zfs_prop_get_int(zhp, ZFS_PROP_ENCRYPTION) == ZIO_CRYPT_OFF) {
		zfs_error_aux(zhp->zfs_hdl,
		    "'%s' is not encrypted.", zfs_get_name(zhp));
		ret = EINVAL;
		goto error;
	}

	/* slots live on the encryption root's key object, as for add */
	ret = zfs_crypto_get_encryption_root(zhp, &is_encroot, prop_encroot);
	if (ret != 0) {
		zfs_error_aux(zhp->zfs_hdl,
		    "Failed to get encryption root for '%s'.",
		    zfs_get_name(zhp));
		goto error;
	} else if (!is_encroot) {
		zfs_crypto_keyslot_root_error(zhp, "removed from",
		    prop_encroot);
		ret = EINVAL;
		goto error;
	}

	if (!feature_is_enabled(zhp->zpool_hdl, SPA_FEATURE_KEYSLOTS)) {
		zfs_error_aux(zhp->zfs_hdl,
		    "pool does not have the keyslots feature enabled");
		ret = ENOTSUP;
		goto error;
	}

	if (zfs_prop_get_int(zhp, ZFS_PROP_KEYSTATUS) !=
	    ZFS_KEYSTATUS_AVAILABLE) {
		zfs_error_aux(zhp->zfs_hdl,
		    "key must be loaded to remove a slot");
		ret = EACCES;
		goto error;
	}

	ret = lzc_keyslot_remove(zhp->zfs_name, slot);
	if (ret != 0) {
		switch (ret) {
		case EPERM:
			zfs_error_aux(zhp->zfs_hdl,
			    "Permission denied.");
			break;
		case EACCES:
			zfs_error_aux(zhp->zfs_hdl,
			    "key must be loaded to remove a slot");
			break;
		case ENOENT:
			zfs_error_aux(zhp->zfs_hdl,
			    "key slot %llu does not exist",
			    (u_longlong_t)slot);
			break;
		case EINVAL:
			zfs_error_aux(zhp->zfs_hdl,
			    "Invalid parameters provided for dataset %s.",
			    zfs_get_name(zhp));
			break;
		case ENOTSUP:
			zfs_error_aux(zhp->zfs_hdl,
			    "pool does not have the keyslots feature enabled");
			break;
		}
		goto error;
	}

	return (0);

error:
	zfs_error(zhp->zfs_hdl, EZFS_CRYPTOFAILED, errbuf);

	return (ret);
}

/*
 * Rewrap a key slot: replace the secret that unlocks slot n, keeping the slot
 * number and the slot's keyformat. The old secret is never read: the root's key
 * must be loaded, and wkey_1 in memory is what authorises the operation - the
 * same authority keyslot remove plus keyslot add already need (design P5
 * section 15).
 */
int
zfs_crypto_rewrap_keyslot(zfs_handle_t *zhp, uint64_t slot, nvlist_t *props)
{
	int ret;
	char errbuf[ERRBUFLEN];
	char prop_encroot[MAXNAMELEN];
	char num[32];
	nvlist_t *typed_props = NULL, *slots = NULL, *slotnvl = NULL;
	uint64_t keyformat = ZFS_KEYFORMAT_NONE;
	uint64_t iters = 0;
	const char *keylocation = NULL;
	uint8_t *key_data = NULL;
	uint_t key_datalen = 0;
	boolean_t is_encroot;

	(void) snprintf(errbuf, sizeof (errbuf),
	    "Key slot rewrap error");

	if (slot == 0) {
		zfs_error_aux(zhp->zfs_hdl, "Slot 0 is not a key slot.");
		ret = EINVAL;
		goto error;
	}

	/* slot 1's entries wrap the master key; rekeying it is change-key's */
	if (slot == DSL_CRYPTO_KEY_SLOT_PRIMARY) {
		zfs_error_aux(zhp->zfs_hdl,
		    "slot 1 is the primary slot; use 'zfs change-key' to "
		    "rekey it");
		ret = EINVAL;
		goto error;
	}

	if (zfs_prop_get_int(zhp, ZFS_PROP_ENCRYPTION) == ZIO_CRYPT_OFF) {
		zfs_error_aux(zhp->zfs_hdl,
		    "'%s' is not encrypted.", zfs_get_name(zhp));
		ret = EINVAL;
		goto error;
	}

	/*
	 * Take the raw properties and convert them the way the create path
	 * does, so the values are validated in one place rather than in each
	 * caller. No property at all is valid here, so an empty set is
	 * allocated to carry the defaults.
	 */
	ret = zfs_crypto_verify_rewrap_keyslot_nvlist(zhp, props,
	    &typed_props, errbuf);
	if (ret != 0)
		goto error;

	if (typed_props == NULL)
		typed_props = fnvlist_alloc();
	props = typed_props;

	/* slots live on the encryption root's key object, as for add */
	ret = zfs_crypto_get_encryption_root(zhp, &is_encroot, prop_encroot);
	if (ret != 0) {
		zfs_error_aux(zhp->zfs_hdl,
		    "Failed to get encryption root for '%s'.",
		    zfs_get_name(zhp));
		goto error;
	} else if (!is_encroot) {
		zfs_crypto_keyslot_root_error(zhp, "rewrapped for",
		    prop_encroot);
		ret = EINVAL;
		goto error;
	}

	/* check the feature and the loaded key before asking for a secret */
	if (!feature_is_enabled(zhp->zpool_hdl, SPA_FEATURE_KEYSLOTS)) {
		zfs_error_aux(zhp->zfs_hdl,
		    "pool does not have the keyslots feature enabled");
		ret = ENOTSUP;
		goto error;
	}

	/*
	 * This also loads the handle, which the slot-list channel needs:
	 * zfs_crypto_get_keyslots() is EINVAL on an unloaded handle.
	 */
	if (zfs_prop_get_int(zhp, ZFS_PROP_KEYSTATUS) !=
	    ZFS_KEYSTATUS_AVAILABLE) {
		zfs_error_aux(zhp->zfs_hdl,
		    "key must be loaded to rewrap a slot");
		ret = EACCES;
		goto error;
	}

	/*
	 * The slot's type is fixed, so it comes from the slot-list channel and
	 * not from the command line. A slot whose parameter entries cannot be
	 * read is absent from that channel, which is why the kernel's
	 * corrupt-slot EINVAL is reachable only through the ioctl.
	 */
	(void) snprintf(num, sizeof (num), "%llu", (u_longlong_t)slot);
	ret = zfs_crypto_get_keyslots(zhp, &slots);
	if (ret != 0) {
		zfs_error_aux(zhp->zfs_hdl,
		    "Failed to get key slots for '%s'.", zfs_get_name(zhp));
		goto error;
	}
	if (nvlist_lookup_nvlist(slots, num, &slotnvl) != 0) {
		zfs_error_aux(zhp->zfs_hdl, "key slot %llu does not exist",
		    (u_longlong_t)slot);
		ret = ENOENT;
		goto error;
	}
	(void) nvlist_lookup_uint64(slotnvl, "keyformat", &keyformat);
	(void) nvlist_lookup_uint64(slotnvl, "pbkdf2iters", &iters);

	/*
	 * A slot that is in the channel but whose stored type is not one we
	 * support cannot be rewrapped: nothing could derive the new secret.
	 */
	if (keyformat >= ZFS_KEYFORMAT_FORMATS ||
	    keyformat == ZFS_KEYFORMAT_NONE) {
		zfs_error_aux(zhp->zfs_hdl,
		    "key slot %llu is corrupt; remove it and add a new one",
		    (u_longlong_t)slot);
		ret = EINVAL;
		goto error;
	}

	/*
	 * Hand the recorded type to the kernel too: it refuses a request whose
	 * format differs from KEYFORMAT_<n>, so an ioctl caller cannot change a
	 * slot's type. This is the only place props gains a keyformat; the CLI
	 * refuses -o keyformat outright.
	 */
	ret = nvlist_add_uint64(props,
	    zfs_prop_to_name(ZFS_PROP_KEYFORMAT), keyformat);
	if (ret != 0)
		goto error;

	/* default to prompt if no keylocation is specified, as create does */
	(void) nvlist_lookup_string(props,
	    zfs_prop_to_name(ZFS_PROP_KEYLOCATION), &keylocation);
	if (keylocation == NULL) {
		keylocation = "prompt";
		ret = nvlist_add_string(props,
		    zfs_prop_to_name(ZFS_PROP_KEYLOCATION), keylocation);
		if (ret != 0)
			goto error;
	}

	/*
	 * A rewrap changes the secret, not the slot's work factor: an omitted
	 * pbkdf2iters keeps the slot's current count instead of resetting it to
	 * the default, so a hardened slot is not silently weakened. An explicit
	 * -o overrides it. Only passphrase slots carry a count; for raw/hex the
	 * helper requires pbkdf2iters absent, so nothing is injected.
	 */
	if (keyformat == ZFS_KEYFORMAT_PASSPHRASE &&
	    !nvlist_exists(props, zfs_prop_to_name(ZFS_PROP_PBKDF2_ITERS))) {
		if (iters < MIN_PBKDF2_ITERATIONS) {
			zfs_error_aux(zhp->zfs_hdl,
			    "key slot %llu has pbkdf2iters %llu below the "
			    "minimum %d; specify -o pbkdf2iters",
			    (u_longlong_t)slot, (u_longlong_t)iters,
			    MIN_PBKDF2_ITERATIONS);
			ret = EINVAL;
			goto error;
		}
		ret = nvlist_add_uint64(props,
		    zfs_prop_to_name(ZFS_PROP_PBKDF2_ITERS), iters);
		if (ret != 0)
			goto error;
	}

	/* new secret, new salt, new IV; the iteration count is set above */
	ret = populate_create_encryption_params_nvlists(zhp->zfs_hdl, zhp,
	    B_TRUE, keyformat, keylocation, props, &key_data, &key_datalen);
	if (ret != 0)
		goto error;

	ret = lzc_keyslot_rewrap(zhp->zfs_name, slot, props, key_data,
	    key_datalen);
	if (ret != 0) {
		switch (ret) {
		case EPERM:
			zfs_error_aux(zhp->zfs_hdl,
			    "Permission denied.");
			break;
		case EACCES:
			zfs_error_aux(zhp->zfs_hdl,
			    "key must be loaded to rewrap a slot");
			break;
		case ENOENT:
			zfs_error_aux(zhp->zfs_hdl,
			    "key slot %llu does not exist",
			    (u_longlong_t)slot);
			break;
		case ENOTSUP:
			zfs_error_aux(zhp->zfs_hdl,
			    "pool does not have the keyslots feature enabled");
			break;
		case EINVAL:
			/*
			 * libzfs has validated the properties and read the
			 * slot's type, so a kernel EINVAL here means the slot
			 * changed under us: its keyformat is unreadable or
			 * unsupported.
			 */
			zfs_error_aux(zhp->zfs_hdl,
			    "key slot %llu is corrupt; remove it and add a "
			    "new one", (u_longlong_t)slot);
			break;
		case E2BIG:
			zfs_error_aux(zhp->zfs_hdl,
			    "keylocation is too long");
			break;
		}
		goto error;
	}

	free(key_data);
	nvlist_free(slots);
	nvlist_free(typed_props);

	return (0);

error:
	free(key_data);
	nvlist_free(slots);
	nvlist_free(typed_props);
	zfs_error(zhp->zfs_hdl, EZFS_CRYPTOFAILED, errbuf);

	return (ret);
}

int
zfs_crypto_unload_key(zfs_handle_t *zhp)
{
	int ret;
	char errbuf[ERRBUFLEN];
	char prop_encroot[MAXNAMELEN];
	uint64_t keystatus, keyformat;
	boolean_t is_encroot;

	(void) snprintf(errbuf, sizeof (errbuf),
	    "Key unload error");

	/* check that encryption is enabled for the pool */
	if (!encryption_feature_is_enabled(zhp->zpool_hdl)) {
		zfs_error_aux(zhp->zfs_hdl,
		    "Encryption feature not enabled.");
		ret = EINVAL;
		goto error;
	}

	/* Fetch the keyformat. Check that the dataset is encrypted. */
	keyformat = zfs_prop_get_int(zhp, ZFS_PROP_KEYFORMAT);
	if (keyformat == ZFS_KEYFORMAT_NONE) {
		zfs_error_aux(zhp->zfs_hdl,
		    "'%s' is not encrypted.", zfs_get_name(zhp));
		ret = EINVAL;
		goto error;
	}

	/*
	 * Fetch the key location. Check that we are working with an
	 * encryption root.
	 */
	ret = zfs_crypto_get_encryption_root(zhp, &is_encroot, prop_encroot);
	if (ret != 0) {
		zfs_error_aux(zhp->zfs_hdl,
		    "Failed to get encryption root for '%s'.",
		    zfs_get_name(zhp));
		goto error;
	} else if (!is_encroot) {
		zfs_error_aux(zhp->zfs_hdl,
		    "Keys must be unloaded for encryption root of '%s' (%s).",
		    zfs_get_name(zhp), prop_encroot);
		ret = EINVAL;
		goto error;
	}

	/* check that the key is loaded */
	keystatus = zfs_prop_get_int(zhp, ZFS_PROP_KEYSTATUS);
	if (keystatus == ZFS_KEYSTATUS_UNAVAILABLE) {
		zfs_error_aux(zhp->zfs_hdl,
		    "Key already unloaded for '%s'.", zfs_get_name(zhp));
		ret = EACCES;
		goto error;
	}

	/* call the ioctl */
	ret = lzc_unload_key(zhp->zfs_name);

	if (ret != 0) {
		switch (ret) {
		case EPERM:
			zfs_error_aux(zhp->zfs_hdl,
			    "Permission denied.");
			break;
		case EACCES:
			zfs_error_aux(zhp->zfs_hdl,
			    "Key already unloaded for '%s'.",
			    zfs_get_name(zhp));
			break;
		case EBUSY:
			zfs_error_aux(zhp->zfs_hdl,
			    "'%s' is busy.", zfs_get_name(zhp));
			break;
		}
		zfs_error(zhp->zfs_hdl, EZFS_CRYPTOFAILED, errbuf);
	}

	return (ret);

error:
	zfs_error(zhp->zfs_hdl, EZFS_CRYPTOFAILED, errbuf);
	return (ret);
}

static int
zfs_crypto_verify_rewrap_nvlist(zfs_handle_t *zhp, nvlist_t *props,
    boolean_t inheritkey, nvlist_t **props_out, char *errbuf)
{
	int ret;
	nvpair_t *elem = NULL;
	nvlist_t *new_props = NULL;

	/*
	 * loop through all provided properties, we should only have
	 * keyformat, keylocation and pbkdf2iters, and user properties.
	 * The actual validation of values is done by zfs_valid_proplist().
	 */
	while ((elem = nvlist_next_nvpair(props, elem)) != NULL) {
		const char *propname = nvpair_name(elem);

		switch (zfs_name_to_prop(propname)) {
		case ZFS_PROP_PBKDF2_ITERS:
		case ZFS_PROP_KEYFORMAT:
		case ZFS_PROP_KEYLOCATION:
			if (inheritkey) {
				ret = EINVAL;
				zfs_error_aux(zhp->zfs_hdl,
				    "Only user properties may be set with "
				    "'zfs change-key -i'");
				goto error;
			}
			break;
		case ZPROP_INVAL:
			if (zfs_prop_user(propname))
				break;
			zfs_fallthrough;
		default:
			ret = EINVAL;
			if (inheritkey) {
				zfs_error_aux(zhp->zfs_hdl,
				    "Only user properties may be set with "
				    "'zfs change-key -i'");
			} else {
				zfs_error_aux(zhp->zfs_hdl,
				    "Only keyformat, keylocation, pbkdf2iters, "
				    "and user properties may be set with this "
				    "command.");
			}
			goto error;
		}
	}

	new_props = zfs_valid_proplist(zhp->zfs_hdl, zhp->zfs_type, props,
	    zfs_prop_get_int(zhp, ZFS_PROP_ZONED), NULL, zhp->zpool_hdl,
	    B_TRUE, errbuf);
	if (new_props == NULL) {
		ret = EINVAL;
		goto error;
	}

	*props_out = new_props;
	return (0);

error:
	nvlist_free(new_props);
	*props_out = NULL;
	return (ret);
}

/*
 * Refuse a key change on an encryption root that holds alternate slots. Every
 * slot is wrapped under the primary wrapping key, so replacing it would make
 * all of them unusable. The kernel enforces this as well; this is the half that
 * runs before any key is prompted for, kept in one place so that the condition
 * and the message cannot drift between callers.
 *
 * Reports its own error, so callers must not report it again.
 */
int
zfs_crypto_change_key_slots_check(zfs_handle_t *zhp)
{
	int ret;
	uint_t count = 0;
	boolean_t is_encroot;
	nvlist_t *slots = NULL;
	nvpair_t *elem;

	ret = zfs_crypto_get_encryption_root(zhp, &is_encroot, NULL);
	if (ret != 0) {
		zfs_error_aux(zhp->zfs_hdl,
		    "Failed to get encryption root for '%s'.",
		    zfs_get_name(zhp));
		zfs_error(zhp->zfs_hdl, EZFS_CRYPTOFAILED, "Key change error");
		return (ret);
	}

	/* a non-root rewrap leaves the root's primary key alone */
	if (!is_encroot)
		return (0);

	ret = zfs_crypto_get_keyslots(zhp, &slots);
	if (ret != 0) {
		zfs_error_aux(zhp->zfs_hdl, "Failed to get key slots for '%s'.",
		    zfs_get_name(zhp));
		zfs_error(zhp->zfs_hdl, EZFS_CRYPTOFAILED, "Key change error");
		return (ret);
	}

	for (elem = nvlist_next_nvpair(slots, NULL); elem != NULL;
	    elem = nvlist_next_nvpair(slots, elem))
		count++;
	nvlist_free(slots);

	if (count == 0)
		return (0);

	zfs_error_aux(zhp->zfs_hdl,
	    "cannot change key: '%s' has %llu extra key slot(s); changing the "
	    "primary key would make them unusable; remove them with "
	    "'zfs keyslot remove -S <n>' first",
	    zfs_get_name(zhp), (u_longlong_t)count);
	zfs_error(zhp->zfs_hdl, EZFS_CRYPTOFAILED, "Key change error");

	return (EINVAL);
}

int
zfs_crypto_rewrap(zfs_handle_t *zhp, nvlist_t *raw_props, boolean_t inheritkey)
{
	int ret;
	char errbuf[ERRBUFLEN];
	boolean_t is_encroot;
	nvlist_t *props = NULL;
	uint8_t *wkeydata = NULL;
	uint_t wkeylen = 0;
	dcp_cmd_t cmd = (inheritkey) ? DCP_CMD_INHERIT : DCP_CMD_NEW_KEY;
	uint64_t crypt, pcrypt, keystatus, pkeystatus;
	uint64_t keyformat = ZFS_KEYFORMAT_NONE;
	zfs_handle_t *pzhp = NULL;
	const char *keylocation = NULL;
	char origin_name[MAXNAMELEN];
	char prop_keylocation[MAXNAMELEN];
	char parent_name[ZFS_MAX_DATASET_NAME_LEN];

	(void) snprintf(errbuf, sizeof (errbuf),
	    "Key change error");

	/* check that encryption is enabled for the pool */
	if (!encryption_feature_is_enabled(zhp->zpool_hdl)) {
		zfs_error_aux(zhp->zfs_hdl,
		    "Encryption feature not enabled.");
		ret = EINVAL;
		goto error;
	}

	/* get crypt from dataset */
	crypt = zfs_prop_get_int(zhp, ZFS_PROP_ENCRYPTION);
	if (crypt == ZIO_CRYPT_OFF) {
		zfs_error_aux(zhp->zfs_hdl,
		    "Dataset not encrypted.");
		ret = EINVAL;
		goto error;
	}

	/* get the encryption root of the dataset */
	ret = zfs_crypto_get_encryption_root(zhp, &is_encroot, NULL);
	if (ret != 0) {
		zfs_error_aux(zhp->zfs_hdl,
		    "Failed to get encryption root for '%s'.",
		    zfs_get_name(zhp));
		goto error;
	}

	/* Clones use their origin's key and cannot rewrap it */
	ret = zfs_prop_get(zhp, ZFS_PROP_ORIGIN, origin_name,
	    sizeof (origin_name), NULL, NULL, 0, B_TRUE);
	if (ret == 0 && strcmp(origin_name, "") != 0) {
		zfs_error_aux(zhp->zfs_hdl,
		    "Keys cannot be changed on clones.");
		ret = EINVAL;
		goto error;
	}

	/*
	 * Refuse before anything prompts for a key: on an encryption root
	 * that holds alternate slots the kernel would refuse anyway, but only
	 * after the user had typed a new passphrase. The helper reports its
	 * own error, so return directly: the error label would print a second
	 * message.
	 */
	ret = zfs_crypto_change_key_slots_check(zhp);
	if (ret != 0)
		return (ret);

	/* validate the provided properties */
	ret = zfs_crypto_verify_rewrap_nvlist(zhp, raw_props, inheritkey,
	    &props, errbuf);
	if (ret != 0)
		goto error;

	/*
	 * If the user wants to use the inheritkey variant of this function
	 * we don't need to collect any crypto arguments.
	 */
	if (!inheritkey) {
		/*
		 * Load keyformat and keylocation from the nvlist. Fetch from
		 * the dataset properties if not specified.
		 */
		(void) nvlist_lookup_uint64(props,
		    zfs_prop_to_name(ZFS_PROP_KEYFORMAT), &keyformat);
		(void) nvlist_lookup_string(props,
		    zfs_prop_to_name(ZFS_PROP_KEYLOCATION), &keylocation);

		if (is_encroot) {
			/*
			 * If this is already an encryption root, just keep
			 * any properties not set by the user.
			 */
			if (keyformat == ZFS_KEYFORMAT_NONE) {
				keyformat = zfs_prop_get_int(zhp,
				    ZFS_PROP_KEYFORMAT);
				ret = nvlist_add_uint64(props,
				    zfs_prop_to_name(ZFS_PROP_KEYFORMAT),
				    keyformat);
				if (ret != 0) {
					zfs_error_aux(zhp->zfs_hdl,
					    "Failed to "
					    "get existing keyformat "
					    "property.");
					goto error;
				}
			}

			if (keylocation == NULL) {
				ret = zfs_prop_get(zhp, ZFS_PROP_KEYLOCATION,
				    prop_keylocation, sizeof (prop_keylocation),
				    NULL, NULL, 0, B_TRUE);
				if (ret != 0) {
					zfs_error_aux(zhp->zfs_hdl,
					    "Failed to "
					    "get existing keylocation "
					    "property.");
					goto error;
				}

				keylocation = prop_keylocation;
			}
		} else {
			/* need a new key for non-encryption roots */
			if (keyformat == ZFS_KEYFORMAT_NONE) {
				ret = EINVAL;
				zfs_error_aux(zhp->zfs_hdl,
				    "Keyformat required "
				    "for new encryption root.");
				goto error;
			}

			/* default to prompt if no keylocation is specified */
			if (keylocation == NULL) {
				keylocation = "prompt";
				ret = nvlist_add_string(props,
				    zfs_prop_to_name(ZFS_PROP_KEYLOCATION),
				    keylocation);
				if (ret != 0)
					goto error;
			}
		}

		/* fetch the new wrapping key and associated properties */
		ret = populate_create_encryption_params_nvlists(zhp->zfs_hdl,
		    zhp, B_TRUE, keyformat, keylocation, props, &wkeydata,
		    &wkeylen);
		if (ret != 0)
			goto error;
	} else {
		/* check that zhp is an encryption root */
		if (!is_encroot) {
			zfs_error_aux(zhp->zfs_hdl,
			    "Key inheritting can only be performed on "
			    "encryption roots.");
			ret = EINVAL;
			goto error;
		}

		/* get the parent's name */
		ret = zfs_parent_name(zhp, parent_name, sizeof (parent_name));
		if (ret != 0) {
			zfs_error_aux(zhp->zfs_hdl,
			    "Root dataset cannot inherit key.");
			ret = EINVAL;
			goto error;
		}

		/* get a handle to the parent */
		pzhp = make_dataset_handle(zhp->zfs_hdl, parent_name);
		if (pzhp == NULL) {
			zfs_error_aux(zhp->zfs_hdl,
			    "Failed to lookup parent.");
			ret = ENOENT;
			goto error;
		}

		/* parent must be encrypted */
		pcrypt = zfs_prop_get_int(pzhp, ZFS_PROP_ENCRYPTION);
		if (pcrypt == ZIO_CRYPT_OFF) {
			zfs_error_aux(pzhp->zfs_hdl,
			    "Parent must be encrypted.");
			ret = EINVAL;
			goto error;
		}

		/* check that the parent's key is loaded */
		pkeystatus = zfs_prop_get_int(pzhp, ZFS_PROP_KEYSTATUS);
		if (pkeystatus == ZFS_KEYSTATUS_UNAVAILABLE) {
			zfs_error_aux(pzhp->zfs_hdl,
			    "Parent key must be loaded.");
			ret = EACCES;
			goto error;
		}
	}

	/* check that the key is loaded */
	keystatus = zfs_prop_get_int(zhp, ZFS_PROP_KEYSTATUS);
	if (keystatus == ZFS_KEYSTATUS_UNAVAILABLE) {
		zfs_error_aux(zhp->zfs_hdl,
		    "Key must be loaded.");
		ret = EACCES;
		goto error;
	}

	/* call the ioctl */
	ret = lzc_change_key(zhp->zfs_name, cmd, props, wkeydata, wkeylen);
	if (ret != 0) {
		switch (ret) {
		case EPERM:
			zfs_error_aux(zhp->zfs_hdl,
			    "Permission denied.");
			break;
		case EINVAL:
			zfs_error_aux(zhp->zfs_hdl,
			    "Invalid properties for key change.");
			break;
		case EACCES:
			zfs_error_aux(zhp->zfs_hdl,
			    "Key is not currently loaded.");
			break;
		case ZFS_ERR_CRYPTO_KEY_MISMATCH:
			zfs_error_aux(zhp->zfs_hdl,
			    "A dataset using the same encryption root as '%s' "
			    "has a key that cannot be unwrapped with the "
			    "root's wrapping key.",
			    zhp->zfs_name);
			break;
		}
		zfs_error(zhp->zfs_hdl, EZFS_CRYPTOFAILED, errbuf);
	}

	if (pzhp != NULL)
		zfs_close(pzhp);
	if (props != NULL)
		nvlist_free(props);
	if (wkeydata != NULL)
		free(wkeydata);

	return (ret);

error:
	if (pzhp != NULL)
		zfs_close(pzhp);
	if (props != NULL)
		nvlist_free(props);
	if (wkeydata != NULL)
		free(wkeydata);

	zfs_error(zhp->zfs_hdl, EZFS_CRYPTOFAILED, errbuf);
	return (ret);
}

boolean_t
zfs_is_encrypted(zfs_handle_t *zhp)
{
	uint8_t flags = zhp->zfs_dmustats.dds_flags;

	if (flags & DDS_FLAG_HAS_ENCRYPTED)
		return ((flags & DDS_FLAG_ENCRYPTED) != 0);

	return (zfs_prop_get_int(zhp, ZFS_PROP_ENCRYPTION) != ZIO_CRYPT_OFF);
}
