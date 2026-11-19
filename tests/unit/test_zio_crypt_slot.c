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
 * Copyright (c) 2026, Umer Saleem.
 */

/*
 * Tests for zio_crypt_slot_wrap() / zio_crypt_slot_unwrap(), the primitive that
 * seals a dataset's wrapping key under a key-slot key.
 *
 * The property that matters most is the AAD binding: the same ciphertext must
 * not authenticate under a different key GUID, slot number or format version,
 * because that is what stops a slot entry being moved to another key object.
 */

#include <string.h>

#include <libspl.h>
#include <sys/zio_crypt.h>
#include <sys/crypto/common.h>
#include <sys/crypto/icp.h>
#include <sys/fs/zfs.h>

#include "unit.h"

typedef struct slot_suite {
	uint64_t	s_suite;
	const char	*s_name;
} slot_suite_t;

/*
 * The wrapping key is always WRAPPING_KEY_LEN bytes whatever the dataset's
 * cipher, so these cases exercise both modes rather than key lengths.
 */
static const slot_suite_t suites[] = {
	{ ZIO_CRYPT_AES_128_CCM, "aes-128-ccm" },
	{ ZIO_CRYPT_AES_256_CCM, "aes-256-ccm" },
	{ ZIO_CRYPT_AES_256_GCM, "aes-256-gcm" },
};

#define	NSUITES		(sizeof (suites) / sizeof (suites[0]))

static const uint64_t test_guid = 0x1122334455667788ULL;
static const uint64_t test_version = ZIO_CRYPT_KEY_CURRENT_VERSION;
static const uint64_t test_slot = 2;

static void
fill_key(uint8_t *buf, size_t len, unsigned seed)
{
	for (size_t i = 0; i < len; i++)
		buf[i] = (uint8_t)(seed * 31 + i * 7);
}

static void
init_keys(crypto_key_t *slot_key, crypto_key_t *wrong_key, uint8_t *slotbuf,
    uint8_t *wrongbuf)
{
	fill_key(slotbuf, MASTER_KEY_MAX_LEN, 1);
	fill_key(wrongbuf, MASTER_KEY_MAX_LEN, 3);

	slot_key->ck_length = CRYPTO_BYTES2BITS(WRAPPING_KEY_LEN);
	slot_key->ck_data = slotbuf;
	wrong_key->ck_length = CRYPTO_BYTES2BITS(WRAPPING_KEY_LEN);
	wrong_key->ck_data = wrongbuf;
}

static MunitResult
test_roundtrip(const MunitParameter params[], void *data)
{
	(void) params;
	(void) data;

	for (size_t i = 0; i < NSUITES; i++) {
		const slot_suite_t *s = &suites[i];
		crypto_key_t slot_key, wrong_key;
		uint8_t slotbuf[MASTER_KEY_MAX_LEN];
		uint8_t wrongbuf[MASTER_KEY_MAX_LEN];
		uint8_t rootbuf[MASTER_KEY_MAX_LEN];
		uint8_t out[MASTER_KEY_MAX_LEN];
		uint8_t iv[ZIO_DATA_IV_LEN];
		uint8_t mac[ZIO_DATA_MAC_LEN];
		uint8_t cipher[MASTER_KEY_MAX_LEN];

		init_keys(&slot_key, &wrong_key, slotbuf, wrongbuf);
		fill_key(rootbuf, WRAPPING_KEY_LEN, 2);
		memset(out, 0, sizeof (out));

		munit_assert_int(zio_crypt_slot_wrap(s->s_suite, &slot_key,
		    test_guid, test_version, test_slot, rootbuf, iv, mac,
		    cipher), ==, 0);
		munit_assert_int(zio_crypt_slot_unwrap(s->s_suite, &slot_key,
		    test_guid, test_version, test_slot, cipher, iv, mac,
		    out), ==, 0);
		munit_assert_memory_equal(WRAPPING_KEY_LEN, out, rootbuf);
	}

	return (MUNIT_OK);
}

static MunitResult
test_wrap_is_unique(const MunitParameter params[], void *data)
{
	(void) params;
	(void) data;

	for (size_t i = 0; i < NSUITES; i++) {
		const slot_suite_t *s = &suites[i];
		crypto_key_t slot_key, wrong_key;
		uint8_t slotbuf[MASTER_KEY_MAX_LEN];
		uint8_t wrongbuf[MASTER_KEY_MAX_LEN];
		uint8_t rootbuf[MASTER_KEY_MAX_LEN];
		uint8_t iv1[ZIO_DATA_IV_LEN], iv2[ZIO_DATA_IV_LEN];
		uint8_t mac1[ZIO_DATA_MAC_LEN], mac2[ZIO_DATA_MAC_LEN];
		uint8_t cipher1[MASTER_KEY_MAX_LEN];
		uint8_t cipher2[MASTER_KEY_MAX_LEN];

		init_keys(&slot_key, &wrong_key, slotbuf, wrongbuf);
		fill_key(rootbuf, WRAPPING_KEY_LEN, 2);

		munit_assert_int(zio_crypt_slot_wrap(s->s_suite, &slot_key,
		    test_guid, test_version, test_slot, rootbuf, iv1, mac1,
		    cipher1), ==, 0);
		munit_assert_int(zio_crypt_slot_wrap(s->s_suite, &slot_key,
		    test_guid, test_version, test_slot, rootbuf, iv2, mac2,
		    cipher2), ==, 0);

		/* a fresh IV per wrap, and the ciphertext is not the key */
		munit_assert_memory_not_equal(ZIO_DATA_IV_LEN, iv1, iv2);
		munit_assert_memory_not_equal(WRAPPING_KEY_LEN, cipher1,
		    cipher2);
		munit_assert_memory_not_equal(WRAPPING_KEY_LEN, cipher1,
		    rootbuf);
	}

	return (MUNIT_OK);
}

/*
 * The AAD must bind the ciphertext to one key object and one slot number.
 * Each of these would be an on-disk format vulnerability if it passed.
 */
static MunitResult
test_aad_binding(const MunitParameter params[], void *data)
{
	(void) params;
	(void) data;

	for (size_t i = 0; i < NSUITES; i++) {
		const slot_suite_t *s = &suites[i];
		crypto_key_t slot_key, wrong_key;
		uint8_t slotbuf[MASTER_KEY_MAX_LEN];
		uint8_t wrongbuf[MASTER_KEY_MAX_LEN];
		uint8_t rootbuf[MASTER_KEY_MAX_LEN];
		uint8_t out[MASTER_KEY_MAX_LEN];
		uint8_t iv[ZIO_DATA_IV_LEN];
		uint8_t mac[ZIO_DATA_MAC_LEN];
		uint8_t cipher[MASTER_KEY_MAX_LEN];

		init_keys(&slot_key, &wrong_key, slotbuf, wrongbuf);
		fill_key(rootbuf, WRAPPING_KEY_LEN, 2);

		munit_assert_int(zio_crypt_slot_wrap(s->s_suite, &slot_key,
		    test_guid, test_version, test_slot, rootbuf, iv, mac,
		    cipher), ==, 0);

		/* different slot number */
		munit_assert_int(zio_crypt_slot_unwrap(s->s_suite, &slot_key,
		    test_guid, test_version, test_slot + 1, cipher, iv, mac,
		    out), !=, 0);

		/* different key object */
		munit_assert_int(zio_crypt_slot_unwrap(s->s_suite, &slot_key,
		    test_guid + 1, test_version, test_slot, cipher, iv, mac,
		    out), !=, 0);

		/* different format version */
		munit_assert_int(zio_crypt_slot_unwrap(s->s_suite, &slot_key,
		    test_guid, test_version + 1, test_slot, cipher, iv, mac,
		    out), !=, 0);

		/*
		 * A different suite changes the cipher too, so this exercises
		 * suite binding end to end, not the AAD word alone.
		 */
		munit_assert_int(zio_crypt_slot_unwrap(
		    suites[(i + 1) % NSUITES].s_suite, &slot_key, test_guid,
		    test_version, test_slot, cipher, iv, mac, out), !=, 0);

		/* the wrong slot key must not authenticate */
		munit_assert_int(zio_crypt_slot_unwrap(s->s_suite, &wrong_key,
		    test_guid, test_version, test_slot, cipher, iv, mac,
		    out), !=, 0);
	}

	return (MUNIT_OK);
}

static MunitResult
test_tamper(const MunitParameter params[], void *data)
{
	(void) params;
	(void) data;

	for (size_t i = 0; i < NSUITES; i++) {
		const slot_suite_t *s = &suites[i];
		crypto_key_t slot_key, wrong_key;
		uint8_t slotbuf[MASTER_KEY_MAX_LEN];
		uint8_t wrongbuf[MASTER_KEY_MAX_LEN];
		uint8_t rootbuf[MASTER_KEY_MAX_LEN];
		uint8_t out[MASTER_KEY_MAX_LEN];
		uint8_t iv[ZIO_DATA_IV_LEN];
		uint8_t mac[ZIO_DATA_MAC_LEN];
		uint8_t cipher[MASTER_KEY_MAX_LEN];

		init_keys(&slot_key, &wrong_key, slotbuf, wrongbuf);
		fill_key(rootbuf, WRAPPING_KEY_LEN, 2);

		munit_assert_int(zio_crypt_slot_wrap(s->s_suite, &slot_key,
		    test_guid, test_version, test_slot, rootbuf, iv, mac,
		    cipher), ==, 0);

		/* flipping the ciphertext must fail authentication */
		cipher[0] ^= 1;
		munit_assert_int(zio_crypt_slot_unwrap(s->s_suite, &slot_key,
		    test_guid, test_version, test_slot, cipher, iv, mac,
		    out), !=, 0);
		cipher[0] ^= 1;

		/* so must flipping the MAC */
		mac[0] ^= 1;
		munit_assert_int(zio_crypt_slot_unwrap(s->s_suite, &slot_key,
		    test_guid, test_version, test_slot, cipher, iv, mac,
		    out), !=, 0);
		mac[0] ^= 1;

		/* and the untampered copy must still verify */
		munit_assert_int(zio_crypt_slot_unwrap(s->s_suite, &slot_key,
		    test_guid, test_version, test_slot, cipher, iv, mac,
		    out), ==, 0);
	}

	return (MUNIT_OK);
}

static MunitResult
test_invalid_args(const MunitParameter params[], void *data)
{
	uint8_t keybuf[MASTER_KEY_MAX_LEN];
	uint8_t shortbuf[MASTER_KEY_MAX_LEN];
	uint8_t iv[ZIO_DATA_IV_LEN];
	uint8_t mac[ZIO_DATA_MAC_LEN];
	uint8_t cipher[MASTER_KEY_MAX_LEN];
	crypto_key_t key, shortkey;

	(void) params;
	(void) data;

	fill_key(keybuf, sizeof (keybuf), 5);
	fill_key(shortbuf, sizeof (shortbuf), 6);

	key.ck_length = CRYPTO_BYTES2BITS(32);
	key.ck_data = keybuf;
	shortkey.ck_length = CRYPTO_BYTES2BITS(16);
	shortkey.ck_data = shortbuf;

	munit_assert_int(zio_crypt_slot_wrap(ZIO_CRYPT_AES_256_GCM, NULL,
	    test_guid, test_version, test_slot, keybuf, iv, mac, cipher),
	    !=, 0);
	munit_assert_int(zio_crypt_slot_wrap(ZIO_CRYPT_AES_256_GCM, &key,
	    test_guid, test_version, test_slot, NULL, iv, mac, cipher),
	    !=, 0);
	munit_assert_int(zio_crypt_slot_wrap(ZIO_CRYPT_AES_256_GCM, &key,
	    test_guid, test_version, test_slot, keybuf, NULL, mac, cipher),
	    !=, 0);
	munit_assert_int(zio_crypt_slot_wrap(ZIO_CRYPT_AES_256_GCM, &key,
	    test_guid, test_version, test_slot, keybuf, iv, NULL, cipher),
	    !=, 0);
	munit_assert_int(zio_crypt_slot_wrap(ZIO_CRYPT_AES_256_GCM, &key,
	    test_guid, test_version, test_slot, keybuf, iv, mac, NULL),
	    !=, 0);

	/* suites that are not AEAD ciphers */
	munit_assert_int(zio_crypt_slot_wrap(ZIO_CRYPT_OFF, &key, test_guid,
	    test_version, test_slot, keybuf, iv, mac, cipher), !=, 0);
	munit_assert_int(zio_crypt_slot_wrap(ZIO_CRYPT_FUNCTIONS, &key,
	    test_guid, test_version, test_slot, keybuf, iv, mac, cipher),
	    !=, 0);

	/*
	 * Wrapping keys are always WRAPPING_KEY_LEN, so a truncated slot key
	 * must be refused by every suite rather than sealing part of the key.
	 */
	for (size_t i = 0; i < NSUITES; i++) {
		munit_assert_int(zio_crypt_slot_wrap(suites[i].s_suite,
		    &shortkey, test_guid, test_version, test_slot, keybuf, iv,
		    mac, cipher), !=, 0);
	}

	return (MUNIT_OK);
}

static const MunitTest slot_tests[] = {
	UNIT_TEST("roundtrip",		test_roundtrip),
	UNIT_TEST("wrap_is_unique",	test_wrap_is_unique),
	UNIT_TEST("aad_binding",	test_aad_binding),
	UNIT_TEST("tamper",		test_tamper),
	UNIT_TEST("invalid_args",	test_invalid_args),
	{ 0 },
};

static const MunitSuite slot_test_suite = {
	"zio_crypt_slot.",
	slot_tests,
	NULL,
	1,
	MUNIT_SUITE_OPTION_NONE,
};

int
main(int argc, char **argv)
{
	/* random_get_bytes() and the crypto backend need initialising */
	libspl_init();
	if (icp_init() != 0)
		return (1);

	return (munit_suite_main(&slot_test_suite, NULL, argc, argv));
}
