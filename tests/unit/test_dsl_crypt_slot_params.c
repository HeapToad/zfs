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
 * Tests for dsl_crypto_key_slot_params_valid(). A slot's key derivation
 * parameters must follow the same rules zfs create applies: a passphrase needs
 * a non-zero salt and at least MIN_PBKDF2_ITERATIONS iterations, while every
 * other format needs both zero.
 */

#include <libspl.h>
#include <sys/dsl_crypt.h>
#include <sys/fs/zfs.h>

#include "unit.h"

static MunitResult
test_raw_hex(const MunitParameter params[], void *data)
{
	(void) params;
	(void) data;

	munit_assert_true(dsl_crypto_key_slot_params_valid(
	    ZFS_KEYFORMAT_RAW, 0, 0));
	munit_assert_true(dsl_crypto_key_slot_params_valid(
	    ZFS_KEYFORMAT_HEX, 0, 0));

	munit_assert_false(dsl_crypto_key_slot_params_valid(
	    ZFS_KEYFORMAT_RAW, 1, 0));
	munit_assert_false(dsl_crypto_key_slot_params_valid(
	    ZFS_KEYFORMAT_RAW, 0, 1));
	munit_assert_false(dsl_crypto_key_slot_params_valid(
	    ZFS_KEYFORMAT_HEX, 1, MIN_PBKDF2_ITERATIONS));

	return (MUNIT_OK);
}

static MunitResult
test_passphrase(const MunitParameter params[], void *data)
{
	(void) params;
	(void) data;

	munit_assert_true(dsl_crypto_key_slot_params_valid(
	    ZFS_KEYFORMAT_PASSPHRASE, 1, MIN_PBKDF2_ITERATIONS));
	munit_assert_true(dsl_crypto_key_slot_params_valid(
	    ZFS_KEYFORMAT_PASSPHRASE, 1, MIN_PBKDF2_ITERATIONS + 100000));

	munit_assert_false(dsl_crypto_key_slot_params_valid(
	    ZFS_KEYFORMAT_PASSPHRASE, 0, MIN_PBKDF2_ITERATIONS));
	munit_assert_false(dsl_crypto_key_slot_params_valid(
	    ZFS_KEYFORMAT_PASSPHRASE, 1, 0));
	munit_assert_false(dsl_crypto_key_slot_params_valid(
	    ZFS_KEYFORMAT_PASSPHRASE, 1, MIN_PBKDF2_ITERATIONS - 1));

	return (MUNIT_OK);
}

static MunitResult
test_bad_format(const MunitParameter params[], void *data)
{
	(void) params;
	(void) data;

	munit_assert_false(dsl_crypto_key_slot_params_valid(
	    ZFS_KEYFORMAT_NONE, 0, 0));
	munit_assert_false(dsl_crypto_key_slot_params_valid(
	    ZFS_KEYFORMAT_FORMATS, 0, 0));
	munit_assert_false(dsl_crypto_key_slot_params_valid(
	    (zfs_keyformat_t)(ZFS_KEYFORMAT_FORMATS + 1), 0, 0));

	return (MUNIT_OK);
}

static const MunitTest slot_params_tests[] = {
	UNIT_TEST("raw_hex",		test_raw_hex),
	UNIT_TEST("passphrase",		test_passphrase),
	UNIT_TEST("bad_format",		test_bad_format),
	{ 0 },
};

static const MunitSuite slot_params_test_suite = {
	"dsl_crypto_key_slot_params_valid.",
	slot_params_tests,
	NULL,
	1,
	MUNIT_SUITE_OPTION_NONE,
};

int
main(int argc, char **argv)
{
	libspl_init();

	return (munit_suite_main(&slot_params_test_suite, NULL, argc, argv));
}
