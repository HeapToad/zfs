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
 * Tests for dsl_crypto_key_slot_wrap_parse(). It recognises the
 * DSL_CRYPTO_WRAP_<n> entry names produced by dsl_crypto_key_slot_name() and
 * returns the slot number for n >= 2. Slot 1 has no WRAP entry.
 */

#include <libspl.h>
#include <sys/dsl_crypt.h>

#include "unit.h"

static MunitResult
test_matches(const MunitParameter params[], void *data)
{
	(void) params;
	(void) data;

	munit_assert_uint64(dsl_crypto_key_slot_wrap_parse(
	    "DSL_CRYPTO_WRAP_2"), ==, 2);
	munit_assert_uint64(dsl_crypto_key_slot_wrap_parse(
	    "DSL_CRYPTO_WRAP_10"), ==, 10);
	munit_assert_uint64(dsl_crypto_key_slot_wrap_parse(
	    "DSL_CRYPTO_WRAP_65535"), ==, 65535);

	return (MUNIT_OK);
}

static MunitResult
test_rejects(const MunitParameter params[], void *data)
{
	(void) params;
	(void) data;

	/* slot 1 has no WRAP entry, and slot 0 is not a slot */
	munit_assert_uint64(dsl_crypto_key_slot_wrap_parse(
	    "DSL_CRYPTO_WRAP_1"), ==, 0);
	munit_assert_uint64(dsl_crypto_key_slot_wrap_parse(
	    "DSL_CRYPTO_WRAP_0"), ==, 0);
	munit_assert_uint64(dsl_crypto_key_slot_wrap_parse(
	    "DSL_CRYPTO_WRAP_"), ==, 0);
	munit_assert_uint64(dsl_crypto_key_slot_wrap_parse(
	    "DSL_CRYPTO_WRAP"), ==, 0);

	/* canonical decimal only */
	munit_assert_uint64(dsl_crypto_key_slot_wrap_parse(
	    "DSL_CRYPTO_WRAP_02"), ==, 0);
	munit_assert_uint64(dsl_crypto_key_slot_wrap_parse(
	    "DSL_CRYPTO_WRAP_2x"), ==, 0);
	munit_assert_uint64(dsl_crypto_key_slot_wrap_parse(
	    "DSL_CRYPTO_WRAP_-2"), ==, 0);

	/* other key-object entries are not slots */
	munit_assert_uint64(dsl_crypto_key_slot_wrap_parse(
	    "DSL_CRYPTO_IV_2"), ==, 0);
	munit_assert_uint64(dsl_crypto_key_slot_wrap_parse(
	    "DSL_CRYPTO_GUID"), ==, 0);
	munit_assert_uint64(dsl_crypto_key_slot_wrap_parse(
	    "keylocation_2"), ==, 0);

	/* overflow is not a slot number */
	munit_assert_uint64(dsl_crypto_key_slot_wrap_parse(
	    "DSL_CRYPTO_WRAP_18446744073709551616"), ==, 0);

	return (MUNIT_OK);
}

static const MunitTest wrap_parse_tests[] = {
	UNIT_TEST("matches",		test_matches),
	UNIT_TEST("rejects",		test_rejects),
	{ 0 },
};

static const MunitSuite wrap_parse_test_suite = {
	"dsl_crypto_key_slot_wrap_parse.",
	wrap_parse_tests,
	NULL,
	1,
	MUNIT_SUITE_OPTION_NONE,
};

int
main(int argc, char **argv)
{
	libspl_init();

	return (munit_suite_main(&wrap_parse_test_suite, NULL, argc, argv));
}
