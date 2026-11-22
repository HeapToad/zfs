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
 * Tests for dsl_crypto_key_slot_name(). Slot 1 must resolve to the legacy
 * on-disk names, byte for byte, because that is what keeps existing key
 * objects readable; its key derivation parameters use their property names.
 * Slots 2 and up use DSL_CRYPTO_<FIELD>_<n> and have no master or HMAC entry.
 * Unsupported slots and fields, and a short buffer, must resolve to NULL.
 */

#include <libspl.h>
#include <sys/dsl_crypt.h>
#include <zfs_prop.h>

#include "unit.h"

static MunitResult
test_primary_slot(const MunitParameter params[], void *data)
{
	char name[DSL_CRYPTO_KEY_SLOT_NAME_MAX];

	(void) params;
	(void) data;

	munit_assert_string_equal(
	    dsl_crypto_key_slot_name(name, sizeof (name),
	    DSL_CRYPTO_KEY_SLOT_PRIMARY, DSL_CRYPTO_KEY_SLOT_MASTER),
	    "DSL_CRYPTO_MASTER_KEY_1");
	munit_assert_string_equal(
	    dsl_crypto_key_slot_name(name, sizeof (name),
	    DSL_CRYPTO_KEY_SLOT_PRIMARY, DSL_CRYPTO_KEY_SLOT_HMAC),
	    "DSL_CRYPTO_HMAC_KEY_1");
	munit_assert_string_equal(
	    dsl_crypto_key_slot_name(name, sizeof (name),
	    DSL_CRYPTO_KEY_SLOT_PRIMARY, DSL_CRYPTO_KEY_SLOT_IV),
	    "DSL_CRYPTO_IV");
	munit_assert_string_equal(
	    dsl_crypto_key_slot_name(name, sizeof (name),
	    DSL_CRYPTO_KEY_SLOT_PRIMARY, DSL_CRYPTO_KEY_SLOT_MAC),
	    "DSL_CRYPTO_MAC");
	munit_assert_string_equal(
	    dsl_crypto_key_slot_name(name, sizeof (name),
	    DSL_CRYPTO_KEY_SLOT_PRIMARY, DSL_CRYPTO_KEY_SLOT_KEYFORMAT),
	    "keyformat");
	munit_assert_string_equal(
	    dsl_crypto_key_slot_name(name, sizeof (name),
	    DSL_CRYPTO_KEY_SLOT_PRIMARY, DSL_CRYPTO_KEY_SLOT_PBKDF2SALT),
	    "pbkdf2salt");
	munit_assert_string_equal(
	    dsl_crypto_key_slot_name(name, sizeof (name),
	    DSL_CRYPTO_KEY_SLOT_PRIMARY, DSL_CRYPTO_KEY_SLOT_PBKDF2ITERS),
	    "pbkdf2iters");

	return (MUNIT_OK);
}

static MunitResult
test_secondary_slot(const MunitParameter params[], void *data)
{
	char name[DSL_CRYPTO_KEY_SLOT_NAME_MAX];

	(void) params;
	(void) data;

	munit_assert_string_equal(
	    dsl_crypto_key_slot_name(name, sizeof (name), 2,
	    DSL_CRYPTO_KEY_SLOT_WRAP), "DSL_CRYPTO_WRAP_2");
	munit_assert_string_equal(
	    dsl_crypto_key_slot_name(name, sizeof (name), 2,
	    DSL_CRYPTO_KEY_SLOT_IV), "DSL_CRYPTO_IV_2");
	munit_assert_string_equal(
	    dsl_crypto_key_slot_name(name, sizeof (name), 2,
	    DSL_CRYPTO_KEY_SLOT_MAC), "DSL_CRYPTO_MAC_2");
	munit_assert_string_equal(
	    dsl_crypto_key_slot_name(name, sizeof (name), 2,
	    DSL_CRYPTO_KEY_SLOT_KEYFORMAT), "DSL_CRYPTO_KEYFORMAT_2");
	munit_assert_string_equal(
	    dsl_crypto_key_slot_name(name, sizeof (name), 2,
	    DSL_CRYPTO_KEY_SLOT_PBKDF2SALT), "DSL_CRYPTO_PBKDF2SALT_2");
	munit_assert_string_equal(
	    dsl_crypto_key_slot_name(name, sizeof (name), 2,
	    DSL_CRYPTO_KEY_SLOT_PBKDF2ITERS), "DSL_CRYPTO_PBKDF2ITERS_2");

	/* the number is not fixed width, so large slots must still fit */
	munit_assert_string_equal(
	    dsl_crypto_key_slot_name(name, sizeof (name), 65535,
	    DSL_CRYPTO_KEY_SLOT_WRAP), "DSL_CRYPTO_WRAP_65535");

	return (MUNIT_OK);
}

static MunitResult
test_unsupported(const MunitParameter params[], void *data)
{
	char name[DSL_CRYPTO_KEY_SLOT_NAME_MAX];

	(void) params;
	(void) data;

	/* slot 1 has no WRAP entry (it seals the master key, not wkey_1) */
	munit_assert_ptr_null(dsl_crypto_key_slot_name(name, sizeof (name),
	    DSL_CRYPTO_KEY_SLOT_PRIMARY, DSL_CRYPTO_KEY_SLOT_WRAP));
	/* slots 2 and up have no master or HMAC entry */
	munit_assert_ptr_null(dsl_crypto_key_slot_name(name, sizeof (name), 2,
	    DSL_CRYPTO_KEY_SLOT_MASTER));
	munit_assert_ptr_null(dsl_crypto_key_slot_name(name, sizeof (name), 2,
	    DSL_CRYPTO_KEY_SLOT_HMAC));
	/* slot 0 is not a slot */
	munit_assert_ptr_null(dsl_crypto_key_slot_name(name, sizeof (name), 0,
	    DSL_CRYPTO_KEY_SLOT_IV));
	/* FIELDS is a sentinel, not a field */
	munit_assert_ptr_null(dsl_crypto_key_slot_name(name, sizeof (name),
	    DSL_CRYPTO_KEY_SLOT_PRIMARY, DSL_CRYPTO_KEY_SLOT_FIELDS));
	munit_assert_ptr_null(dsl_crypto_key_slot_name(name, sizeof (name), 2,
	    DSL_CRYPTO_KEY_SLOT_FIELDS));

	return (MUNIT_OK);
}

static MunitResult
test_short_buffer(const MunitParameter params[], void *data)
{
	char tiny[8];

	(void) params;
	(void) data;

	/* "DSL_CRYPTO_MASTER_KEY_1" and "DSL_CRYPTO_WRAP_2" do not fit in 8 */
	munit_assert_ptr_null(dsl_crypto_key_slot_name(tiny, sizeof (tiny),
	    DSL_CRYPTO_KEY_SLOT_PRIMARY, DSL_CRYPTO_KEY_SLOT_MASTER));
	munit_assert_ptr_null(dsl_crypto_key_slot_name(tiny, sizeof (tiny), 2,
	    DSL_CRYPTO_KEY_SLOT_WRAP));
	munit_assert_ptr_null(dsl_crypto_key_slot_name(NULL, 16, 2,
	    DSL_CRYPTO_KEY_SLOT_WRAP));
	munit_assert_ptr_null(dsl_crypto_key_slot_name(tiny, 0, 2,
	    DSL_CRYPTO_KEY_SLOT_WRAP));

	return (MUNIT_OK);
}

static const MunitTest slot_name_tests[] = {
	UNIT_TEST("primary_slot",	test_primary_slot),
	UNIT_TEST("secondary_slot",	test_secondary_slot),
	UNIT_TEST("unsupported",	test_unsupported),
	UNIT_TEST("short_buffer",	test_short_buffer),
	{ 0 },
};

static const MunitSuite slot_name_test_suite = {
	"dsl_crypto_key_slot_name.",
	slot_name_tests,
	NULL,
	1,
	MUNIT_SUITE_OPTION_NONE,
};

int
main(int argc, char **argv)
{
	libspl_init();
	/* zfs_prop_to_name() needs the property table registered */
	zfs_prop_init();

	return (munit_suite_main(&slot_name_test_suite, NULL, argc, argv));
}
