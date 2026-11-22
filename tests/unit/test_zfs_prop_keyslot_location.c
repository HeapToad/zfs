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
 * Tests for zfs_prop_keyslot_location(). It recognises keylocation_<n> for
 * n >= 2 only; slot 1 is the unsuffixed keylocation property, so
 * keylocation_1 is not part of the family. The suffix must be plain digits.
 */

#include <libspl.h>
#include <sys/fs/zfs.h>

#include "unit.h"

static MunitResult
test_matches(const MunitParameter params[], void *data)
{
	uint64_t slot = 0;

	(void) params;
	(void) data;

	munit_assert_true(zfs_prop_keyslot_location("keylocation_2", &slot));
	munit_assert_uint64(slot, ==, 2);

	munit_assert_true(zfs_prop_keyslot_location("keylocation_10", &slot));
	munit_assert_uint64(slot, ==, 10);

	/* the out parameter is optional */
	munit_assert_true(zfs_prop_keyslot_location("keylocation_3", NULL));

	return (MUNIT_OK);
}

static MunitResult
test_rejects(const MunitParameter params[], void *data)
{
	uint64_t slot;

	(void) params;
	(void) data;

	/* slot 1 is the unsuffixed keylocation property */
	munit_assert_false(zfs_prop_keyslot_location("keylocation_1", &slot));
	munit_assert_false(zfs_prop_keyslot_location("keylocation_0", &slot));
	munit_assert_false(zfs_prop_keyslot_location("keylocation", &slot));
	munit_assert_false(zfs_prop_keyslot_location("keylocation_", &slot));

	/* the suffix is digits only, in canonical form */
	munit_assert_false(zfs_prop_keyslot_location("keylocation_2x", &slot));
	munit_assert_false(zfs_prop_keyslot_location("keylocation_-2", &slot));
	munit_assert_false(zfs_prop_keyslot_location("keylocation_ 2", &slot));
	munit_assert_false(zfs_prop_keyslot_location("keylocation_02", &slot));

	/* the prefix must match from the start */
	munit_assert_false(zfs_prop_keyslot_location("xkeylocation_2", &slot));
	munit_assert_false(zfs_prop_keyslot_location("keyformat", &slot));

	/* a suffix that overflows uint64_t is not a slot number */
	munit_assert_false(zfs_prop_keyslot_location(
	    "keylocation_18446744073709551616", &slot));

	return (MUNIT_OK);
}

static const MunitTest keyslot_location_tests[] = {
	UNIT_TEST("matches",		test_matches),
	UNIT_TEST("rejects",		test_rejects),
	{ 0 },
};

static const MunitSuite keyslot_location_test_suite = {
	"zfs_prop_keyslot_location.",
	keyslot_location_tests,
	NULL,
	1,
	MUNIT_SUITE_OPTION_NONE,
};

int
main(int argc, char **argv)
{
	libspl_init();

	return (munit_suite_main(&keyslot_location_test_suite, NULL, argc,
	    argv));
}
