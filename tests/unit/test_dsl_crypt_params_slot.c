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
 * Tests for the "keyslot" argument of dsl_crypto_params_create_nvlist().
 * The slot selects which key slot the root's wrapping key is loaded from.
 * It must default to the primary slot (1) -- kmem_zalloc gives no useful
 * default, so the parser has to set it -- must reject slot 0, is unbounded
 * above (D9), and must reject an nvpair of the wrong type rather than fall
 * back to slot 1. A props-only call (create, change-key, raw receive) never
 * names a slot and must stay on slot 1.
 */

#include <libspl.h>
#include <sys/dsl_crypt.h>
#include <sys/fs/zfs.h>
#include <sys/nvpair.h>
#include <zfs_prop.h>

#include "unit.h"

static MunitResult
test_default_slot(const MunitParameter params[], void *data)
{
	dsl_crypto_params_t *dcp = NULL;
	nvlist_t *args = NULL;

	(void) params;
	(void) data;

	/* no crypto_args at all: the create/change-key/recv shape */
	unit_ok(dsl_crypto_params_create_nvlist(DCP_CMD_NONE, NULL, NULL,
	    &dcp));
	unit_notnull(dcp);
	unit_eq(dcp->cp_slot, DSL_CRYPTO_KEY_SLOT_PRIMARY);
	dsl_crypto_params_free(dcp, B_TRUE);

	/* empty crypto_args: load-key without "keyslot" */
	unit_ok(nvlist_alloc(&args, NV_UNIQUE_NAME, KM_SLEEP));
	unit_ok(dsl_crypto_params_create_nvlist(DCP_CMD_NONE, NULL, args,
	    &dcp));
	unit_notnull(dcp);
	unit_eq(dcp->cp_slot, DSL_CRYPTO_KEY_SLOT_PRIMARY);
	dsl_crypto_params_free(dcp, B_TRUE);
	nvlist_free(args);

	return (MUNIT_OK);
}

static MunitResult
test_explicit_slot(const MunitParameter params[], void *data)
{
	const uint64_t slots[] = { 2, 3, 65535, UINT64_MAX };
	dsl_crypto_params_t *dcp = NULL;
	nvlist_t *args = NULL;
	uint_t i;

	(void) params;
	(void) data;

	/*
	 * There is no upper bound on the slot number: names are formatted on
	 * demand and allocation starts from the bottom, so the parser must not
	 * impose a ceiling.
	 */
	for (i = 0; i < sizeof (slots) / sizeof (slots[0]); i++) {
		unit_ok(nvlist_alloc(&args, NV_UNIQUE_NAME, KM_SLEEP));
		fnvlist_add_uint64(args, "keyslot", slots[i]);
		unit_ok(dsl_crypto_params_create_nvlist(DCP_CMD_NONE, NULL,
		    args, &dcp));
		unit_notnull(dcp);
		unit_eq(dcp->cp_slot, slots[i]);
		dsl_crypto_params_free(dcp, B_TRUE);
		nvlist_free(args);
		args = NULL;
	}

	return (MUNIT_OK);
}

static MunitResult
test_rejects_slot_zero(const MunitParameter params[], void *data)
{
	dsl_crypto_params_t *dcp = NULL;
	nvlist_t *args = NULL;

	(void) params;
	(void) data;

	/* there is no slot 0; the primary slot is 1 */
	unit_ok(nvlist_alloc(&args, NV_UNIQUE_NAME, KM_SLEEP));
	fnvlist_add_uint64(args, "keyslot", 0);
	unit_err(dsl_crypto_params_create_nvlist(DCP_CMD_NONE, NULL, args,
	    &dcp), EINVAL);
	unit_null(dcp);
	nvlist_free(args);

	return (MUNIT_OK);
}

static MunitResult
test_rejects_wrong_type(const MunitParameter params[], void *data)
{
	dsl_crypto_params_t *dcp = NULL;
	nvlist_t *args = NULL;

	(void) params;
	(void) data;

	/*
	 * "keyslot" is a uint64. Any other type is a caller bug and must fail,
	 * not be silently treated as the primary slot.
	 */
	unit_ok(nvlist_alloc(&args, NV_UNIQUE_NAME, KM_SLEEP));
	fnvlist_add_string(args, "keyslot", "2");
	unit_err(dsl_crypto_params_create_nvlist(DCP_CMD_NONE, NULL, args,
	    &dcp), EINVAL);
	unit_null(dcp);
	nvlist_free(args);

	return (MUNIT_OK);
}

static MunitResult
test_props_path_unaffected(const MunitParameter params[], void *data)
{
	dsl_crypto_params_t *dcp = NULL;
	nvlist_t *props = NULL;

	(void) params;
	(void) data;

	/*
	 * An ordinary create: props only, no crypto_args, still slot 1. The
	 * property table must be registered first, as libzfs_init() does, or
	 * zfs_prop_to_name() returns NULL for every property.
	 */
	zfs_prop_init();

	unit_ok(nvlist_alloc(&props, NV_UNIQUE_NAME, KM_SLEEP));
	fnvlist_add_uint64(props, zfs_prop_to_name(ZFS_PROP_ENCRYPTION),
	    ZIO_CRYPT_ON);
	fnvlist_add_uint64(props, zfs_prop_to_name(ZFS_PROP_KEYFORMAT),
	    ZFS_KEYFORMAT_RAW);
	fnvlist_add_string(props, zfs_prop_to_name(ZFS_PROP_KEYLOCATION),
	    "file:///tmp/k");

	unit_ok(dsl_crypto_params_create_nvlist(DCP_CMD_NONE, props, NULL,
	    &dcp));
	unit_notnull(dcp);
	unit_eq(dcp->cp_slot, DSL_CRYPTO_KEY_SLOT_PRIMARY);
	unit_eq(dcp->cp_crypt, ZIO_CRYPT_ON_VALUE);
	unit_notnull(dcp->cp_keylocation);

	dsl_crypto_params_free(dcp, B_TRUE);
	nvlist_free(props);

	return (MUNIT_OK);
}

static const MunitTest params_slot_tests[] = {
	UNIT_TEST("default_slot",		test_default_slot),
	UNIT_TEST("explicit_slot",		test_explicit_slot),
	UNIT_TEST("rejects_slot_zero",		test_rejects_slot_zero),
	UNIT_TEST("rejects_wrong_type",		test_rejects_wrong_type),
	UNIT_TEST("props_path_unaffected",	test_props_path_unaffected),
	{ 0 },
};

static const MunitSuite params_slot_test_suite = {
	"dsl_crypto_params_slot.",
	params_slot_tests,
	NULL,
	1,
	MUNIT_SUITE_OPTION_NONE,
};

int
main(int argc, char **argv)
{
	libspl_init();

	return (munit_suite_main(&params_slot_test_suite, NULL, argc, argv));
}
