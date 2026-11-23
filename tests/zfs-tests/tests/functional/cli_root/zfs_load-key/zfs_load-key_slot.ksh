#!/bin/ksh -p
# SPDX-License-Identifier: CDDL-1.0
#
# This file and its contents are supplied under the terms of the
# Common Development and Distribution License ("CDDL"), version 1.0.
# You may only use this file in accordance with the terms of version
# 1.0 of the CDDL.
#
# A full copy of the text of the CDDL should have accompanied this
# source.  A copy of the CDDL is also available via the Internet at
# https://opensource.org/license/CDDL-1.0.
#

#
# Copyright (c) 2026 Umer Saleem
#

. $STF_SUITE/include/libtest.shlib
. $STF_SUITE/tests/functional/cli_root/zfs_load-key/zfs_load-key_common.kshlib

#
# DESCRIPTION:
# 'zfs load-key -S' rejects bad slot arguments and a slot that does not exist,
# and 'zfs unload-key' does not accept -S at all.
#
# STRATEGY:
# 1. Create two encrypted datasets, so the recursive case covers more than
#    one encryption root.
# 2. -S 0 and -S junk are usage errors.
# 3. unload-key does not take -S.
# 4. load-key -S 2 on a dataset with no additional slots fails, reports that
#    the slot does not exist, and leaves keystatus unavailable.
# 5. load-key -r -S 2 over the pool fails as a whole and reports the summary,
#    with every root still unavailable.
#

verify_runnable "both"

function cleanup
{
	for ds in $TESTPOOL/$TESTFS1 $TESTPOOL/$TESTFS2; do
		datasetexists $ds && destroy_dataset $ds -r
	done
}
log_onexit cleanup

log_assert "'zfs load-key -S' rejects bad slot arguments and a missing slot"

for ds in $TESTPOOL/$TESTFS1 $TESTPOOL/$TESTFS2; do
	log_must eval "echo $PASSPHRASE | zfs create -o encryption=on" \
	    "-o keyformat=passphrase -o keylocation=prompt $ds"
done

log_mustnot zfs load-key -S 0 $TESTPOOL/$TESTFS1
log_mustnot zfs load-key -S junk $TESTPOOL/$TESTFS1
log_mustnot zfs unload-key -S 1 $TESTPOOL/$TESTFS1

for ds in $TESTPOOL/$TESTFS1 $TESTPOOL/$TESTFS2; do
	log_must zfs unmount $ds
	log_must zfs unload-key $ds
done

typeset out rc
out=$(zfs load-key -S 2 $TESTPOOL/$TESTFS1 2>&1)
rc=$?
log_must test $rc -ne 0
log_must eval "echo \"$out\" | grep -q 'does not exist'"
log_must test "$(get_prop keystatus $TESTPOOL/$TESTFS1)" = "unavailable"

out=$(zfs load-key -r -S 2 $TESTPOOL 2>&1)
rc=$?
log_must test $rc -ne 0
log_must eval "echo \"$out\" | grep -q 'key(s) successfully loaded'"
for ds in $TESTPOOL/$TESTFS1 $TESTPOOL/$TESTFS2; do
	log_must test "$(get_prop keystatus $ds)" = "unavailable"
done

log_pass "'zfs load-key -S' rejects bad slots and a missing slot"
