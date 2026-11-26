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
. $STF_SUITE/tests/functional/cli_root/zfs_keyslot/zfs_keyslot.kshlib

#
# DESCRIPTION:
# The stored location of every slot is editable while the extra slots exist,
# and the inherit forms are refused.
#
# STRATEGY:
# 1. Create an encrypted root with slots 2 and 3, each with a raw key file,
#    and a copy of the slot 1 and slot 2 key material.
# 2. Point slot 1 at its copy with 'zfs set keylocation': only the source
#    changes, slots 2 and 3 are untouched, and slot 1 still unlocks.
# 3. Point slot 2 at its copy with 'zfs keyslot set -S 2 -o keylocation':
#    the change is in place, slot 3 is untouched, and slot 2 still unlocks.
# 4. 'zfs set keylocation=none' is refused for an encrypted dataset, and
#    neither 'keylocation' nor 'keylocation_2' can be inherited.
# 5. The refusals change nothing, and slot 3 still unlocks.
#

verify_runnable "both"

typeset encroot=$TESTPOOL/$TESTFS1/enc

function cleanup
{
	datasetexists $TESTPOOL/$TESTFS1 && \
	    keyslot_unmount_tree $TESTPOOL/$TESTFS1
	datasetexists $TESTPOOL/$TESTFS1 && \
	    destroy_dataset $TESTPOOL/$TESTFS1 -r
	rm -f $TESTDIR/kskey.[0-9] $TESTDIR/kskey.[0-9]b
}
log_onexit cleanup

#
# Unlock from slot $1 and read the file. The tree is mounted and unmounted
# around the read so the stored location, not -L, supplies the key.
#
function verify_data
{
	typeset slot=$1

	keyslot_unlock $encroot $slot
	log_must zfs mount $encroot
	log_must grep -q data /$encroot/file
	log_must zfs unmount $encroot
}

log_assert "every slot's stored location is editable and inherit is refused"

log_must zfs create $TESTPOOL/$TESTFS1
for i in 1 2 3; do
	log_must eval "head -c 32 /dev/urandom > $TESTDIR/kskey.$i"
done
# A location holds the same key material: repointing does not rewrap.
log_must cp $TESTDIR/kskey.1 $TESTDIR/kskey.1b
log_must cp $TESTDIR/kskey.2 $TESTDIR/kskey.2b

log_must zfs create -o encryption=on -o keyformat=raw \
    -o keylocation=file://$TESTDIR/kskey.1 $encroot
log_must zfs keyslot add -S 2 -o keyformat=raw \
    -o keylocation=file://$TESTDIR/kskey.2 $encroot
log_must zfs keyslot add -S 3 -o keyformat=raw \
    -o keylocation=file://$TESTDIR/kskey.3 $encroot
log_must eval "echo data > /$encroot/file"

#
# 2. Slot 1: 'zfs set keylocation' with the extra slots in place.
#
log_must zfs set keylocation=file://$TESTDIR/kskey.1b $encroot
log_must test "$(get_prop keylocation $encroot)" = \
    "file://$TESTDIR/kskey.1b"
log_must test "$(zfs get -H -o source keylocation $encroot)" = "local"
log_must test "$(get_prop keylocation_2 $encroot)" = \
    "file://$TESTDIR/kskey.2"
log_must test "$(get_prop keylocation_3 $encroot)" = \
    "file://$TESTDIR/kskey.3"
verify_data 1

#
# 3. Slot 2: an in-place edit, with slot 3 untouched.
#
log_must zfs keyslot set -S 2 -o keylocation=file://$TESTDIR/kskey.2b \
    $encroot
log_must test "$(get_prop keylocation_2 $encroot)" = \
    "file://$TESTDIR/kskey.2b"
log_must test "$(zfs get -H -o source keylocation_2 $encroot)" = "local"
log_must test "$(get_prop keylocation_3 $encroot)" = \
    "file://$TESTDIR/kskey.3"
verify_data 2

#
# 4. Refusals.
#
keyslot_mustfail 'must not be' zfs set keylocation=none $encroot
keyslot_mustfail 'cannot be inherited' zfs inherit keylocation $encroot
keyslot_mustfail 'invalid property' zfs inherit keylocation_2 $encroot

#
# 5. They changed nothing.
#
log_must test "$(get_prop keylocation $encroot)" = \
    "file://$TESTDIR/kskey.1b"
log_must test "$(get_prop keylocation_2 $encroot)" = \
    "file://$TESTDIR/kskey.2b"
verify_data 3

log_pass "every slot's stored location is editable and inherit is refused"
