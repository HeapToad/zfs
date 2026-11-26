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
# Renaming a slotted encryption root, rolling back a child and destroying a
# child recursively leave the root's key object - and its slots - intact.
#
# STRATEGY:
# 1. Create an encrypted root with a child, add slots 2 and 3, and write a
#    file through the root.
# 2. Record the root's key object id and a fingerprint of its deterministic
#    entries, and confirm the pool holds two key objects.
# 3. 'zfs rename' the root: same object id, same fingerprint (ROOT_DDOBJ
#    included), slot 2's location still local, and slot 2 still unlocks.
# 4. Snapshot the child, add a file, roll it back: the fingerprint is
#    unchanged, the new file is gone, and slot 2 still unlocks.
# 5. 'zfs destroy -r' the child: only its key object disappears, the
#    fingerprint is unchanged, and slot 2 still unlocks.
#

verify_runnable "both"

typeset encroot=$TESTPOOL/$TESTFS1/enc
typeset renroot=$TESTPOOL/$TESTFS1/ren

function cleanup
{
	datasetexists $TESTPOOL/$TESTFS1 && \
	    keyslot_unmount_tree $TESTPOOL/$TESTFS1
	datasetexists $TESTPOOL/$TESTFS1 && \
	    destroy_dataset $TESTPOOL/$TESTFS1 -r
	rm -f $TESTDIR/kskey.[0-9]
}
log_onexit cleanup

#
# Unlock the root from slot 2, mount it and read the file written before the
# operation. Mounting only the root keeps the child's state out of the way.
#
function verify_tree
{
	typeset ds=$1

	keyslot_unlock $ds 2
	log_must zfs mount $ds
	log_must grep -q data /$ds/file
}

log_assert "rename, rollback and destroy -r keep a slotted root's key object"

log_must zfs create $TESTPOOL/$TESTFS1
for i in 1 2 3; do
	log_must eval "head -c 32 /dev/urandom > $TESTDIR/kskey.$i"
done

log_must zfs create -o encryption=on -o keyformat=raw \
    -o keylocation=file://$TESTDIR/kskey.1 $encroot
log_must zfs create $encroot/child
log_must zfs keyslot add -S 2 -o keyformat=raw \
    -o keylocation=file://$TESTDIR/kskey.2 $encroot
log_must zfs keyslot add -S 3 -o keyformat=raw \
    -o keylocation=file://$TESTDIR/kskey.3 $encroot
log_must eval "echo data > /$encroot/file"

obj=$(keyslot_key_obj $TESTPOOL)
log_must test -n "$obj"
fp=$(keyslot_obj_hash $TESTPOOL $obj)
log_must test "$(keyslot_key_objs $TESTPOOL | wc -l)" -eq 2

#
# 3. rename: the same object, unchanged, and the location stays local.
#
log_must zfs rename $encroot $renroot
log_must test "$(keyslot_key_obj $TESTPOOL)" = "$obj"
log_must test "$(keyslot_obj_hash $TESTPOOL $obj)" = "$fp"
log_must test "$(get_prop keylocation_2 $renroot)" = \
    "file://$TESTDIR/kskey.2"
log_must test "$(zfs get -H -o source keylocation_2 $renroot)" = "local"
log_must test "$(zfs keyslot list -H $renroot | wc -l)" -eq 3
verify_tree $renroot

#
# 4. rollback of a child: the file added after the snapshot is discarded and
#    the root's key object is untouched.
#
log_must zfs snapshot $renroot/child@s1
log_must zfs mount $renroot/child
log_must eval "echo after > /$renroot/child/after"
log_must zfs unmount $renroot/child
log_must zfs rollback $renroot/child@s1
log_must test "$(keyslot_obj_hash $TESTPOOL $obj)" = "$fp"

log_must zfs mount $renroot/child
log_mustnot test -e /$renroot/child/after
log_must zfs unmount $renroot/child
verify_tree $renroot

#
# 5. destroy -r of a child: only the child's key object goes away.
#
log_must zfs destroy -r $renroot/child
log_must test "$(keyslot_key_objs $TESTPOOL | wc -l)" -eq 1
log_must test "$(keyslot_obj_hash $TESTPOOL $obj)" = "$fp"
verify_tree $renroot

log_pass "rename, rollback and destroy -r keep a slotted root's key object"
