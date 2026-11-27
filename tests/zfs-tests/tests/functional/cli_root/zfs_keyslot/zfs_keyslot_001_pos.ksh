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
# 'zfs keyslot add', 'list' and 'remove' manage the alternate wrappings of an
# encryption root's wrapping key.
#
# STRATEGY:
# 1. Create an encrypted root with a child, and snapshot every key object.
# 2. 'add' without -S takes slot 2, 'add -S 4' takes slot 4, and a second
#    automatic add fills the lowest free slot, 3.
# 3. Each added slot has its six entries, and no other key object changed.
# 4. 'list' shows the slots with and without a header, with parsable output,
#    and as JSON.
# 5. 'add -S 1', 'add -S 0' and a taken slot are refused, and so is removing
#    slot 1 or a slot that does not exist.
# 6. A locked root refuses both add and remove and names the reason, while
#    list still works.
# 7. 'remove' drops the slot's entries and its stored location, and the next
#    automatic add reuses that slot.
#

verify_runnable "both"

typeset encroot=$TESTPOOL/$TESTFS1/enc
typeset child=$encroot/child
typeset before=$TESTDIR/ksobj.before
typeset after=$TESTDIR/ksobj.after

function cleanup
{
	datasetexists $TESTPOOL/$TESTFS1 && \
	    keyslot_unmount_tree $TESTPOOL/$TESTFS1
	datasetexists $TESTPOOL/$TESTFS1 && \
	    destroy_dataset $TESTPOOL/$TESTFS1 -r
	rm -f $TESTDIR/kskey.[0-9] $TESTDIR/kskey.wrong $before $after \
	    $TESTDIR/ksobj.before.other $TESTDIR/ksobj.after.other
}
log_onexit cleanup

function write_key
{
	log_must eval "printf '%s' $2 > $1"
}

#
# Every entry that slot $1 writes into the encryption root's key object, and
# no seventh entry for that slot.
#
function verify_slot_entries
{
	typeset slot=$1
	typeset obj name count

	obj=$(keyslot_key_obj $TESTPOOL)
	log_must test -n "$obj"

	for name in WRAP IV MAC KEYFORMAT PBKDF2SALT PBKDF2ITERS; do
		log_must eval "zdb -dddddd $TESTPOOL $obj | grep -aq " \
		    "'DSL_CRYPTO_${name}_${slot} ='"
	done

	count=$(zdb -dddddd $TESTPOOL $obj | \
	    grep -acE "DSL_CRYPTO_[A-Z0-9_]+_${slot} =")
	log_must test "$count" -eq 6
}

function verify_slot_entries_gone
{
	typeset slot=$1
	typeset obj

	obj=$(keyslot_key_obj $TESTPOOL)
	log_must test -n "$obj"

	log_mustnot eval "zdb -dddddd $TESTPOOL $obj | grep -aq " \
	    "'DSL_CRYPTO_WRAP_${slot} ='"
}

log_assert "zfs keyslot add/list/remove manage the slots of an encryption root"

log_must zfs create $TESTPOOL/$TESTFS1
write_key $TESTDIR/kskey.1 $RAWKEY
write_key $TESTDIR/kskey.2 $RAWKEY1
write_key $TESTDIR/kskey.3 $RAWKEY
write_key $TESTDIR/kskey.4 $RAWKEY1

log_must zfs create -o encryption=on -o keyformat=raw \
    -o keylocation=file://$TESTDIR/kskey.1 $encroot
log_must zfs create $child
log_must key_available $encroot
log_must test "$(keyslot_slots $encroot)" = "1"

keyslot_obj_snapshot $TESTPOOL > $before

#
# 2. Allocation: the lowest free slot each time.
#
out=$(zfs keyslot add -o keyformat=raw \
    -o keylocation=file://$TESTDIR/kskey.2 $encroot 2>&1)
log_must eval "echo \"$out\" | grep -q 'added key slot 2'"
log_must zfs keyslot add -S 4 -o keyformat=raw \
    -o keylocation=file://$TESTDIR/kskey.3 $encroot
out=$(zfs keyslot add -o keyformat=raw \
    -o keylocation=file://$TESTDIR/kskey.4 $encroot 2>&1)
log_must eval "echo \"$out\" | grep -q 'added key slot 3'"
log_must test "$(keyslot_slots $encroot)" = "1,2,3,4"

#
# 3. Each slot's entries, and only the root's key object changed.
#
verify_slot_entries 2
verify_slot_entries 3
verify_slot_entries 4

keyslot_obj_snapshot $TESTPOOL > $after
log_must test "$(wc -l < $before)" -eq "$(wc -l < $after)"

obj=$(keyslot_key_obj $TESTPOOL)
log_must test "$(grep "^$obj " $before)" != "$(grep "^$obj " $after)"

# every other key object (the child's) has the same fingerprint
grep -v "^$obj " $before > $TESTDIR/ksobj.before.other
grep -v "^$obj " $after > $TESTDIR/ksobj.after.other
log_must diff $TESTDIR/ksobj.before.other $TESTDIR/ksobj.after.other

#
# 4. list: text, parsable, JSON.
#
log_must test "$(zfs keyslot list -H $encroot | wc -l)" -eq 4
log_must test "$(zfs keyslot list -H -p $encroot | \
    awk '$1 == 2 { print $2 }')" = "1"
# -H is scripting mode: exactly five tab-separated columns per row.
log_must test "$(zfs keyslot list -H -p $encroot | \
    awk -F'\t' 'NF != 5' | wc -l)" -eq 0
log_must eval "zfs keyslot list -j $encroot | grep -q 'keyslots'"
log_must eval "zfs keyslot list -j $encroot | grep -q '\"4\":'"

#
# 5. Refusals.
#
keyslot_mustfail 'primary slot' zfs keyslot add -S 1 -o keyformat=raw \
    -o keylocation=file://$TESTDIR/kskey.2 $encroot
keyslot_mustfail 'already in use' zfs keyslot add -S 2 -o keyformat=raw \
    -o keylocation=file://$TESTDIR/kskey.2 $encroot
log_mustnot zfs keyslot add -S 0 -o keyformat=raw \
    -o keylocation=file://$TESTDIR/kskey.2 $encroot
keyslot_mustfail 'primary slot' zfs keyslot remove -S 1 $encroot
keyslot_mustfail 'does not exist' zfs keyslot remove -S 9 $encroot

#
# 6. A locked root refuses both verbs, and list still works.
#
keyslot_unmount_tree $encroot
log_must zfs unload-key $encroot
log_must key_unavailable $encroot

keyslot_mustfail 'key must be loaded' zfs keyslot add -S 9 -o keyformat=raw \
    -o keylocation=file://$TESTDIR/kskey.2 $encroot
keyslot_mustfail 'key must be loaded' zfs keyslot remove -S 2 $encroot
log_must test "$(keyslot_slots $encroot)" = "1,2,3,4"

log_must zfs load-key $encroot
log_must key_available $encroot

#
# 7. remove drops, and the slot is reused.
#
log_must zfs keyslot remove -S 2 $encroot
verify_slot_entries_gone 2
log_must test "$(get_prop keylocation_2 $encroot)" = "-"
log_must test "$(keyslot_slots $encroot)" = "1,3,4"

keyslot_unmount_tree $encroot
log_must zfs unload-key $encroot
keyslot_mustfail 'does not exist' zfs load-key -S 2 $encroot
log_must zfs load-key -S 3 $encroot
log_must key_available $encroot

out=$(zfs keyslot add -o keyformat=raw \
    -o keylocation=file://$TESTDIR/kskey.2 $encroot 2>&1)
log_must eval "echo \"$out\" | grep -q 'added key slot 2'"
log_must test "$(keyslot_slots $encroot)" = "1,2,3,4"

log_pass "zfs keyslot add/list/remove manage the slots of an encryption root"
