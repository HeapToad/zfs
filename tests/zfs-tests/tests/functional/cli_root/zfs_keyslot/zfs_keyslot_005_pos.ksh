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
# 'zfs keyslot rewrap' replaces one slot's secret in place. The old secret stops
# unlocking the tree, the new one unlocks it, and the slot number, the key
# format, the other slots and the encryption key itself do not change. A raw
# stream carries the rewrapped slot.
#
# STRATEGY:
# 1. Create an encrypted root with a child, slot 2 (passphrase, 200000
#    iterations) and slot 3 (hex, from a file), and write a file through each.
# 2. Fingerprint every key object in the pool and record slot 2's salt and
#    iteration count.
# 3. Rewrap slot 2 to a new passphrase, naming no properties: the slot list,
#    the key format and the set of key objects are unchanged, the salt is new,
#    and the iteration count becomes the default rather than the 200000 it held.
# 4. The old passphrase is refused and installs nothing; the new one unlocks
#    the root and the child; slot 1 still unlocks with its own key; and every
#    key object except the root's is byte-identical.
# 5. Rewrap slot 3 with no properties: its stored location becomes prompt and
#    its key material is the piped hex.
# 6. Refusals: a locked root, an absent slot, slot 1 and -o keyformat. The slot
#    still unlocks afterwards.
# 7. A raw send carries the rewrapped slot: the old secret is refused on the
#    copy, the new one unlocks it, and the copy's salt matches.
# 8. A user granted the keyslot permission can rewrap the slot.
#

verify_runnable "both"

typeset encroot=$TESTPOOL/$TESTFS1/enc
typeset recvroot=$TESTPOOL/$TESTFS1/recv
typeset oldpass=oldpassphrase
typeset newpass=newpassphrase
typeset delegpass=delegatedpass
typeset deleg_user=ksdeleg
typeset deleg_group=ksdeleg
# 64 hex digits: a hex slot's key material is text, so a pipe can carry it.
typeset hex1=aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899
typeset hex2=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef

function cleanup
{
	datasetexists $recvroot && destroy_dataset $recvroot -r
	datasetexists $TESTPOOL/$TESTFS1 && \
	    keyslot_unmount_tree $TESTPOOL/$TESTFS1
	datasetexists $TESTPOOL/$TESTFS1 && \
	    destroy_dataset $TESTPOOL/$TESTFS1 -r
	del_user $deleg_user
	del_group $deleg_group
	rm -f $TESTDIR/kskey.1 $TESTDIR/kskey.3 $TESTDIR/kspass
}
log_onexit cleanup

#
# One field of one slot's listing: $1 dataset, $2 slot, $3 column.
#
function slot_field
{
	zfs keyslot list -Hp $1 | awk -F'\t' -v s=$2 -v c=$3 \
	    '$1 == s { print $c }'
}

#
# Quiet the tree: unmount everything, then unload the key. unload-key refuses a
# mounted dataset, so this order is required.
#
function unload_all
{
	keyslot_unmount_tree $encroot
	if key_available $encroot; then
		log_must zfs unload-key $encroot
	fi
}

#
# Unlock the tree from slot $1 and read both files. When $2 is given it is the
# material, piped in; otherwise the slot's stored location supplies it.
#
function verify_tree
{
	typeset slot=$1 secret=$2

	unload_all
	if [[ -n $secret ]]; then
		log_must eval "echo '$secret' | zfs load-key -S $slot \
		    -L prompt $encroot"
	elif [[ $slot == 1 ]]; then
		log_must zfs load-key $encroot
	else
		log_must zfs load-key -S $slot $encroot
	fi
	log_must key_available $encroot
	log_must zfs mount $encroot
	log_must zfs mount $encroot/child
	log_must grep -q data /$encroot/file
	log_must grep -q childdata /$encroot/child/childfile
	log_must zfs unmount $encroot/child
	log_must zfs unmount $encroot
}

log_assert "rewrap replaces one slot's secret and leaves everything else alone"

log_must zfs create $TESTPOOL/$TESTFS1
log_must eval "head -c 32 /dev/urandom > $TESTDIR/kskey.1"
log_must eval "echo $hex2 > $TESTDIR/kskey.3"

log_must zfs create -o encryption=on -o keyformat=raw \
    -o keylocation=file://$TESTDIR/kskey.1 $encroot
log_must zfs create $encroot/child
log_must eval "echo data > /$encroot/file"
log_must eval "echo childdata > /$encroot/child/childfile"
log_must eval "echo '$oldpass' | zfs keyslot add -S 2 \
    -o keyformat=passphrase -o keylocation=prompt \
    -o pbkdf2iters=200000 $encroot"
log_must zfs keyslot add -S 3 -o keyformat=hex \
    -o keylocation=file://$TESTDIR/kskey.3 $encroot

typeset rootobj=$(keyslot_key_obj $TESTPOOL)
typeset objs_before=$(keyslot_key_objs $TESTPOOL)
typeset fp_before=$(keyslot_obj_snapshot $TESTPOOL)
typeset salt_before=$(slot_field $encroot 2 3)
typeset iters_before=$(slot_field $encroot 2 4)
log_must test "$iters_before" = "200000"

#
# 3. The rewrap itself.
#
log_must eval "echo '$newpass' | zfs keyslot rewrap -S 2 $encroot"

log_must test "$(keyslot_slots $encroot)" = "1,2,3"
log_must test "$(slot_field $encroot 2 2)" = "3"
log_must test "$(slot_field $encroot 2 5)" = "prompt"
log_must test "$(slot_field $encroot 2 3)" != "$salt_before"
log_must test "$(slot_field $encroot 2 4)" != "$iters_before"

#
# The count it now holds is the default, not the slot's previous value: a fresh
# slot created with no -o records the same count.
#
log_must eval "echo 'calibrationpass' | zfs keyslot add -S 4 \
    -o keyformat=passphrase -o keylocation=prompt $encroot"
log_must test "$(slot_field $encroot 2 4)" = "$(slot_field $encroot 4 4)"
log_must zfs keyslot remove -S 4 $encroot

# the same key objects, and the root's is still the one carrying the slots
log_must test "$(keyslot_key_objs $TESTPOOL)" = "$objs_before"
log_must test "$(keyslot_key_obj $TESTPOOL)" = "$rootobj"

# every other key object is byte-identical
for obj in $objs_before; do
	[[ $obj == $rootobj ]] && continue
	log_must test "$(keyslot_obj_hash $TESTPOOL $obj)" = \
	    "$(echo "$fp_before" | awk -v o=$obj '$1 == o { print $2 }')"
done

#
# 4. The old secret is gone; the new one unlocks the tree.
#
unload_all
out=$(echo "$oldpass" | zfs load-key -S 2 -L prompt $encroot 2>&1)
rc=$?
log_note "old secret: $out"
log_must test $rc -ne 0
log_must eval "echo \"$out\" | grep -q 'Incorrect key'"
log_must key_unavailable $encroot

verify_tree 2 "$newpass"
verify_tree 1

#
# 5. A rewrap that names no location stores prompt and takes the piped secret.
#
log_must eval "echo '$hex1' | zfs keyslot rewrap -S 3 $encroot"
log_must test "$(slot_field $encroot 3 5)" = "prompt"
verify_tree 3 "$hex1"

#
# 6. Refusals, and the slot is still usable afterwards.
#
unload_all
keyslot_mustfail 'key must be loaded' zfs keyslot rewrap -S 2 $encroot
verify_tree 2 "$newpass"

keyslot_mustfail 'key slot 9 does not exist' zfs keyslot rewrap -S 9 $encroot
keyslot_mustfail 'primary slot' zfs keyslot rewrap -S 1 $encroot
keyslot_mustfail 'keyformat is fixed' zfs keyslot rewrap -S 2 \
    -o keyformat=raw $encroot
verify_tree 2 "$newpass"

#
# 7. A raw send carries the rewrapped slot.
#
log_must zfs snapshot $encroot@snap
log_must eval "zfs send -w $encroot@snap | zfs receive $recvroot"

out=$(echo "$oldpass" | zfs load-key -S 2 -L prompt $recvroot 2>&1)
rc=$?
log_note "old secret on the copy: $out"
log_must test $rc -ne 0
log_must eval "echo \"$out\" | grep -q 'Incorrect key'"
log_must eval "echo '$newpass' | zfs load-key -S 2 -L prompt $recvroot"
log_must key_available $recvroot
log_must test "$(slot_field $recvroot 2 3)" = "$(slot_field $encroot 2 3)"

#
# 8. A user granted the keyslot permission can rewrap the slot.
#
verify_tree 2 "$newpass"
log_must eval "echo '$delegpass' > $TESTDIR/kspass"
log_must add_group $deleg_group
log_must add_user $deleg_group $deleg_user
log_must zfs allow $deleg_user keyslot $encroot
log_must user_run $deleg_user zfs keyslot rewrap -S 2 \
    -o keylocation=file://$TESTDIR/kspass $encroot
log_must zfs unallow $deleg_user keyslot $encroot
log_must test "$(slot_field $encroot 2 5)" = "file://$TESTDIR/kspass"
log_must test "$(slot_field $encroot 2 3)" != "$salt_before"
verify_tree 2 "$delegpass"

log_pass "rewrap replaces one slot's secret and leaves everything else alone"
