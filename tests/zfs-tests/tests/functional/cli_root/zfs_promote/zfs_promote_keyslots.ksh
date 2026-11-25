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
# Promoting a clone of a slotted encryption root keeps the slot entries and
# moves every slot location to the new root, so each slot still unlocks the
# tree afterwards.
#
# STRATEGY:
# 1. With slots 2 and 3 in place, promote a clone. The slot entries are
#    unchanged and the key object stays the same object; only the encryption
#    root object id, which promote legitimately rewrites, moves.
# 2. The locations move to the new root as local settings and the old root
#    keeps no layer at all.
# 3. The old root refuses 'keyslot list' and names the new root.
# 4. Every slot still unlocks the tree and the data reads.
# 5. The same holds for a location the root received, which is stored under
#    the $recvd suffix.
#

verify_runnable "both"

typeset encroot=$TESTPOOL/$TESTFS1/enc
typeset clone=$TESTPOOL/$TESTFS1/cl
typeset recroot=$TESTPOOL/$TESTFS1/rec
typeset recvroot=$TESTPOOL/recv
typeset recvclone=$TESTPOOL/recvcl

function cleanup
{
	datasetexists $TESTPOOL/$TESTFS1 && \
	    destroy_dataset $TESTPOOL/$TESTFS1 -r
	datasetexists $TESTPOOL/recv && destroy_dataset $TESTPOOL/recv -rf
	datasetexists $TESTPOOL/recvcl && destroy_dataset $TESTPOOL/recvcl -rf
	rm -f $TESTDIR/h1k[1-5]
}
log_onexit cleanup

#
# The encryption root's key object is the one carrying slot entries; a child's
# key object has none, so the presence of WRAP_2 identifies it.
#
function slot_key_obj
{
	typeset obj

	for obj in $(zdb -dddddd $TESTPOOL | grep -a 'crypto_key_obj' | \
	    sed 's/.*= //' | sort -u); do
		if zdb -dddddd $TESTPOOL $obj | grep -aq 'DSL_CRYPTO_WRAP_2'
		then
			echo $obj
			return 0
		fi
	done

	log_fail "no key object with slot entries in $TESTPOOL"
}

#
# Hash the key object entries whose zdb rendering is deterministic. A slot's
# WRAP, IV and MAC are printed as raw bytes whose tail differs between two
# dumps of the same unchanged object, so they are excluded here and proven
# intact by unlocking with the slot instead. ROOT_DDOBJ is excluded because
# promote rewrites it.
#
function slots_hash
{
	zdb -dddddd $TESTPOOL $1 | grep -a 'DSL_CRYPTO' | \
	    grep -avE 'DSL_CRYPTO_(ROOT_DDOBJ|WRAP_[0-9]|IV_[0-9]|MAC_[0-9])' | \
	    sort | md5sum | awk '{ print $1 }'
}

#
# Unmount every dataset in the pool except the test filesystem itself, which is
# mounted at $TESTDIR and holds the slot key files. Children first: after a
# promote the origin and its children are mounted members of the new root's
# encryption tree, so unmounting the root alone leaves the tree busy and
# unload-key fails with "'<root>' is busy". Plain parent names sort before
# their children, so a reverse sort visits the children first.
#
function unmount_pool
{
	typeset name

	for name in $(zfs list -H -o name -r $TESTPOOL | sort -r); do
		case "$name" in
		"$TESTPOOL"|"$TESTPOOL/$TESTFS")
			continue
			;;
		esac
		zfs unmount $name 2>/dev/null
	done
}

#
# Unlock the tree with the given slot. The tree is mounted before the promote
# and stays mounted, so unmounting it first is what makes the mount in the
# caller unconditional. The key still reads as loaded unless promote left the
# keystore keyed by the old root, so unload only then.
#
function unlock_with_slot
{
	typeset ds=$1 slot=$2

	unmount_pool
	if key_available $ds; then
		log_must zfs unload-key $ds
	fi

	log_must zfs load-key -S $slot $ds
	log_must key_available $ds
}

log_assert "promote of a slotted clone keeps the slots and moves the locations"

log_must zfs create $TESTPOOL/$TESTFS1
for i in 1 2 3 4 5; do
	log_must eval "head -c 32 /dev/urandom > $TESTDIR/h1k$i"
done

#
# 1. and 2. Slot entries survive, locations move to the new root as local and
# the origin keeps nothing.
#
log_must zfs create -o encryption=on -o keyformat=raw \
    -o keylocation=file://$TESTDIR/h1k1 $encroot
log_must zfs create $encroot/child
log_must zfs keyslot add -S 2 -o keyformat=raw \
    -o keylocation=file://$TESTDIR/h1k2 $encroot
log_must zfs keyslot add -S 3 -o keyformat=raw \
    -o keylocation=file://$TESTDIR/h1k3 $encroot
log_must eval "echo data > /$encroot/file"

obj_before=$(slot_key_obj)
log_must test -n "$obj_before"
log_must test -n "$(zdb -dddddd $TESTPOOL $obj_before | \
    grep -a 'DSL_CRYPTO' | head -1)"
hash_before=$(slots_hash $obj_before)

log_must zfs snapshot $encroot@s1
log_must zfs clone $encroot@s1 $clone
log_must verify_encryption_root $clone $encroot

log_must zfs promote $clone
log_must verify_encryption_root $encroot $clone

# the key object is the same object and its deterministic entries are
# unchanged
log_must test "$(slot_key_obj)" = "$obj_before"
log_must test "$(slots_hash $obj_before)" = "$hash_before"

log_must test "$(get_prop keylocation_2 $clone)" = "file://$TESTDIR/h1k2"
log_must test "$(get_prop keylocation_3 $clone)" = "file://$TESTDIR/h1k3"
log_must test "$(zfs get -H -o source keylocation_2 $clone)" = "local"
log_must test "$(zfs get -H -o source keylocation_3 $clone)" = "local"
# a surviving $recvd layer on the origin would show up as source received, so
# a '-' value proves that neither layer is left behind
log_must test "$(get_prop keylocation_2 $encroot)" = "-"
log_must test "$(get_prop keylocation_3 $encroot)" = "-"

#
# 3. The old root is no longer the root, and says so.
#
typeset out rc
out=$(zfs keyslot list $encroot 2>&1)
rc=$?
log_must test $rc -ne 0
log_must eval "echo \"$out\" | grep -q \"$clone\""

#
# 4. Every slot still unlocks the tree. keystatus right after the promote is
# recorded rather than assumed: PR #19943 is not in this base, so the tree can
# read unavailable until the key is loaded again. When a base carries #19943
# the reload below stops being needed and keystatus stays available.
#
log_note "keystatus on $clone after promote:" \
    "$(get_prop keystatus $clone)"
unlock_with_slot $clone 2
log_must zfs mount $clone
log_must grep -q data /$clone/file
unlock_with_slot $clone 3
log_must zfs mount $clone
log_must grep -q data /$clone/file

#
# 5. The same for a location the root received.
#
log_must zfs create -o encryption=on -o keyformat=raw \
    -o keylocation=file://$TESTDIR/h1k4 $recroot
log_must zfs keyslot add -S 2 -o keyformat=raw \
    -o keylocation=file://$TESTDIR/h1k5 $recroot
log_must zfs snapshot $recroot@s1
log_must eval "zfs send -w -p $recroot@s1 | zfs receive -u $recvroot"
log_must test "$(zfs get -H -o source keylocation_2 $recvroot)" = "received"

# The receive already created $recvroot@s1 from the stream, so the clone
# gets its own snapshot.
log_must zfs snapshot $recvroot@s2
log_must zfs clone $recvroot@s2 $recvclone
log_must zfs promote $recvclone
log_must test "$(zfs get -H -o source keylocation_2 $recvclone)" = "local"
log_must test "$(get_prop keylocation_2 $recvclone)" = \
    "file://$TESTDIR/h1k5"
log_must test "$(get_prop keylocation_2 $recvroot)" = "-"
log_must zfs load-key -S 2 $recvclone
log_must key_available $recvclone

log_pass "promote of a slotted clone keeps the slots and moves the locations"
