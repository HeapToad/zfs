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
# Every slot of an encryption root unlocks the same tree, and a slot given the
# wrong key is refused without installing anything.
#
# STRATEGY:
# 1. Create an encrypted root with slots 2 and 3, each with its own raw key,
#    and a file to read.
# 2. After unloading, unlock from slot 1, then slot 2, then slot 3, and read
#    the file through each.
# 3. Attempt every slot with the wrong raw key: 'load-key' fails, says the key
#    is incorrect, and leaves keystatus unavailable.
# 4. After each failed attempt the primary slot still unlocks the tree, so the
#    failure installed nothing and did not disturb the other slots.
# 5. A passphrase slot records its format as a format, not as a format with part
#    of the salt in the upper half, and unlocks the tree from that slot.
#

verify_runnable "both"

typeset encroot=$TESTPOOL/$TESTFS1/enc

function cleanup
{
	datasetexists $TESTPOOL/$TESTFS1 && \
	    keyslot_unmount_tree $TESTPOOL/$TESTFS1
	datasetexists $TESTPOOL/$TESTFS1 && \
	    destroy_dataset $TESTPOOL/$TESTFS1 -r
	rm -f $TESTDIR/kskey.[0-9] $TESTDIR/kskey.wrong "$TESTDIR/pass key"
}
log_onexit cleanup

log_assert "every slot unlocks the tree, and a wrong key installs nothing"

log_must zfs create $TESTPOOL/$TESTFS1
for i in 1 2 3; do
	log_must eval "head -c 32 /dev/urandom > $TESTDIR/kskey.$i"
done
log_must eval "head -c 32 /dev/urandom > $TESTDIR/kskey.wrong"

log_must zfs create -o encryption=on -o keyformat=raw \
    -o keylocation=file://$TESTDIR/kskey.1 $encroot
log_must eval "echo data > /$encroot/file"
log_must zfs keyslot add -S 2 -o keyformat=raw \
    -o keylocation=file://$TESTDIR/kskey.2 $encroot
log_must zfs keyslot add -S 3 -o keyformat=raw \
    -o keylocation=file://$TESTDIR/kskey.3 $encroot

#
# 2. Each slot unlocks the tree on its own.
#
for slot in 1 2 3; do
	keyslot_unlock $encroot $slot
	log_must zfs mount $encroot
	log_must grep -q data /$encroot/file
	log_must zfs unmount $encroot
done

#
# 3. and 4. The wrong key is refused, and nothing is installed.
#
for slot in 1 2 3; do
	keyslot_unmount_tree $encroot
	if key_available $encroot; then
		log_must zfs unload-key $encroot
	fi

	if [[ $slot == 1 ]]; then
		out=$(zfs load-key -L file://$TESTDIR/kskey.wrong \
		    $encroot 2>&1)
		rc=$?
	else
		out=$(zfs load-key -S $slot -L \
		    file://$TESTDIR/kskey.wrong $encroot 2>&1)
		rc=$?
	fi

	log_note "slot $slot: $out"
	log_must test $rc -ne 0
	log_must eval "echo \"$out\" | grep -q 'Incorrect key'"
	log_must key_unavailable $encroot

	log_must zfs load-key $encroot
	log_must key_available $encroot
	log_must zfs unload-key $encroot
done

#
# 5. A passphrase slot stores its keyformat as a keyformat: the 8-byte entry
#    must not carry part of the salt in its upper half. The location also
#    contains a space, which only a tab-separated listing can carry.
#
typeset passroot=$TESTPOOL/$TESTFS1/encpass
typeset passphrase="password1"
typeset kf salt loc

log_must eval "echo $passphrase > \"$TESTDIR/pass key\""
log_must zfs create -o encryption=on -o keyformat=passphrase \
    -o "keylocation=file://$TESTDIR/pass key" $passroot
log_must zfs keyslot add -S 2 -o keyformat=passphrase \
    -o "keylocation=file://$TESTDIR/pass key" $passroot

kf=$(zfs keyslot list -Hp $passroot | awk -F'\t' '$1 == 2 { print $2 }')
salt=$(zfs keyslot list -Hp $passroot | awk -F'\t' '$1 == 2 { print $3 }')
loc=$(zfs keyslot list -Hp $passroot | awk -F'\t' '$1 == 2 { print $5 }')
log_note "slot 2: keyformat=$kf salt=$salt location=$loc"
log_must test "$kf" = "3"
log_must test "$salt" -ne 0
log_must test "$loc" = "file://$TESTDIR/pass key"

log_must zfs unload-key $passroot
log_must zfs load-key -S 2 $passroot
log_must key_available $passroot

log_pass "every slot unlocks the tree, and a wrong key installs nothing"
