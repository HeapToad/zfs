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
# 'zfs change-key' refuses to replace the primary key while the encryption
# root holds extra key slots, and refuses before it reads the old key.
#
# STRATEGY:
# 1. An encryption root with no extra slots can change its key.
# 2. With a slot added, change-key fails and names the reason; the extra slot
#    and the primary key still work afterwards.
# 3. 'change-key -i' is refused the same way.
# 4. A locked slotted root is refused by 'change-key -l' before the old key is
#    read, so nothing is consumed from stdin.
# 5. A non-root child of a slotted root can still detach.
# 6. Removing the extra slot makes both change-key forms work again.
#

verify_runnable "both"

typeset encroot=$TESTPOOL/$TESTFS1/enc
typeset detach=$encroot/detach
typeset parent=$TESTPOOL/$TESTFS1/parent
typeset child=$parent/child
typeset promptroot=$TESTPOOL/$TESTFS1/prompt

function cleanup
{
	datasetexists $TESTPOOL/$TESTFS1 && \
	    destroy_dataset $TESTPOOL/$TESTFS1 -r
	rm -f $TESTDIR/ckey.[1-9] $TESTDIR/ckstdin
}
log_onexit cleanup

# Write a 32-byte raw key; a trailing newline would make it 33 bytes.
function write_key
{
	log_must eval "printf '%s' $2 > $1"
}

function change_key_refused
{
	typeset out rc

	out=$("$@" 2>&1)
	rc=$?

	log_note "output: $out"
	log_must test $rc -ne 0
	log_must eval "echo \"$out\" | grep -q 'extra key slot'"
	log_must eval "echo \"$out\" | grep -q 'keyslot remove'"
}

log_assert "'zfs change-key' is refused while extra key slots exist"

log_must zfs create $TESTPOOL/$TESTFS1
write_key $TESTDIR/ckey.1 $RAWKEY
write_key $TESTDIR/ckey.2 $RAWKEY1
write_key $TESTDIR/ckey.3 $RAWKEY1
write_key $TESTDIR/ckey.4 $RAWKEY
write_key $TESTDIR/ckey.5 $RAWKEY
write_key $TESTDIR/ckey.6 $RAWKEY1
write_key $TESTDIR/ckey.7 $RAWKEY
write_key $TESTDIR/ckey.8 $RAWKEY
write_key $TESTDIR/ckey.9 $RAWKEY1

#
# 1. Control: a root with no extra slots can change its key.
#
log_must zfs create -o encryption=on -o keyformat=raw \
    -o keylocation=file://$TESTDIR/ckey.1 $encroot
log_must key_available $encroot
log_must zfs change-key -o keylocation=file://$TESTDIR/ckey.2 $encroot
log_must verify_keylocation $encroot file://$TESTDIR/ckey.2

#
# 2. One extra slot refuses the change, and leaves both slots usable.
#
log_must zfs keyslot add -S 2 -o keyformat=raw \
    -o keylocation=file://$TESTDIR/ckey.3 $encroot
change_key_refused zfs change-key -o keylocation=file://$TESTDIR/ckey.4 \
    $encroot
log_must test "$(get_prop keylocation_2 $encroot)" = \
    "file://$TESTDIR/ckey.3"
log_must zfs unmount $encroot
log_must zfs unload-key $encroot
log_must zfs load-key -S 2 $encroot
log_must key_available $encroot
log_must zfs unload-key $encroot
log_must zfs load-key $encroot
log_must key_available $encroot

#
# 3. The inherit form is refused the same way, and the child stays its own
#    encryption root.
#
log_must zfs create -o encryption=on -o keyformat=raw \
    -o keylocation=file://$TESTDIR/ckey.5 $parent
log_must zfs create -o encryption=on -o keyformat=raw \
    -o keylocation=file://$TESTDIR/ckey.6 $child
log_must zfs keyslot add -S 2 -o keyformat=raw \
    -o keylocation=file://$TESTDIR/ckey.7 $child
change_key_refused zfs change-key -i $child
log_must verify_encryption_root $child $child

#
# 4. The refusal comes before the old key is read: the first line of the
#    supplied stdin is still there to be read afterwards.
#
log_must eval "printf '%s\nMARKER\n' $PASSPHRASE > $TESTDIR/ckstdin"
log_must eval "printf '%s\n%s\n' $PASSPHRASE $PASSPHRASE | zfs create" \
    "-o encryption=on -o keyformat=passphrase -o keylocation=prompt" \
    "$promptroot"
log_must zfs keyslot add -S 2 -o keyformat=raw \
    -o keylocation=file://$TESTDIR/ckey.4 $promptroot
log_must zfs unmount $promptroot
log_must zfs unload-key $promptroot
log_must key_unavailable $promptroot

exec 3< $TESTDIR/ckstdin
log_mustnot zfs change-key -l $promptroot <&3
read -r line <&3
exec 3<&-
log_must test "$line" = "$PASSPHRASE"
log_must key_unavailable $promptroot

#
# 5. A non-root child can still detach while the root holds extra slots.
#    A detach with an explicit keylocation also needs its keyformat; the CLI
#    refuses a new root whose keylocation is set but whose keyformat is not.
#
log_must zfs create $detach
log_must zfs change-key -o keyformat=raw -o keylocation=file://$TESTDIR/ckey.8 \
    $detach
log_must verify_encryption_root $detach $detach
log_must test "$(get_prop keylocation_2 $encroot)" = \
    "file://$TESTDIR/ckey.3"

#
# 6. Removing the extra slot makes both forms work again, and the key that the
#    change installed really unlocks the tree.
#
# Case 2 left $encroot unmounted, so mount it again: the file below has to be
# written through the dataset, not into the bare mountpoint directory. The
# detached child is still mounted under $encroot's mountpoint, so it is
# unmounted first or unmounting $encroot later fails on its stale path.
#
log_must zfs unmount $detach
log_must zfs mount $encroot
log_must eval "echo test > /$TESTPOOL/$TESTFS1/enc/file"
log_must zfs keyslot remove -S 2 $encroot
log_must zfs change-key -o keylocation=file://$TESTDIR/ckey.9 $encroot
log_must zfs unmount $encroot
log_must zfs unload-key $encroot
log_must zfs load-key $encroot
log_must key_available $encroot
log_must zfs mount $encroot
log_must grep -q test /$TESTPOOL/$TESTFS1/enc/file

log_must zfs keyslot remove -S 2 $child
log_must zfs change-key -i $child
log_must verify_encryption_root $child $parent

log_pass "'zfs change-key' is refused while extra key slots exist"
