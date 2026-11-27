// SPDX-License-Identifier: BSD-3-Clause
/*
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of the <organization> nor the
 *       names of its contributors may be used to endorse or promote products
 *       derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL <COPYRIGHT HOLDER> BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * Copyright (c) 2020, Felix Dörre
 * All rights reserved.
 */

#include <sys/dsl_crypt.h>
#include <sys/byteorder.h>
#include <libzfs.h>

#include <syslog.h>

#include <sys/zio_crypt.h>
#include <openssl/evp.h>

#define	PAM_SM_AUTH
#define	PAM_SM_PASSWORD
#define	PAM_SM_SESSION
#include <security/pam_modules.h>

#if	defined(__linux__)
#include <security/pam_ext.h>
#define	MAP_FLAGS MAP_PRIVATE | MAP_ANONYMOUS
#elif	defined(__FreeBSD__)
#include <security/pam_appl.h>
static void
pam_syslog(pam_handle_t *pamh, int loglevel, const char *fmt, ...)
{
	(void) pamh;
	va_list args;
	va_start(args, fmt);
	vsyslog(loglevel, fmt, args);
	va_end(args);
}
#define	MAP_FLAGS MAP_PRIVATE | MAP_ANON | MAP_NOCORE
#endif

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <sys/wait.h>
#include <pwd.h>
#include <lib/libzfs/libzfs_impl.h>

#include <sys/mman.h>

static const char PASSWORD_VAR_NAME[] = "pam_zfs_key_authtok";
static const char OLD_PASSWORD_VAR_NAME[] = "pam_zfs_key_oldauthtok";

static libzfs_handle_t *g_zfs;

static void destroy_pw(pam_handle_t *pamh, void *data, int errcode);

typedef int (*mlock_func_t) (const void *, size_t);

typedef struct {
	size_t len;
	char *value;
} pw_password_t;

/*
 * Try to mlock(2) or munlock(2) addr while handling EAGAIN by retrying ten
 * times and sleeping 10 milliseconds in between for a total of 0.1
 * seconds. lock_func must point to either mlock(2) or munlock(2).
 */
static int
try_lock(mlock_func_t lock_func, const void *addr, size_t len)
{
	int err;
	int retries = 10;
	useconds_t sleep_dur = 10 * 1000;

	if ((err = (*lock_func)(addr, len)) != EAGAIN) {
		return (err);
	}
	for (int i = retries; i > 0; --i) {
		(void) usleep(sleep_dur);
		if ((err = (*lock_func)(addr, len)) != EAGAIN) {
			break;
		}
	}
	return (err);
}


static pw_password_t *
alloc_pw_size(size_t len)
{
	pw_password_t *pw = malloc(sizeof (pw_password_t));
	if (!pw) {
		return (NULL);
	}
	pw->len = len;
	/*
	 * We use mmap(2) rather than malloc(3) since later on we mlock(2) the
	 * memory region. Since mlock(2) and munlock(2) operate on whole memory
	 * pages we should allocate a whole page here as mmap(2) does. Further
	 * this ensures that the addresses passed to mlock(2) an munlock(2) are
	 * on a page boundary as suggested by FreeBSD and required by some
	 * other implementations. Finally we avoid inadvertently munlocking
	 * memory mlocked by an concurrently running instance of us.
	 */
	pw->value = mmap(NULL, pw->len, PROT_READ | PROT_WRITE, MAP_FLAGS,
	    -1, 0);

	if (pw->value == MAP_FAILED) {
		free(pw);
		return (NULL);
	}
	if (try_lock(mlock, pw->value, pw->len) != 0) {
		(void) munmap(pw->value, pw->len);
		free(pw);
		return (NULL);
	}
	return (pw);
}

static pw_password_t *
alloc_pw_string(const char *source)
{
	size_t len = strlen(source) + 1;
	pw_password_t *pw = alloc_pw_size(len);

	if (!pw) {
		return (NULL);
	}
	memcpy(pw->value, source, pw->len);
	return (pw);
}

static void
pw_free(pw_password_t *pw)
{
	memset(pw->value, 0, pw->len);
	if (try_lock(munlock, pw->value, pw->len) == 0) {
		(void) munmap(pw->value, pw->len);
	}
	free(pw);
}

static pw_password_t *
pw_fetch(pam_handle_t *pamh, int tok)
{
	const char *token;
	if (pam_get_authtok(pamh, tok, &token, NULL) != PAM_SUCCESS) {
		pam_syslog(pamh, LOG_ERR,
		    "couldn't get password from PAM stack");
		return (NULL);
	}
	if (!token) {
		pam_syslog(pamh, LOG_ERR,
		    "token from PAM stack is null");
		return (NULL);
	}
	return (alloc_pw_string(token));
}

static const pw_password_t *
pw_fetch_lazy(pam_handle_t *pamh, int tok, const char *var_name)
{
	pw_password_t *pw = pw_fetch(pamh, tok);
	if (pw == NULL) {
		return (NULL);
	}
	int ret = pam_set_data(pamh, var_name, pw, destroy_pw);
	if (ret != PAM_SUCCESS) {
		pw_free(pw);
		pam_syslog(pamh, LOG_ERR, "pam_set_data failed");
		return (NULL);
	}
	return (pw);
}

static const pw_password_t *
pw_get(pam_handle_t *pamh, int tok, const char *var_name)
{
	const pw_password_t *authtok = NULL;
	int ret = pam_get_data(pamh, var_name,
	    (const void**)(&authtok));
	if (ret == PAM_SUCCESS)
		return (authtok);
	if (ret == PAM_NO_MODULE_DATA)
		return (pw_fetch_lazy(pamh, tok, var_name));
	pam_syslog(pamh, LOG_ERR, "password not available");
	return (NULL);
}

static int
pw_clear(pam_handle_t *pamh, const char *var_name)
{
	int ret = pam_set_data(pamh, var_name, NULL, NULL);
	if (ret != PAM_SUCCESS) {
		pam_syslog(pamh, LOG_ERR, "clearing password failed");
		return (-1);
	}
	return (0);
}

static void
destroy_pw(pam_handle_t *pamh, void *data, int errcode)
{
	(void) pamh, (void) errcode;

	if (data != NULL) {
		pw_free((pw_password_t *)data);
	}
}

static int
pam_zfs_init(pam_handle_t *pamh)
{
	int error = 0;
	if ((g_zfs = libzfs_init()) == NULL) {
		error = errno;
		pam_syslog(pamh, LOG_ERR, "Zfs initialization error: %s",
		    libzfs_error_init(error));
	}
	return (error);
}

static void
pam_zfs_free(void)
{
	libzfs_fini(g_zfs);
}

static pw_password_t *
derive_passphrase(pam_handle_t *pamh, const char *passphrase, uint64_t salt,
    uint64_t iters)
{
	pw_password_t *key = alloc_pw_size(WRAPPING_KEY_LEN);
	if (!key) {
		return (NULL);
	}

	salt = LE_64(salt);
	if (!PKCS5_PBKDF2_HMAC_SHA1((char *)passphrase,
	    strlen(passphrase), (uint8_t *)&salt,
	    sizeof (uint64_t), iters, WRAPPING_KEY_LEN,
	    (uint8_t *)key->value)) {
		pam_syslog(pamh, LOG_ERR, "pbkdf failed");
		pw_free(key);
		return (NULL);
	}
	return (key);
}

/*
 * Derive a wrapping key from a passphrase. With an nvlist, a fresh salt is
 * generated and, together with the caller's iteration count, added to it; the
 * count is DEFAULT_PBKDF2_ITERATIONS for a new or rekeyed slot and the slot's
 * current count for a rewrap that preserves it. Without an nvlist, the
 * dataset's own properties are used: slot 1's salt and iterations.
 */
static pw_password_t *
prepare_passphrase(pam_handle_t *pamh, zfs_handle_t *ds,
    const char *passphrase, nvlist_t *nvlist, uint64_t iters)
{
	uint64_t salt;

	if (nvlist == NULL) {
		salt = zfs_prop_get_int(ds, ZFS_PROP_PBKDF2_SALT);
		iters = zfs_prop_get_int(ds, ZFS_PROP_PBKDF2_ITERS);
		return (derive_passphrase(pamh, passphrase, salt, iters));
	}

	int fd = open("/dev/urandom", O_RDONLY);
	if (fd < 0) {
		return (NULL);
	}
	int bytes_read = 0;
	char *buf = (char *)&salt;
	size_t bytes = sizeof (uint64_t);
	while (bytes_read < bytes) {
		ssize_t len = read(fd, buf + bytes_read, bytes
		    - bytes_read);
		if (len < 0) {
			close(fd);
			return (NULL);
		}
		bytes_read += len;
	}
	close(fd);

	if (nvlist_add_uint64(nvlist,
	    zfs_prop_to_name(ZFS_PROP_PBKDF2_SALT), salt)) {
		pam_syslog(pamh, LOG_ERR,
		    "failed to add salt to nvlist");
		return (NULL);
	}
	if (nvlist_add_uint64(nvlist, zfs_prop_to_name(
	    ZFS_PROP_PBKDF2_ITERS), iters)) {
		pam_syslog(pamh, LOG_ERR,
		    "failed to add iters to nvlist");
		return (NULL);
	}

	return (derive_passphrase(pamh, passphrase, salt, iters));
}

typedef struct {
	uint64_t slot;
	uint64_t salt;
	uint64_t iters;
} passphrase_slot_t;

static int
slot_compare(const void *a, const void *b)
{
	const passphrase_slot_t *sa = a;
	const passphrase_slot_t *sb = b;

	if (sa->slot < sb->slot)
		return (-1);
	if (sa->slot > sb->slot)
		return (1);
	return (0);
}

/*
 * Collect the passphrase key slots of an encryption root, ascending, from the
 * slot-list channel. Slot 1 is not in the channel; callers reach it through the
 * dataset's properties. Slots whose parameters cannot be read are absent from
 * the channel and are skipped. When any_extra is given it reports whether the
 * root has slots beyond the primary one at all, whatever their format, which
 * is the condition change-key refuses on.
 *
 * On success *slots_out is either NULL with *count_out 0, or a malloc'd array
 * the caller frees.
 */
static int
get_passphrase_slots(pam_handle_t *pamh, zfs_handle_t *ds,
    passphrase_slot_t **slots_out, size_t *count_out, boolean_t *any_extra)
{
	nvlist_t *slots = NULL, *slotnvl;
	nvpair_t *pair = NULL;
	passphrase_slot_t *list = NULL, *grown;
	size_t count = 0;
	int ret;

	*slots_out = NULL;
	*count_out = 0;
	if (any_extra != NULL)
		*any_extra = B_FALSE;

	ret = zfs_crypto_get_keyslots(ds, &slots);
	if (ret != 0) {
		pam_syslog(pamh, LOG_ERR, "failed to list key slots for %s: %d",
		    zfs_get_name(ds), ret);
		return (ret);
	}

	while ((pair = nvlist_next_nvpair(slots, pair)) != NULL) {
		uint64_t slot, keyformat, salt, iters;

		slot = strtoull(nvpair_name(pair), NULL, 10);
		if (slot < 2)
			continue;
		if (any_extra != NULL)
			*any_extra = B_TRUE;
		if (nvpair_value_nvlist(pair, &slotnvl) != 0)
			continue;
		if (nvlist_lookup_uint64(slotnvl, "keyformat",
		    &keyformat) != 0 ||
		    keyformat != ZFS_KEYFORMAT_PASSPHRASE)
			continue;
		if (nvlist_lookup_uint64(slotnvl, "pbkdf2salt", &salt) != 0 ||
		    nvlist_lookup_uint64(slotnvl, "pbkdf2iters", &iters) != 0)
			continue;

		grown = realloc(list, (count + 1) * sizeof (*list));
		if (grown == NULL) {
			free(list);
			nvlist_free(slots);
			pam_syslog(pamh, LOG_ERR,
			    "out of memory listing key slots");
			return (ENOMEM);
		}
		list = grown;
		list[count].slot = slot;
		list[count].salt = salt;
		list[count].iters = iters;
		count++;
	}

	nvlist_free(slots);

	if (count > 1)
		qsort(list, count, sizeof (*list), slot_compare);

	*slots_out = list;
	*count_out = count;
	return (0);
}

static int
is_key_loaded(pam_handle_t *pamh, const char *ds_name)
{
	zfs_handle_t *ds = zfs_open(g_zfs, ds_name, ZFS_TYPE_FILESYSTEM);
	if (ds == NULL) {
		pam_syslog(pamh, LOG_ERR, "dataset %s not found", ds_name);
		return (-1);
	}
	int keystatus = zfs_prop_get_int(ds, ZFS_PROP_KEYSTATUS);
	zfs_close(ds);
	return (keystatus != ZFS_KEYSTATUS_UNAVAILABLE);
}

/*
 * Derive the new wrapping key for a passphrase with a fresh salt and the given
 * iteration count, and add the properties a new or rewrapped passphrase slot
 * needs. The count is the default for a rekeyed primary slot and the matched
 * slot's current count for a rewrap, so a password change keeps the slot's
 * work factor.
 */
static pw_password_t *
prepare_new_key(pam_handle_t *pamh, zfs_handle_t *ds, const char *passphrase,
    nvlist_t *nvlist, uint64_t iters)
{
	pw_password_t *key = prepare_passphrase(pamh, ds, passphrase, nvlist,
	    iters);
	if (key == NULL)
		return (NULL);

	if (nvlist_add_string(nvlist,
	    zfs_prop_to_name(ZFS_PROP_KEYLOCATION), "prompt") != 0 ||
	    nvlist_add_uint64(nvlist, zfs_prop_to_name(ZFS_PROP_KEYFORMAT),
	    ZFS_KEYFORMAT_PASSPHRASE) != 0) {
		pam_syslog(pamh, LOG_ERR, "failed to add key slot properties");
		pw_free(key);
		return (NULL);
	}
	return (key);
}

/*
 * Identify the slot the old password unlocks, changing nothing: with the noop
 * flag the kernel unwraps and verifies, then returns before installing. A
 * real load would only return EEXIST, because at password-change time the home
 * is already unlocked. Slot 1 is tested through the dataset's properties, the
 * alternate slots through their own, ascending. Returns 0 with *slot 0 when
 * nothing matches; *iters_out carries the matched alternate slot's iteration
 * count (0 when the primary slot matched or nothing did).
 */
static int
find_key_slot(pam_handle_t *pamh, zfs_handle_t *ds, const char *passphrase,
    uint64_t *slot, boolean_t *has_extra, uint64_t *iters_out)
{
	const char *ds_name = zfs_get_name(ds);
	passphrase_slot_t *slots = NULL;
	size_t nslots = 0, i;
	pw_password_t *key;
	int ret;

	*slot = 0;
	*iters_out = 0;

	/*
	 * Reading the key format loads the handle's properties, which the
	 * slot-list channel requires before it can be read.
	 */
	uint64_t keyformat = zfs_prop_get_int(ds, ZFS_PROP_KEYFORMAT);

	ret = get_passphrase_slots(pamh, ds, &slots, &nslots, has_extra);
	if (ret != 0)
		return (ret);

	/* the primary slot wins, and change-key's own path rekeys it */
	if (keyformat == ZFS_KEYFORMAT_PASSPHRASE) {
		key = prepare_passphrase(pamh, ds, passphrase, NULL, 0);
		if (key == NULL) {
			free(slots);
			return (EIO);
		}
		if (lzc_load_key(ds_name, B_TRUE, (uint8_t *)key->value,
		    WRAPPING_KEY_LEN) == 0)
			*slot = DSL_CRYPTO_KEY_SLOT_PRIMARY;
		pw_free(key);
		if (*slot != 0) {
			free(slots);
			return (0);
		}
	}

	for (i = 0; i < nslots; i++) {
		key = derive_passphrase(pamh, passphrase, slots[i].salt,
		    slots[i].iters);
		if (key == NULL)
			continue;
		ret = lzc_load_key_slot(ds_name, B_TRUE,
		    (uint8_t *)key->value, WRAPPING_KEY_LEN, slots[i].slot);
		pw_free(key);
		if (ret == 0) {
			*slot = slots[i].slot;
			*iters_out = slots[i].iters;
			break;
		}
	}

	free(slots);
	return (0);
}

/* Today's password change: rekey slot 1 with lzc_change_key(). */
static int
rekey_primary(pam_handle_t *pamh, zfs_handle_t *ds, const char *passphrase)
{
	const char *ds_name = zfs_get_name(ds);
	nvlist_t *nvlist = fnvlist_alloc();
	pw_password_t *key = prepare_new_key(pamh, ds, passphrase, nvlist,
	    DEFAULT_PBKDF2_ITERATIONS);
	if (key == NULL) {
		nvlist_free(nvlist);
		return (EIO);
	}
	int ret = lzc_change_key(ds_name, DCP_CMD_NEW_KEY, nvlist,
	    (uint8_t *)key->value, WRAPPING_KEY_LEN);
	pw_free(key);
	nvlist_free(nvlist);
	if (ret != 0) {
		pam_syslog(pamh, LOG_ERR,
		    "'%s': rekeying the primary slot failed: %d", ds_name, ret);
	}
	return (ret);
}

/*
 * Re-wrap alternate slot `slot` under the new password. The slot number,
 * keyformat and iteration count are preserved, wkey_1 and every other slot are
 * untouched, and the location becomes prompt because that is the source PAM
 * supplies. The new key is derived with the slot's own iteration count so it
 * matches what load-key will later use.
 */
static int
rewrap_slot(pam_handle_t *pamh, zfs_handle_t *ds, uint64_t slot,
    const char *passphrase, uint64_t iters)
{
	const char *ds_name = zfs_get_name(ds);
	nvlist_t *nvlist = fnvlist_alloc();
	pw_password_t *key = prepare_new_key(pamh, ds, passphrase, nvlist,
	    iters);
	if (key == NULL) {
		nvlist_free(nvlist);
		return (EIO);
	}
	int ret = lzc_keyslot_rewrap(ds_name, slot, nvlist,
	    (uint8_t *)key->value, WRAPPING_KEY_LEN);
	pw_free(key);
	nvlist_free(nvlist);
	return (ret);
}

/*
 * PAM-driven password change (design P5 section 14.6). The old password
 * identifies the one slot that is rekeyed; nothing else is touched. The primary
 * slot is only rekeyed when the root has no alternate slots, because change-key
 * refuses in that state and PAM must not make that call on the owner's behalf.
 */
static int
change_key(pam_handle_t *pamh, const char *ds_name, const char *old_pass,
    const char *new_pass)
{
	zfs_handle_t *ds = zfs_open(g_zfs, ds_name, ZFS_TYPE_FILESYSTEM);
	if (ds == NULL) {
		pam_syslog(pamh, LOG_ERR, "dataset %s not found", ds_name);
		return (-1);
	}

	uint64_t slot = 0, iters = 0;
	boolean_t has_extra = B_FALSE;
	int ret = find_key_slot(pamh, ds, old_pass, &slot, &has_extra, &iters);
	if (ret != 0) {
		zfs_close(ds);
		return (-1);
	}

	if (slot == 0) {
		pam_syslog(pamh, LOG_ERR,
		    "'%s': the old password does not unlock any key slot; "
		    "nothing changed", ds_name);
		zfs_close(ds);
		return (-1);
	}

	if (slot == DSL_CRYPTO_KEY_SLOT_PRIMARY) {
		if (has_extra) {
			pam_syslog(pamh, LOG_ERR,
			    "'%s': the password matches the primary key "
			    "slot and alternate key slots exist; refusing "
			    "to rekey it", ds_name);
			zfs_close(ds);
			return (-1);
		}
		ret = rekey_primary(pamh, ds, new_pass);
	} else {
		ret = rewrap_slot(pamh, ds, slot, new_pass, iters);
		if (ret != 0) {
			pam_syslog(pamh, LOG_ERR,
			    "'%s': failed to rewrap key slot %llu: %d",
			    ds_name, (u_longlong_t)slot, ret);
		}
	}

	zfs_close(ds);
	return (ret == 0 ? 0 : -1);
}

typedef struct {
	char *homes_prefix;
	char *runstatedir;
	char *homedir;
	char *dsname;
	uid_t uid_min;
	uid_t uid_max;
	uid_t uid;
	const char *username;
	boolean_t unmount_and_unload;
	boolean_t force_unmount;
	boolean_t recursive_homes;
	boolean_t mount_recursively;
} zfs_key_config_t;

static int
zfs_key_config_load(pam_handle_t *pamh, zfs_key_config_t *config,
    int argc, const char **argv)
{
#if	defined(__FreeBSD__)
	config->homes_prefix = strdup("zroot/home");
#else
	config->homes_prefix = strdup("rpool/home");
#endif
	if (config->homes_prefix == NULL) {
		pam_syslog(pamh, LOG_ERR, "strdup failure");
		return (PAM_SERVICE_ERR);
	}
	config->runstatedir = strdup(RUNSTATEDIR "/pam_zfs_key");
	if (config->runstatedir == NULL) {
		pam_syslog(pamh, LOG_ERR, "strdup failure");
		free(config->homes_prefix);
		return (PAM_SERVICE_ERR);
	}
	const char *name;
	if (pam_get_user(pamh, &name, NULL) != PAM_SUCCESS) {
		pam_syslog(pamh, LOG_ERR,
		    "couldn't get username from PAM stack");
		free(config->runstatedir);
		free(config->homes_prefix);
		return (PAM_SERVICE_ERR);
	}
	struct passwd *entry = getpwnam(name);
	if (!entry) {
		free(config->runstatedir);
		free(config->homes_prefix);
		return (PAM_USER_UNKNOWN);
	}
	config->uid_min = 1000;
	config->uid_max = MAXUID;
	config->uid = entry->pw_uid;
	config->username = name;
	config->unmount_and_unload = B_TRUE;
	config->force_unmount = B_FALSE;
	config->recursive_homes = B_FALSE;
	config->mount_recursively = B_FALSE;
	config->dsname = NULL;
	config->homedir = NULL;
	for (int c = 0; c < argc; c++) {
		if (strncmp(argv[c], "homes=", 6) == 0) {
			free(config->homes_prefix);
			config->homes_prefix = strdup(argv[c] + 6);
		} else if (strncmp(argv[c], "runstatedir=", 12) == 0) {
			free(config->runstatedir);
			config->runstatedir = strdup(argv[c] + 12);
		} else if (strncmp(argv[c], "uid_min=", 8) == 0) {
			sscanf(argv[c] + 8, "%u", &config->uid_min);
		} else if (strncmp(argv[c], "uid_max=", 8) == 0) {
			sscanf(argv[c] + 8, "%u", &config->uid_max);
		} else if (strcmp(argv[c], "nounmount") == 0) {
			config->unmount_and_unload = B_FALSE;
		} else if (strcmp(argv[c], "forceunmount") == 0) {
			config->force_unmount = B_TRUE;
		} else if (strcmp(argv[c], "recursive_homes") == 0) {
			config->recursive_homes = B_TRUE;
		} else if (strcmp(argv[c], "mount_recursively") == 0) {
			config->mount_recursively = B_TRUE;
		} else if (strcmp(argv[c], "prop_mountpoint") == 0) {
			if (config->homedir == NULL)
				config->homedir = strdup(entry->pw_dir);
		}
	}
	return (PAM_SUCCESS);
}

typedef struct {
	pam_handle_t *pamh;
	zfs_key_config_t *target;
} mount_umount_dataset_data_t;

static int
mount_dataset(zfs_handle_t *zhp, void *data)
{
	mount_umount_dataset_data_t *mount_umount_dataset_data = data;

	zfs_key_config_t *target = mount_umount_dataset_data->target;
	pam_handle_t *pamh = mount_umount_dataset_data->pamh;

	/* Refresh properties to get the latest key status */
	zfs_refresh_properties(zhp);

	int ret = 0;

	/* Check if dataset type is filesystem */
	if (zhp->zfs_type != ZFS_TYPE_FILESYSTEM) {
		pam_syslog(pamh, LOG_DEBUG,
		    "dataset is not filesystem: %s, skipping.",
		    zfs_get_name(zhp));
		return (0);
	}

	/* Check if encryption key is available */
	if (zfs_prop_get_int(zhp, ZFS_PROP_KEYSTATUS) ==
	    ZFS_KEYSTATUS_UNAVAILABLE) {
		pam_syslog(pamh, LOG_WARNING,
		    "key unavailable for: %s, skipping",
		    zfs_get_name(zhp));
		return (0);
	}

	/* Check if prop canmount is on */
	if (zfs_prop_get_int(zhp, ZFS_PROP_CANMOUNT) != ZFS_CANMOUNT_ON) {
		pam_syslog(pamh, LOG_INFO,
		    "canmount is not on for: %s, skipping",
		    zfs_get_name(zhp));
		return (0);
	}

	/* Get mountpoint prop for check */
	char mountpoint[ZFS_MAXPROPLEN];
	if ((ret = zfs_prop_get(zhp, ZFS_PROP_MOUNTPOINT, mountpoint,
	    sizeof (mountpoint), NULL, NULL, 0, 1)) != 0) {
		pam_syslog(pamh, LOG_ERR,
		    "failed to get mountpoint prop: %d", ret);
		return (-1);
	}

	/* Check if mountpoint isn't none or legacy */
	if (strcmp(mountpoint, ZFS_MOUNTPOINT_NONE) == 0 ||
	    strcmp(mountpoint, ZFS_MOUNTPOINT_LEGACY) == 0) {
		pam_syslog(pamh, LOG_INFO,
		    "mountpoint is none or legacy for: %s, skipping",
		    zfs_get_name(zhp));
		return (0);
	}

	/* Don't mount the dataset if already mounted */
	if (zfs_is_mounted(zhp, NULL)) {
		pam_syslog(pamh, LOG_INFO, "already mounted: %s",
		    zfs_get_name(zhp));
		return (0);
	}

	/* Mount the dataset */
	ret = zfs_mount(zhp, NULL, 0);
	if (ret) {
		pam_syslog(pamh, LOG_ERR,
		    "zfs_mount failed for %s with: %d", zfs_get_name(zhp),
		    ret);
		return (ret);
	}

	/* Recursively mount children if the recursive flag is set */
	if (target->mount_recursively) {
		ret = zfs_iter_filesystems_v2(zhp, 0, mount_dataset, data);
		if (ret != 0) {
			pam_syslog(pamh, LOG_ERR,
			    "child iteration failed: %d", ret);
			return (-1);
		}
	}

	return (ret);
}

static int
umount_dataset(zfs_handle_t *zhp, void *data)
{
	mount_umount_dataset_data_t *mount_umount_dataset_data = data;

	zfs_key_config_t *target = mount_umount_dataset_data->target;
	pam_handle_t *pamh = mount_umount_dataset_data->pamh;

	int ret = 0;
	/* Recursively umount children if the recursive flag is set */
	if (target->mount_recursively) {
		ret = zfs_iter_filesystems_v2(zhp, 0, umount_dataset, data);
		if (ret != 0) {
			pam_syslog(pamh, LOG_ERR,
			    "child iteration failed: %d", ret);
			return (-1);
		}
	}

	/* Check if dataset type is filesystem */
	if (zhp->zfs_type != ZFS_TYPE_FILESYSTEM) {
		pam_syslog(pamh, LOG_DEBUG,
		    "dataset is not filesystem: %s, skipping",
		    zfs_get_name(zhp));
		return (0);
	}

	/* Don't umount the dataset if already unmounted */
	if (zfs_is_mounted(zhp, NULL) == 0) {
		pam_syslog(pamh, LOG_INFO, "already unmounted: %s",
		    zfs_get_name(zhp));
		return (0);
	}

	/* Unmount the dataset */
	ret = zfs_unmount(zhp, NULL, target->force_unmount ? MS_FORCE : 0);
	if (ret) {
		pam_syslog(pamh, LOG_ERR,
		    "zfs_unmount failed for %s with: %d", zfs_get_name(zhp),
		    ret);
		return (ret);
	}

	return (ret);
}

static int
decrypt_mount(pam_handle_t *pamh, zfs_key_config_t *config, const char *ds_name,
    const char *passphrase, boolean_t noop)
{
	zfs_handle_t *ds = zfs_open(g_zfs, ds_name, ZFS_TYPE_FILESYSTEM);
	if (ds == NULL) {
		pam_syslog(pamh, LOG_ERR, "dataset %s not found", ds_name);
		return (-1);
	}
	/*
	 * Slot 1 is today's path, and the only slot a slotless deployment has.
	 * It is skipped when it does not hold a passphrase: deriving against a
	 * salt and iteration count of zero cannot succeed.
	 */
	int ret = EACCES;
	pw_password_t *key;
	if (zfs_prop_get_int(ds, ZFS_PROP_KEYFORMAT) ==
	    ZFS_KEYFORMAT_PASSPHRASE) {
		key = prepare_passphrase(pamh, ds, passphrase, NULL, 0);
		if (key == NULL) {
			zfs_close(ds);
			return (-1);
		}
		ret = lzc_load_key(ds_name, noop, (uint8_t *)key->value,
		    WRAPPING_KEY_LEN);
		pw_free(key);
	}

	/*
	 * Then the alternate passphrase slots, ascending, each with its own
	 * salt and iteration count. Only reached when slot 1 did not unlock
	 * the root, so every case that worked before takes the path it always
	 * did.
	 */
	if (ret != 0 && ret != EEXIST) {
		passphrase_slot_t *slots = NULL;
		size_t nslots = 0, i;

		if (get_passphrase_slots(pamh, ds, &slots, &nslots,
		    NULL) == 0) {
			for (i = 0; i < nslots; i++) {
				key = derive_passphrase(pamh, passphrase,
				    slots[i].salt, slots[i].iters);
				if (key == NULL)
					continue;
				ret = lzc_load_key_slot(ds_name, noop,
				    (uint8_t *)key->value, WRAPPING_KEY_LEN,
				    slots[i].slot);
				pw_free(key);
				if (ret == 0 || ret == EEXIST)
					break;
			}
			free(slots);
		}
	}

	if (ret && ret != EEXIST) {
		pam_syslog(pamh, LOG_ERR, "load_key failed: %d", ret);
		zfs_close(ds);
		return (-1);
	}

	if (noop) {
		zfs_close(ds);
		return (0);
	}

	mount_umount_dataset_data_t data;
	data.pamh = pamh;
	data.target = config;

	ret = mount_dataset(ds, &data);
	if (ret != 0) {
		pam_syslog(pamh, LOG_ERR, "mount failed: %d", ret);
		zfs_close(ds);
		return (-1);
	}

	zfs_close(ds);
	return (0);
}

static int
unmount_unload(pam_handle_t *pamh, const char *ds_name,
    zfs_key_config_t *target)
{
	zfs_handle_t *ds = zfs_open(g_zfs, ds_name, ZFS_TYPE_FILESYSTEM);
	if (ds == NULL) {
		pam_syslog(pamh, LOG_ERR, "dataset %s not found", ds_name);
		return (-1);
	}

	mount_umount_dataset_data_t data;
	data.pamh = pamh;
	data.target = target;

	int ret = umount_dataset(ds, &data);
	if (ret) {
		pam_syslog(pamh, LOG_ERR,
		    "unmount_dataset failed with: %d", ret);
		zfs_close(ds);
		return (-1);
	}

	ret = lzc_unload_key(ds_name);
	if (ret) {
		pam_syslog(pamh, LOG_ERR, "unload_key failed with: %d", ret);
		zfs_close(ds);
		return (-1);
	}
	zfs_close(ds);
	return (0);
}

static void
zfs_key_config_free(zfs_key_config_t *config)
{
	free(config->homes_prefix);
	free(config->runstatedir);
	free(config->homedir);
	free(config->dsname);
}

static int
find_dsname_by_prop_value(zfs_handle_t *zhp, void *data)
{
	zfs_type_t type = zfs_get_type(zhp);
	zfs_key_config_t *target = data;
	char mountpoint[ZFS_MAXPROPLEN];

	/* Skip any datasets whose type does not match */
	if ((type & ZFS_TYPE_FILESYSTEM) == 0) {
		zfs_close(zhp);
		return (0);
	}

	/* Skip any datasets whose mountpoint does not match */
	(void) zfs_prop_get(zhp, ZFS_PROP_MOUNTPOINT, mountpoint,
	    sizeof (mountpoint), NULL, NULL, 0, B_FALSE);
	if (strcmp(target->homedir, mountpoint) != 0) {
		if (target->recursive_homes) {
			(void) zfs_iter_filesystems_v2(zhp, 0,
			    find_dsname_by_prop_value, target);
		}
		zfs_close(zhp);
		return (target->dsname != NULL);
	}

	target->dsname = strdup(zfs_get_name(zhp));
	zfs_close(zhp);
	return (1);
}

static char *
zfs_key_config_get_dataset(pam_handle_t *pamh, zfs_key_config_t *config)
{
	if (config->homedir != NULL &&
	    config->homes_prefix != NULL) {
		if (strcmp(config->homes_prefix, "*") == 0) {
			(void) zfs_iter_root(g_zfs,
			    find_dsname_by_prop_value, config);
		} else {
			zfs_handle_t *zhp = zfs_open(g_zfs,
			    config->homes_prefix, ZFS_TYPE_FILESYSTEM);
			if (zhp == NULL) {
				pam_syslog(pamh, LOG_ERR,
				    "dataset %s not found",
				    config->homes_prefix);
				return (NULL);
			}

			(void) zfs_iter_filesystems_v2(zhp, 0,
			    find_dsname_by_prop_value, config);
			zfs_close(zhp);
		}
		char *dsname = config->dsname;
		config->dsname = NULL;
		return (dsname);
	}

	if (config->homes_prefix == NULL) {
		return (NULL);
	}

	size_t len = ZFS_MAX_DATASET_NAME_LEN;
	size_t total_len = strlen(config->homes_prefix) + 1
	    + strlen(config->username);
	if (total_len > len) {
		return (NULL);
	}
	char *ret = malloc(len + 1);
	if (!ret) {
		return (NULL);
	}
	ret[0] = 0;
	(void) snprintf(ret, len + 1, "%s/%s", config->homes_prefix,
	    config->username);
	return (ret);
}

/*
 * Callback type for foreach_dataset.
 * Returns 0 on success, -1 on failure.
 */
typedef int (*dataset_callback_t)(pam_handle_t *, zfs_key_config_t *,
    const char *, void *);

/*
 * Iterate over comma-separated homes prefixes and call callback for each
 * existing dataset. Returns number of successful callbacks, or -1 if none
 * succeeded.
 */
static int
foreach_dataset(pam_handle_t *pamh, zfs_key_config_t *config,
    dataset_callback_t callback, void *data)
{
	if (config->homes_prefix == NULL)
		return (-1);

	/* Check if this is a comma-separated list */
	if (strchr(config->homes_prefix, ',') == NULL) {
		/* Single home - use existing logic */
		char *dataset = zfs_key_config_get_dataset(pamh, config);
		if (dataset == NULL)
			return (-1);
		int ret = callback(pamh, config, dataset, data);
		free(dataset);
		return (ret == 0 ? 1 : -1);
	}

	/* Multiple homes - parse and iterate */
	pam_syslog(pamh, LOG_DEBUG,
	    "processing multiple home prefixes: %s", config->homes_prefix);

	char *homes_copy = strdup(config->homes_prefix);
	if (homes_copy == NULL)
		return (-1);

	char *saved_prefix = config->homes_prefix;
	char *saveptr;
	char *token = strtok_r(homes_copy, ",", &saveptr);
	int success_count = 0;
	boolean_t failed = B_FALSE;

	while (token != NULL) {
		/* Temporarily set homes_prefix to this single prefix */
		config->homes_prefix = token;
		char *dataset = zfs_key_config_get_dataset(pamh, config);
		if (dataset != NULL) {
			pam_syslog(pamh, LOG_DEBUG,
			    "processing dataset '%s' for prefix '%s'",
			    dataset, token);
			if (callback(pamh, config, dataset, data) == 0) {
				success_count++;
			} else {
				failed = B_TRUE;
				pam_syslog(pamh, LOG_WARNING,
				    "operation failed for dataset '%s'",
				    dataset);
			}
			free(dataset);
		} else {
			pam_syslog(pamh, LOG_DEBUG,
			    "no dataset found for prefix '%s', skip", token);
		}
		token = strtok_r(NULL, ",", &saveptr);
	}

	config->homes_prefix = saved_prefix;
	free(homes_copy);
	pam_syslog(pamh, LOG_DEBUG,
	    "processed %d datasets, %s",
	    success_count, failed ? "with failures" : "all successful");
	return (!failed && success_count > 0 ? success_count : -1);
}

static int
zfs_key_config_modify_session_counter(pam_handle_t *pamh,
    zfs_key_config_t *config, int delta)
{
	const char *runtime_path = config->runstatedir;
	if (mkdir(runtime_path, S_IRWXU) != 0 && errno != EEXIST) {
		pam_syslog(pamh, LOG_ERR, "Can't create runtime path: %d",
		    errno);
		return (-1);
	}
	const int runtime_fd = open(runtime_path,
	    O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_DIRECTORY);
	if (runtime_fd < 0) {
		pam_syslog(pamh, LOG_ERR, "Can't open runtime path: %d", errno);
		return (-1);
	}
	if (fchown(runtime_fd, 0, 0) != 0) {
		pam_syslog(pamh, LOG_ERR, "Can't chown runtime path: %d",
		    errno);
		close(runtime_fd);
		return (-1);
	}
	if (fchmod(runtime_fd, S_IRWXU) != 0) {
		pam_syslog(pamh, LOG_ERR, "Can't chmod runtime path: %d",
		    errno);
		close(runtime_fd);
		return (-1);
	}

	char *counter_path;
	if (asprintf(&counter_path, "%u", config->uid) == -1) {
		close(runtime_fd);
		return (-1);
	}

	const int fd = openat(runtime_fd, counter_path,
	    O_RDWR | O_CLOEXEC | O_CREAT | O_NOFOLLOW,
	    S_IRUSR | S_IWUSR);
	int ret = errno;

	free(counter_path);
	close(runtime_fd);

	if (fd < 0) {
		pam_syslog(pamh, LOG_ERR, "Can't open counter file: %d", ret);
		return (-1);
	}
	if (flock(fd, LOCK_EX) != 0) {
		pam_syslog(pamh, LOG_ERR, "Can't lock counter file: %d", errno);
		close(fd);
		return (-1);
	}
	char counter[20];
	char *pos = counter;
	int remaining = sizeof (counter) - 1;
	counter[sizeof (counter) - 1] = 0;
	while (remaining > 0 && (ret = read(fd, pos, remaining)) > 0) {
		remaining -= ret;
		pos += ret;
	}
	*pos = 0;
	long int counter_value = strtol(counter, NULL, 10);
	counter_value += delta;
	if (counter_value < 0) {
		counter_value = 0;
	}
	lseek(fd, 0, SEEK_SET);
	if (ftruncate(fd, 0) != 0) {
		pam_syslog(pamh, LOG_ERR, "Can't truncate counter file: %d",
		    errno);
		close(fd);
		return (-1);
	}
	snprintf(counter, sizeof (counter), "%ld", counter_value);
	remaining = strlen(counter);
	pos = counter;
	while (remaining > 0 && (ret = write(fd, pos, remaining)) > 0) {
		remaining -= ret;
		pos += ret;
	}
	close(fd);
	return (counter_value);
}

/* Callback for authentication - verify password works (noop mode) */
static int
auth_callback(pam_handle_t *pamh, zfs_key_config_t *config,
    const char *dataset, void *data)
{
	const char *passphrase = data;
	return (decrypt_mount(pamh, config, dataset, passphrase, B_TRUE));
}

__attribute__((visibility("default")))
PAM_EXTERN int
pam_sm_authenticate(pam_handle_t *pamh, int flags,
    int argc, const char **argv)
{
	(void) flags;

	if (geteuid() != 0) {
		pam_syslog(pamh, LOG_ERR,
		    "Cannot zfs_mount when not being root.");
		return (PAM_SERVICE_ERR);
	}
	zfs_key_config_t config;
	int config_err = zfs_key_config_load(pamh, &config, argc, argv);
	if (config_err != PAM_SUCCESS) {
		return (config_err);
	}
	if (config.uid < config.uid_min || config.uid > config.uid_max) {
		zfs_key_config_free(&config);
		return (PAM_SERVICE_ERR);
	}

	const pw_password_t *token = pw_fetch_lazy(pamh,
	    PAM_AUTHTOK, PASSWORD_VAR_NAME);
	if (token == NULL) {
		zfs_key_config_free(&config);
		return (PAM_AUTH_ERR);
	}
	if (pam_zfs_init(pamh) != 0) {
		zfs_key_config_free(&config);
		return (PAM_SERVICE_ERR);
	}

	int ret = foreach_dataset(pamh, &config, auth_callback,
	    (void *)token->value);
	pam_zfs_free();
	zfs_key_config_free(&config);
	if (ret < 0) {
		return (PAM_AUTH_ERR);
	}
	return (PAM_SUCCESS);
}

__attribute__((visibility("default")))
PAM_EXTERN int
pam_sm_setcred(pam_handle_t *pamh, int flags,
    int argc, const char **argv)
{
	(void) pamh, (void) flags, (void) argc, (void) argv;
	return (PAM_SUCCESS);
}

/* Context for password change callback */
typedef struct {
	const char *old_pass;
	const char *new_pass;
} chauthtok_ctx_t;

/* Callback for password change */
static int
chauthtok_callback(pam_handle_t *pamh, zfs_key_config_t *config,
    const char *dataset, void *data)
{
	chauthtok_ctx_t *ctx = data;
	int was_loaded = is_key_loaded(pamh, dataset);
	if (!was_loaded) {
		int ret = decrypt_mount(pamh, config, dataset,
		    ctx->old_pass, B_FALSE);
		if (ret == -1) {
			pam_syslog(pamh, LOG_ERR,
			    "failed to load key for '%s' during "
			    "password change", dataset);
			return (-1);
		}
	}
	int ret = change_key(pamh, dataset, ctx->old_pass, ctx->new_pass);
	if (ret == -1) {
		pam_syslog(pamh, LOG_ERR,
		    "failed to change key for dataset '%s'", dataset);
	}
	if (!was_loaded)
		unmount_unload(pamh, dataset, config);
	return (ret);
}

__attribute__((visibility("default")))
PAM_EXTERN int
pam_sm_chauthtok(pam_handle_t *pamh, int flags,
    int argc, const char **argv)
{
	if (geteuid() != 0) {
		pam_syslog(pamh, LOG_ERR,
		    "Cannot zfs_mount when not being root.");
		return (PAM_PERM_DENIED);
	}
	zfs_key_config_t config;
	if (zfs_key_config_load(pamh, &config, argc, argv) != PAM_SUCCESS) {
		return (PAM_SERVICE_ERR);
	}
	if (config.uid < config.uid_min || config.uid > config.uid_max) {
		zfs_key_config_free(&config);
		return (PAM_SERVICE_ERR);
	}
	const pw_password_t *old_token = pw_get(pamh,
	    PAM_OLDAUTHTOK, OLD_PASSWORD_VAR_NAME);

	if (!old_token) {
		pam_syslog(pamh, LOG_ERR,
		    "old password from PAM stack is null");
		zfs_key_config_free(&config);
		return (PAM_SERVICE_ERR);
	}

	if (pam_zfs_init(pamh) != 0) {
		zfs_key_config_free(&config);
		return (PAM_SERVICE_ERR);
	}

	/* First verify old password works for all datasets */
	int ret = foreach_dataset(pamh, &config, auth_callback,
	    (void *)old_token->value);
	if (ret < 0) {
		pam_syslog(pamh, LOG_ERR, "old token mismatch");
		pam_zfs_free();
		zfs_key_config_free(&config);
		return (PAM_PERM_DENIED);
	}

	if ((flags & PAM_UPDATE_AUTHTOK) != 0) {
		const pw_password_t *token = pw_get(pamh, PAM_AUTHTOK,
		    PASSWORD_VAR_NAME);
		if (token == NULL) {
			pam_syslog(pamh, LOG_ERR, "new password unavailable");
			pam_zfs_free();
			zfs_key_config_free(&config);
			pw_clear(pamh, OLD_PASSWORD_VAR_NAME);
			return (PAM_SERVICE_ERR);
		}

		chauthtok_ctx_t ctx = {
			.old_pass = old_token->value,
			.new_pass = token->value
		};

		ret = foreach_dataset(pamh, &config, chauthtok_callback, &ctx);
		pam_zfs_free();
		zfs_key_config_free(&config);

		if (ret < 0) {
			pw_clear(pamh, OLD_PASSWORD_VAR_NAME);
			pw_clear(pamh, PASSWORD_VAR_NAME);
			return (PAM_SERVICE_ERR);
		}

		if (pw_clear(pamh, OLD_PASSWORD_VAR_NAME) == -1 ||
		    pw_clear(pamh, PASSWORD_VAR_NAME) == -1) {
			return (PAM_SERVICE_ERR);
		}
	} else {
		pam_zfs_free();
		zfs_key_config_free(&config);
	}
	return (PAM_SUCCESS);
}

/* Callback for session open - decrypt and mount */
static int
open_session_callback(pam_handle_t *pamh, zfs_key_config_t *config,
    const char *dataset, void *data)
{
	const char *passphrase = data;
	return (decrypt_mount(pamh, config, dataset, passphrase, B_FALSE));
}

/* Callback for session close - unmount and unload */
static int
close_session_callback(pam_handle_t *pamh, zfs_key_config_t *config,
    const char *dataset, void *data)
{
	(void) data;
	return (unmount_unload(pamh, dataset, config));
}

PAM_EXTERN int
pam_sm_open_session(pam_handle_t *pamh, int flags,
    int argc, const char **argv)
{
	(void) flags;

	if (geteuid() != 0) {
		pam_syslog(pamh, LOG_ERR,
		    "Cannot zfs_mount when not being root.");
		return (PAM_SUCCESS);
	}
	zfs_key_config_t config;
	if (zfs_key_config_load(pamh, &config, argc, argv) != PAM_SUCCESS) {
		return (PAM_SESSION_ERR);
	}

	if (config.uid < config.uid_min || config.uid > config.uid_max) {
		zfs_key_config_free(&config);
		return (PAM_SUCCESS);
	}

	int counter = zfs_key_config_modify_session_counter(pamh, &config, 1);
	if (counter != 1) {
		zfs_key_config_free(&config);
		return (PAM_SUCCESS);
	}

	const pw_password_t *token = pw_get(pamh,
	    PAM_AUTHTOK, PASSWORD_VAR_NAME);
	if (token == NULL) {
		zfs_key_config_free(&config);
		return (PAM_SESSION_ERR);
	}
	if (pam_zfs_init(pamh) != 0) {
		zfs_key_config_free(&config);
		return (PAM_SERVICE_ERR);
	}

	int ret = foreach_dataset(pamh, &config, open_session_callback,
	    (void *)token->value);
	pam_zfs_free();
	zfs_key_config_free(&config);

	if (ret < 0) {
		return (PAM_SERVICE_ERR);
	}
	if (pw_clear(pamh, PASSWORD_VAR_NAME) == -1) {
		return (PAM_SERVICE_ERR);
	}
	return (PAM_SUCCESS);

}

__attribute__((visibility("default")))
PAM_EXTERN int
pam_sm_close_session(pam_handle_t *pamh, int flags,
    int argc, const char **argv)
{
	(void) flags;

	if (geteuid() != 0) {
		pam_syslog(pamh, LOG_ERR,
		    "Cannot zfs_mount when not being root.");
		return (PAM_SUCCESS);
	}
	zfs_key_config_t config;
	if (zfs_key_config_load(pamh, &config, argc, argv) != PAM_SUCCESS) {
		return (PAM_SESSION_ERR);
	}
	if (config.uid < config.uid_min || config.uid > config.uid_max) {
		zfs_key_config_free(&config);
		return (PAM_SUCCESS);
	}

	int counter = zfs_key_config_modify_session_counter(pamh, &config, -1);
	if (counter != 0) {
		zfs_key_config_free(&config);
		return (PAM_SUCCESS);
	}

	if (config.unmount_and_unload) {
		if (pam_zfs_init(pamh) != 0) {
			zfs_key_config_free(&config);
			return (PAM_SERVICE_ERR);
		}

		int ret = foreach_dataset(pamh, &config,
		    close_session_callback, NULL);
		pam_zfs_free();

		if (ret < 0) {
			zfs_key_config_free(&config);
			return (PAM_SESSION_ERR);
		}
	}

	zfs_key_config_free(&config);
	return (PAM_SUCCESS);
}
