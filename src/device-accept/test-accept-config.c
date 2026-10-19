/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include "sd-device.h"

#include "accept-bind.h"
#include "accept-config.h"
#include "accept-flow.h"
#include "alloc-util.h"
#include "capability-util.h"
#include "errno-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "fs-util.h"
#include "mkdir.h"
#include "mount-util.h"
#include "path-util.h"
#include "process-util.h"
#include "rm-rf.h"
#include "strv.h"
#include "test-tables.h"
#include "tests.h"
#include "tmpfile-util.h"
#include "virt.h"

TEST(tables) {
        test_table(AcceptTrustLevel, accept_trust_level, ACCEPT_TRUST_LEVEL);
        test_table(AcceptState, accept_state, ACCEPT_STATE);
}

static void test_selector_valid_one(const char *input, AcceptSelectorType type, const char *value) {
        _cleanup_(accept_selector_done) AcceptSelector selector = {};

        log_debug("%s: \"%s\"", __func__, input);

        ASSERT_OK(accept_selector_parse(input, &selector));
        ASSERT_EQ(selector.type, type);
        ASSERT_STREQ(selector.value, value);
}

static void test_selector_invalid_one(const char *input) {
        _cleanup_(accept_selector_done) AcceptSelector selector = {};

        log_debug("%s: \"%s\"", __func__, input);

        ASSERT_ERROR(accept_selector_parse(input, &selector), EINVAL);
}

TEST(selector_parse) {
        test_selector_valid_one("name:eth0", ACCEPT_SELECTOR_NAME, "eth0");
        test_selector_valid_one("name:mlx5_*", ACCEPT_SELECTOR_NAME, "mlx5_*");
        test_selector_valid_one("name:gb!raw0", ACCEPT_SELECTOR_NAME, "gb!raw0");
        test_selector_valid_one("name:0000:01:00.0", ACCEPT_SELECTOR_NAME, "0000:01:00.0");

        test_selector_valid_one("pci:0000:01:00.0", ACCEPT_SELECTOR_PCI, "0000:01:00.0");
        test_selector_valid_one("pci:01:00.0", ACCEPT_SELECTOR_PCI, "0000:01:00.0");
        test_selector_valid_one("pci:AB:1F.7", ACCEPT_SELECTOR_PCI, "0000:ab:1f.7");
        test_selector_valid_one("pci:ABCD:Ef:0a.3", ACCEPT_SELECTOR_PCI, "abcd:ef:0a.3");
        test_selector_valid_one("pci:10000:e0:06.0", ACCEPT_SELECTOR_PCI, "10000:e0:06.0");
        test_selector_valid_one("pci:0000abcd:00:00.0", ACCEPT_SELECTOR_PCI, "abcd:00:00.0");
        test_selector_valid_one("pci:ffffffff:ff:1f.7", ACCEPT_SELECTOR_PCI, "ffffffff:ff:1f.7");

        test_selector_valid_one("path:/sys/devices/pci0000:00/0000:00:1c.0/0000:05:00.0", ACCEPT_SELECTOR_PATH,
                                "/devices/pci0000:00/0000:00:1c.0/0000:05:00.0");
        test_selector_valid_one("path:/devices/pci0000:00/0000:00:1c.0/0000:05:00.0", ACCEPT_SELECTOR_PATH,
                                "/devices/pci0000:00/0000:00:1c.0/0000:05:00.0");
        test_selector_valid_one("path:/sys//devices/pci0000:00/./0000:00:1c.0/", ACCEPT_SELECTOR_PATH,
                                "/devices/pci0000:00/0000:00:1c.0");
        test_selector_valid_one("path:/sys/devices/pci0000:00/*/0000:05:00.?", ACCEPT_SELECTOR_PATH,
                                "/devices/pci0000:00/*/0000:05:00.?");

        test_selector_invalid_one("");
        test_selector_invalid_one("eth0");
        test_selector_invalid_one("0000:01:00.0");
        test_selector_invalid_one("/sys/devices/virtual/net/lo");
        test_selector_invalid_one(":eth0");
        test_selector_invalid_one("bogus:eth0");
        test_selector_invalid_one("NAME:eth0");
        test_selector_invalid_one("PCI:0000:01:00.0");

        test_selector_invalid_one("name:");
        test_selector_invalid_one("name:eth0/bar");

        test_selector_invalid_one("pci:");
        test_selector_invalid_one("pci:00.0");
        test_selector_invalid_one("pci:1:00.0");
        test_selector_invalid_one("pci:001:00.0");
        test_selector_invalid_one("pci:01:0.0");
        test_selector_invalid_one("pci:01:000.0");
        test_selector_invalid_one("pci:01:20.0");
        test_selector_invalid_one("pci:01:00.8");
        test_selector_invalid_one("pci:01:00.00");
        test_selector_invalid_one("pci:01:00");
        test_selector_invalid_one("pci:01:00.");
        test_selector_invalid_one("pci:01:00.0.0");
        test_selector_invalid_one("pci:000:01:00.0");
        test_selector_invalid_one("pci:000000000:01:00.0");
        test_selector_invalid_one("pci:0000:01:00.0:");
        test_selector_invalid_one("pci::01:00.0");
        test_selector_invalid_one("pci:0000::00.0");
        test_selector_invalid_one("pci:0000:01::00.0");
        test_selector_invalid_one("pci:0x00:01:00.0");
        test_selector_invalid_one("pci:+000:01:00.0");
        test_selector_invalid_one("pci:-000:01:00.0");
        test_selector_invalid_one("pci:0000:0g:00.0");
        test_selector_invalid_one("pci:0000:01:00.*");
        test_selector_invalid_one("pci:0000:01:*.0");
        test_selector_invalid_one("pci: 0000:01:00.0");

        test_selector_invalid_one("path:");
        test_selector_invalid_one("path:devices/pci0000:00");
        test_selector_invalid_one("path:/sys");
        test_selector_invalid_one("path:/sys/devices");
        test_selector_invalid_one("path:/devices/");
        test_selector_invalid_one("path:/sys/devices/../bus");
        test_selector_invalid_one("path:/devices/pci0000:00/..");
        test_selector_invalid_one("path:/sys/bus/pci/devices/0000:01:00.0");
        test_selector_invalid_one("path:/sys/class/net/eth0");
        test_selector_invalid_one("path:/sys/kernel/debug");
        test_selector_invalid_one("path:/sysdevices/foo");
}

static bool selector_matches(const char *input, const AcceptDeviceIdentity *identity) {
        _cleanup_(accept_selector_done) AcceptSelector selector = {};

        ASSERT_OK(accept_selector_parse(input, &selector));
        return accept_selector_matches(&selector, identity);
}

TEST(selector_matches) {
        const AcceptDeviceIdentity pci = {
                .sysname = "0000:01:00.0",
                .subsystem = "pci",
                .devpath = "/devices/pci0000:00/0000:00:1c.0/0000:01:00.0",
        }, pci_other_domain = {
                .sysname = "10000:01:00.0",
                .subsystem = "pci",
                .devpath = "/devices/pci10000:00/10000:00:1c.0/10000:01:00.0",
        }, infiniband = {
                .sysname = "mlx5_0",
                .subsystem = "infiniband",
                .devpath = "/devices/pci0000:00/0000:00:1c.0/0000:01:00.0/infiniband/mlx5_0",
        }, netdev = {
                .sysname = "eth0",
                .subsystem = "net",
                .devpath = "/devices/pci0000:00/0000:00:1c.0/0000:01:00.0/net/eth0",
        }, lookalike = {
                .sysname = "0000:01:00.0",
                .subsystem = "other",
                .devpath = "/devices/virtual/other/0000:01:00.0",
        }, no_subsystem = {
                .sysname = "0000:01:00.0",
                .devpath = "/devices/virtual/0000:01:00.0",
        };

        ASSERT_TRUE(selector_matches("name:eth0", &netdev));
        ASSERT_TRUE(selector_matches("name:eth*", &netdev));
        ASSERT_TRUE(selector_matches("name:et?0", &netdev));
        ASSERT_TRUE(selector_matches("name:eth[0-3]", &netdev));
        ASSERT_FALSE(selector_matches("name:eth1", &netdev));
        ASSERT_FALSE(selector_matches("name:Eth0", &netdev));
        ASSERT_FALSE(selector_matches("name:eth", &netdev));
        ASSERT_FALSE(selector_matches("name:eth0", &infiniband));
        ASSERT_TRUE(selector_matches("name:mlx5_*", &infiniband));
        ASSERT_FALSE(selector_matches("name:mlx5_*", &pci));
        ASSERT_TRUE(selector_matches("name:*", &pci));
        ASSERT_TRUE(selector_matches("name:0000:01:00.0", &pci));
        ASSERT_TRUE(selector_matches("name:0000:01:00.0", &lookalike));
        ASSERT_TRUE(selector_matches("name:0000:01:00.0", &no_subsystem));
        ASSERT_FALSE(selector_matches("name:0000:01:00.0", &pci_other_domain));

        ASSERT_TRUE(selector_matches("pci:0000:01:00.0", &pci));
        ASSERT_TRUE(selector_matches("pci:01:00.0", &pci));
        ASSERT_TRUE(selector_matches("pci:0000:01:00.0", &pci));
        ASSERT_FALSE(selector_matches("pci:0000:01:00.1", &pci));
        ASSERT_FALSE(selector_matches("pci:0000:02:00.0", &pci));
        ASSERT_FALSE(selector_matches("pci:0001:01:00.0", &pci));
        ASSERT_FALSE(selector_matches("pci:0000:01:00.0", &infiniband));
        ASSERT_FALSE(selector_matches("pci:0000:01:00.0", &netdev));
        ASSERT_FALSE(selector_matches("pci:0000:01:00.0", &lookalike));
        ASSERT_FALSE(selector_matches("pci:0000:01:00.0", &no_subsystem));
        ASSERT_TRUE(selector_matches("pci:10000:01:00.0", &pci_other_domain));
        ASSERT_FALSE(selector_matches("pci:0000:01:00.0", &pci_other_domain));
        ASSERT_FALSE(selector_matches("pci:10000:01:00.0", &pci));

        ASSERT_TRUE(selector_matches("path:/sys/devices/pci0000:00/0000:00:1c.0/0000:01:00.0", &pci));
        ASSERT_TRUE(selector_matches("path:/devices/pci0000:00/0000:00:1c.0/0000:01:00.0", &pci));
        ASSERT_TRUE(selector_matches("path:/sys/devices/pci0000:00/0000:00:1c.0/0000:01:00.0/", &pci));
        ASSERT_FALSE(selector_matches("path:/sys/devices/pci0000:00/0000:00:1c.0/0000:01:00.0", &infiniband));
        ASSERT_FALSE(selector_matches("path:/sys/devices/pci0000:00/0000:00:1c.0/0000:01:00.0", &netdev));
        ASSERT_FALSE(selector_matches("path:/sys/devices/pci0000:00/0000:00:1c.0", &pci));
        ASSERT_FALSE(selector_matches("path:/sys/devices/pci0000:00", &pci));
        ASSERT_TRUE(selector_matches("path:/sys/devices/pci0000:00/0000:00:1c.0/*", &pci));
        ASSERT_TRUE(selector_matches("path:/sys/devices/pci0000:00/*/0000:01:00.0", &pci));
        ASSERT_TRUE(selector_matches("path:/sys/devices/pci0000:00/*/0000:01:00.?", &pci));
        ASSERT_FALSE(selector_matches("path:/sys/devices/*/0000:01:00.0", &pci));
        ASSERT_FALSE(selector_matches("path:/sys/devices/*", &pci));
        ASSERT_TRUE(selector_matches("path:/sys/devices/*/*/*", &pci));
        ASSERT_TRUE(selector_matches("path:/sys/devices/pci0000:00/*/*/net/eth*", &netdev));
        ASSERT_FALSE(selector_matches("path:/sys/devices/pci0000:00/*/*/net/eth*", &pci));
}

static void write_file(const char *dir, const char *name, const char *contents) {
        _cleanup_free_ char *path = NULL;

        ASSERT_NOT_NULL(path = path_join(dir, name));
        ASSERT_OK(write_string_file(path, contents,
                                    WRITE_STRING_FILE_CREATE|WRITE_STRING_FILE_TRUNCATE|WRITE_STRING_FILE_MKDIR_0755));
}

static const AcceptConfig* lookup(
                const AcceptConfigContext *ctx,
                const char *sysname,
                const char *subsystem,
                const char *devpath) {

        const AcceptDeviceIdentity identity = {
                .sysname = sysname,
                .subsystem = subsystem,
                .devpath = devpath,
        };

        return accept_config_get(ctx, &identity);
}

static void assert_config(const AcceptConfig *config, const char *dir, const char *name, AcceptTrustLevel level) {
        ASSERT_NOT_NULL(config);

        _cleanup_free_ char *path = NULL;
        ASSERT_NOT_NULL(path = path_join(dir, name));

        ASSERT_STREQ(config->filename, path);
        ASSERT_EQ(config->trust_level, level);
}

TEST(config_load) {
        _cleanup_(rm_rf_physical_and_freep) char *root = NULL;
        _cleanup_(accept_config_ctx_freep) AcceptConfigContext *ctx = NULL;
        _cleanup_strv_free_ char **dirs = NULL;
        _cleanup_free_ char *masked = NULL, *dropin = NULL;

        ASSERT_OK(mkdtemp_malloc("/tmp/test-accept-config-XXXXXX", &root));

        const char *etc = strjoina(root, "/etc"), *run = strjoina(root, "/run"), *usr = strjoina(root, "/usr");
        ASSERT_NOT_NULL(dirs = strv_new(etc, run, usr));

        ASSERT_OK(accept_config_ctx_new(dirs, &ctx));
        ASSERT_TRUE(accept_config_is_empty(ctx));
        ASSERT_OK(accept_config_load(ctx));
        ASSERT_TRUE(accept_config_is_empty(ctx));

        write_file(usr, "10-vendor.conf",
                   "[Match]\n"
                   "Device=pci:0000:01:00.0 name:mlx5_*\n"
                   "Device=path:/sys/devices/platform/foo\n"
                   "\n"
                   "[Accept]\n"
                   "TrustLevel=disabled\n");
        write_file(run, "15-runtime.conf",
                   "[Match]\n"
                   "Device=pci:0000:01:00.0\n"
                   "\n"
                   "[Accept]\n"
                   "TrustLevel=full\n");
        write_file(etc, "20-local.conf",
                   "[Match]\n"
                   "Device=name:eth* pci:0000:02:00.0\n"
                   "\n"
                   "[Accept]\n"
                   "TrustLevel=adversary\n");
        ASSERT_OK(accept_config_load(ctx));
        ASSERT_FALSE(accept_config_is_empty(ctx));

        const char *pci_devpath = "/devices/pci0000:00/0000:00:1c.0/0000:01:00.0";
        assert_config(lookup(ctx, "0000:01:00.0", "pci", pci_devpath),
                      usr, "10-vendor.conf", ACCEPT_TRUST_LEVEL_DISABLED);
        assert_config(lookup(ctx, "mlx5_0", "infiniband", "/devices/foo/infiniband/mlx5_0"),
                      usr, "10-vendor.conf", ACCEPT_TRUST_LEVEL_DISABLED);
        assert_config(lookup(ctx, "foo", "platform", "/devices/platform/foo"),
                      usr, "10-vendor.conf", ACCEPT_TRUST_LEVEL_DISABLED);
        assert_config(lookup(ctx, "eth0", "net", "/devices/foo/net/eth0"),
                      etc, "20-local.conf", ACCEPT_TRUST_LEVEL_ADVERSARY);
        assert_config(lookup(ctx, "0000:02:00.0", "pci", "/devices/pci0000:00/0000:02:00.0"),
                      etc, "20-local.conf", ACCEPT_TRUST_LEVEL_ADVERSARY);
        ASSERT_NULL(lookup(ctx, "0000:03:00.0", "pci", "/devices/pci0000:00/0000:03:00.0"));
        ASSERT_NULL(lookup(ctx, "sda", "block", "/devices/pci0000:00/0000:03:00.0/block/sda"));
        ASSERT_NULL(lookup(ctx, "foo", NULL, "/devices/foo"));

        ASSERT_TRUE(strv_isempty(lookup(ctx, "eth0", "net", "/devices/foo/net/eth0")->dropins));

        ASSERT_OK(accept_config_load(ctx));
        ASSERT_OK(accept_config_load(ctx));
        assert_config(lookup(ctx, "eth0", "net", "/devices/foo/net/eth0"),
                      etc, "20-local.conf", ACCEPT_TRUST_LEVEL_ADVERSARY);

        write_file(etc, "10-vendor.conf",
                   "[Match]\n"
                   "Device=name:mlx5_1\n"
                   "\n"
                   "[Accept]\n"
                   "TrustLevel=default\n");
        ASSERT_OK(accept_config_load(ctx));
        assert_config(lookup(ctx, "mlx5_1", "infiniband", "/devices/foo/infiniband/mlx5_1"),
                      etc, "10-vendor.conf", ACCEPT_TRUST_LEVEL_DEFAULT);
        assert_config(lookup(ctx, "0000:01:00.0", "pci", pci_devpath), run, "15-runtime.conf", ACCEPT_TRUST_LEVEL_FULL);
        ASSERT_NULL(lookup(ctx, "mlx5_0", "infiniband", "/devices/foo/infiniband/mlx5_0"));
        ASSERT_NULL(lookup(ctx, "foo", "platform", "/devices/platform/foo"));

        ASSERT_NOT_NULL(masked = path_join(etc, "10-vendor.conf"));
        ASSERT_OK_ERRNO(unlink(masked));
        ASSERT_OK_ERRNO(symlink("/dev/null", masked));
        ASSERT_OK(accept_config_load(ctx));
        ASSERT_NULL(lookup(ctx, "mlx5_1", "infiniband", "/devices/foo/infiniband/mlx5_1"));
        ASSERT_NULL(lookup(ctx, "mlx5_0", "infiniband", "/devices/foo/infiniband/mlx5_0"));
        assert_config(lookup(ctx, "0000:01:00.0", "pci", pci_devpath), run, "15-runtime.conf", ACCEPT_TRUST_LEVEL_FULL);

        ASSERT_OK_ERRNO(unlink(masked));
        ASSERT_OK(touch(masked));
        ASSERT_OK(accept_config_load(ctx));
        ASSERT_NULL(lookup(ctx, "mlx5_0", "infiniband", "/devices/foo/infiniband/mlx5_0"));

        ASSERT_OK_ERRNO(unlink(masked));
        ASSERT_OK(accept_config_load(ctx));
        assert_config(lookup(ctx, "0000:01:00.0", "pci", pci_devpath),
                      usr, "10-vendor.conf", ACCEPT_TRUST_LEVEL_DISABLED);

        write_file(run, "20-local.conf.d/50-override.conf",
                   "[Match]\n"
                   "Device=\n"
                   "Device=name:wlan0 name:wlan1\n"
                   "\n"
                   "[Accept]\n"
                   "TrustLevel=full\n");
        ASSERT_NOT_NULL(dropin = path_join(run, "20-local.conf.d/50-override.conf"));
        ASSERT_OK(accept_config_load(ctx));
        ASSERT_NULL(lookup(ctx, "eth0", "net", "/devices/foo/net/eth0"));
        ASSERT_NULL(lookup(ctx, "0000:02:00.0", "pci", "/devices/pci0000:00/0000:02:00.0"));

        const AcceptConfig *config = lookup(ctx, "wlan1", "net", "/devices/foo/net/wlan1");
        assert_config(config, etc, "20-local.conf", ACCEPT_TRUST_LEVEL_FULL);
        ASSERT_EQ(strv_length(config->dropins), 1u);
        ASSERT_STREQ(config->dropins[0], dropin);

        write_file(etc, "30-orphan.conf.d/50-orphan.conf",
                   "[Match]\n"
                   "Device=name:orphan\n"
                   "\n"
                   "[Accept]\n"
                   "TrustLevel=full\n");
        ASSERT_OK(accept_config_load(ctx));
        ASSERT_NULL(lookup(ctx, "orphan", "net", "/devices/foo/net/orphan"));

        write_file(etc, "40-other.conf.bak",
                   "[Match]\n"
                   "Device=name:backup\n"
                   "\n"
                   "[Accept]\n"
                   "TrustLevel=full\n");
        ASSERT_OK(accept_config_load(ctx));
        ASSERT_NULL(lookup(ctx, "backup", "net", "/devices/foo/net/backup"));
}

TEST(config_invalid) {
        _cleanup_(rm_rf_physical_and_freep) char *root = NULL;
        _cleanup_(accept_config_ctx_freep) AcceptConfigContext *ctx = NULL;
        _cleanup_strv_free_ char **dirs = NULL;

        ASSERT_OK(mkdtemp_malloc("/tmp/test-accept-config-XXXXXX", &root));

        const char *etc = strjoina(root, "/etc");
        ASSERT_NOT_NULL(dirs = strv_new(etc));

        write_file(etc, "10-bad-level.conf",
                   "[Match]\nDevice=name:bad1\n\n[Accept]\nTrustLevel=paranoid\n");
        write_file(etc, "11-bad-case.conf",
                   "[Match]\nDevice=name:bad2\n\n[Accept]\nTrustLevel=Full\n");
        write_file(etc, "12-no-level.conf",
                   "[Match]\nDevice=name:bad3\n");
        write_file(etc, "13-reset-level.conf",
                   "[Match]\nDevice=name:bad4\n\n[Accept]\nTrustLevel=full\nTrustLevel=\n");
        write_file(etc, "14-no-device.conf",
                   "[Accept]\nTrustLevel=full\n");
        write_file(etc, "15-reset-device.conf",
                   "[Match]\nDevice=name:bad5\nDevice=\n\n[Accept]\nTrustLevel=full\n");
        write_file(etc, "16-other-keys.conf",
                   "[Match]\nName=bad6\nPCIAddress=0000:01:00.0\nPath=/sys/devices/foo\n\n[Accept]\nTrustLevel=full\n");
        write_file(etc, "17-other-section.conf",
                   "[Other]\nDevice=name:bad7\nTrustLevel=full\n");
        write_file(etc, "20-mixed.conf",
                   "[Match]\n"
                   "Device=ghost0 pci:zz name:good1 path:/sys/class/net/lo name:good2\n"
                   "\n"
                   "[Accept]\n"
                   "TrustLevel=adversary\n");
        write_file(etc, "21-later-invalid.conf",
                   "[Match]\nDevice=name:good3\n\n[Accept]\nTrustLevel=full\nTrustLevel=bogus\n");
        write_file(etc, "22-quoting.conf",
                   "[Match]\nDevice=  \"name:good4\"   'name:good5'\t name:good6 \n\n[Accept]\nTrustLevel=disabled\n");
        write_file(etc, "23-escape.conf",
                   "[Match]\nDevice=name:good\\*7\n\n[Accept]\nTrustLevel=disabled\n");

        ASSERT_OK(accept_config_ctx_new(dirs, &ctx));
        ASSERT_OK(accept_config_load(ctx));
        ASSERT_FALSE(accept_config_is_empty(ctx));

        FOREACH_STRING(name, "bad1", "bad2", "bad3", "bad4", "bad5", "bad6", "bad7", "ghost0", "lo", "orphan")
                ASSERT_NULL(lookup(ctx, name, "net", "/devices/virtual/net/lo"));

        assert_config(lookup(ctx, "good1", "net", "/devices/foo"), etc, "20-mixed.conf", ACCEPT_TRUST_LEVEL_ADVERSARY);
        assert_config(lookup(ctx, "good2", "net", "/devices/foo"), etc, "20-mixed.conf", ACCEPT_TRUST_LEVEL_ADVERSARY);
        assert_config(lookup(ctx, "good3", "net", "/devices/foo"),
                      etc, "21-later-invalid.conf", ACCEPT_TRUST_LEVEL_FULL);
        assert_config(lookup(ctx, "good4", "net", "/devices/foo"), etc, "22-quoting.conf", ACCEPT_TRUST_LEVEL_DISABLED);
        assert_config(lookup(ctx, "good5", "net", "/devices/foo"), etc, "22-quoting.conf", ACCEPT_TRUST_LEVEL_DISABLED);
        assert_config(lookup(ctx, "good6", "net", "/devices/foo"), etc, "22-quoting.conf", ACCEPT_TRUST_LEVEL_DISABLED);
        assert_config(lookup(ctx, "good*7", "net", "/devices/foo"), etc, "23-escape.conf", ACCEPT_TRUST_LEVEL_DISABLED);
        ASSERT_NULL(lookup(ctx, "good77", "net", "/devices/foo"));
}

TEST(config_missing_dirs) {
        _cleanup_(accept_config_ctx_freep) AcceptConfigContext *ctx = NULL;
        _cleanup_strv_free_ char **dirs = NULL;

        ASSERT_NOT_NULL(dirs = strv_new("/nonexistent/test-accept-config/a", "/nonexistent/test-accept-config/b"));
        ASSERT_OK(accept_config_ctx_new(dirs, &ctx));
        ASSERT_OK(accept_config_load(ctx));
        ASSERT_TRUE(accept_config_is_empty(ctx));
        ASSERT_NULL(lookup(ctx, "eth0", "net", "/devices/foo/net/eth0"));

        ctx = accept_config_ctx_free(ctx);
        ASSERT_OK(accept_config_ctx_new(/* dirs= */ NULL, &ctx));
        ASSERT_OK(accept_config_load(ctx));
}

#define FAKE_DEVICES_DIR "/sys/devices/test-accept-config"
#define FAKE_ATTRIBUTE_FILE_MTIME 1

/* Unlike in sysfs, a write overwrites only the start of the file, so initial values must not be longer. */
static void fake_device_create(const char *name, const char *trust_level) {
        _cleanup_free_ char *syspath = NULL, *uevent = NULL, *attribute = NULL;

        ASSERT_NOT_NULL(syspath = path_join(FAKE_DEVICES_DIR, name));
        ASSERT_NOT_NULL(uevent = path_join(syspath, "uevent"));
        ASSERT_NOT_NULL(attribute = path_join(syspath, "trust_policy"));

        ASSERT_OK(mkdir_p(syspath, 0755));
        ASSERT_OK(touch(uevent));
        write_file(syspath, "trust", "disabled\n");

        if (trust_level) {
                ASSERT_OK(write_string_file(attribute, trust_level,
                                            WRITE_STRING_FILE_CREATE|WRITE_STRING_FILE_TRUNCATE));

                struct timespec ts[2] = {
                        { .tv_sec = FAKE_ATTRIBUTE_FILE_MTIME },
                        { .tv_sec = FAKE_ATTRIBUTE_FILE_MTIME },
                };
                ASSERT_OK_ERRNO(utimensat(AT_FDCWD, attribute, ts, 0));
        }
}

static void fake_device_new(const char *name, const char *trust_level, sd_device **ret) {
        _cleanup_free_ char *syspath = NULL;

        fake_device_create(name, trust_level);

        ASSERT_NOT_NULL(syspath = path_join(FAKE_DEVICES_DIR, name));
        ASSERT_OK(sd_device_new_from_syspath(ret, syspath));
}

static void fake_device_check(const char *name, const char *expected, bool written) {
        _cleanup_free_ char *attribute = NULL, *value = NULL;
        struct stat st;

        ASSERT_NOT_NULL(attribute = path_join(FAKE_DEVICES_DIR, name, "trust_policy"));
        ASSERT_OK(read_one_line_file(attribute, &value));
        ASSERT_STREQ(value, expected);

        ASSERT_OK_ERRNO(stat(attribute, &st));
        ASSERT_TRUE((st.st_mtim.tv_sec != FAKE_ATTRIBUTE_FILE_MTIME) == written);
}

static void fake_subsystem_device_create(const char *name, const char *trust_level, bool on_bus) {
        _cleanup_free_ char *syspath = NULL, *subsystem = NULL, *link = NULL;

        fake_device_create(name, trust_level);

        ASSERT_NOT_NULL(syspath = path_join(FAKE_DEVICES_DIR, name));
        ASSERT_NOT_NULL(subsystem = path_join(syspath, "subsystem"));
        ASSERT_OK_ERRNO(symlink("/sys/bus/test", subsystem));

        if (!on_bus)
                return;

        ASSERT_NOT_NULL(link = path_join("/sys/bus/test/devices", name));
        ASSERT_OK(mkdir_parents(link, 0755));
        ASSERT_OK_ERRNO(symlink(syspath, link));
}

TEST(apply) {
        int r;

        if (getuid() != 0 || have_effective_cap(CAP_SYS_ADMIN) <= 0)
                return (void) log_tests_skipped("Not privileged");
        if (running_in_chroot() > 0)
                return (void) log_tests_skipped("Running in chroot");

        r = ASSERT_OK(pidref_safe_fork(
                        "(apply)",
                        FORK_CLOSE_ALL_FDS|FORK_DEATHSIG_SIGTERM|FORK_REOPEN_LOG|FORK_LOG|FORK_WAIT|
                        FORK_NEW_MOUNTNS|FORK_MOUNTNS_SLAVE,
                        NULL));
        if (r > 0)
                return;

        ASSERT_OK_ERRNO(setenv("SYSTEMD_DEVICE_VERIFY_SYSFS", "0", /* overwrite= */ false));

        r = mount_nofollow_verbose(LOG_ERR, "tmpfs", "/sys/devices", "tmpfs", 0, NULL);
        if (ERRNO_IS_NEG_PRIVILEGE(r)) {
                log_tests_skipped("Lacking privileges to mount a tmpfs on /sys/devices");
                _exit(EXIT_SUCCESS);
        }
        ASSERT_OK(r);

        AcceptConfig config = {
                .filename = (char*) "/etc/systemd/accept.d/10-test.conf",
                .trust_level = ACCEPT_TRUST_LEVEL_ADVERSARY,
        };
        _cleanup_(sd_device_unrefp) sd_device *dev = NULL;

        fake_device_new("no-attribute", /* trust_level= */ NULL, &dev);
        ASSERT_ERROR(accept_config_apply(&config, dev, /* dry_run= */ false), ENOENT);
        ASSERT_ERROR(accept_config_apply(&config, dev, /* dry_run= */ true), ENOENT);
        dev = sd_device_unref(dev);

        fake_device_new("already-set", "adversary\n", &dev);
        ASSERT_OK(accept_config_apply(&config, dev, /* dry_run= */ false));
        dev = sd_device_unref(dev);
        fake_device_check("already-set", "adversary", /* written= */ false);

        fake_device_new("dry-run", "full\n", &dev);
        ASSERT_OK(accept_config_apply(&config, dev, /* dry_run= */ true));
        dev = sd_device_unref(dev);
        fake_device_check("dry-run", "full", /* written= */ false);

        fake_device_new("replaced", "full\n", &dev);
        ASSERT_OK(accept_config_apply(&config, dev, /* dry_run= */ false));

        const char *value;
        ASSERT_OK(sd_device_get_sysattr_value(dev, "trust_policy", &value));
        ASSERT_STREQ(value, "adversary");
        dev = sd_device_unref(dev);
        fake_device_check("replaced", "adversary", /* written= */ true);

        config.trust_level = ACCEPT_TRUST_LEVEL_DISABLED;
        fake_device_new("disabled", "full\n", &dev);
        ASSERT_OK(accept_config_apply(&config, dev, /* dry_run= */ false));
        dev = sd_device_unref(dev);
        fake_device_check("disabled", "disabled", /* written= */ true);

        config.trust_level = ACCEPT_TRUST_LEVEL_DEFAULT;
        fake_device_new("default", "full\n", &dev);
        ASSERT_OK(accept_config_apply(&config, dev, /* dry_run= */ false));
        dev = sd_device_unref(dev);
        fake_device_check("default", "default", /* written= */ true);

        config.trust_level = ACCEPT_TRUST_LEVEL_FULL;
        fake_device_new("full", "none\n", &dev);
        ASSERT_OK(accept_config_apply(&config, dev, /* dry_run= */ false));
        ASSERT_OK(sd_device_get_sysattr_value(dev, "trust", &value));
        ASSERT_STREQ(value, "disabled");
        dev = sd_device_unref(dev);
        fake_device_check("full", "full", /* written= */ true);

        fake_device_new("gb!raw0", "full\n", &dev);

        AcceptDeviceIdentity identity;
        _cleanup_(accept_selector_done) AcceptSelector selector = {};

        ASSERT_OK(sd_device_get_sysname(dev, &value));
        ASSERT_STREQ(value, "gb/raw0");
        ASSERT_OK(accept_device_identity_get(dev, &identity));
        ASSERT_STREQ(identity.sysname, "gb!raw0");
        ASSERT_OK(accept_selector_parse("name:gb!raw0", &selector));
        ASSERT_TRUE(accept_selector_matches(&selector, &identity));
        dev = sd_device_unref(dev);

        _cleanup_free_ char *attribute = NULL;
        ASSERT_NOT_NULL(attribute = path_join(FAKE_DEVICES_DIR, "unwritable", "trust_policy"));
        fake_device_new("unwritable", /* trust_level= */ NULL, &dev);
        ASSERT_OK(mkdir_p(attribute, 0755));
        ASSERT_ERROR(accept_config_apply(&config, dev, /* dry_run= */ false), EISDIR);
        dev = sd_device_unref(dev);

        fake_device_new("vanished", /* trust_level= */ NULL, &dev);
        ASSERT_OK(rm_rf(FAKE_DEVICES_DIR "/vanished", REMOVE_ROOT|REMOVE_PHYSICAL));
        ASSERT_ERROR(accept_config_apply(&config, dev, /* dry_run= */ false), ENODEV);

        _exit(EXIT_SUCCESS);
}

TEST(apply_all_empty) {
        _cleanup_(accept_config_ctx_freep) AcceptConfigContext *ctx = NULL;
        unsigned n_selected = UINT_MAX, n_failed = UINT_MAX;

        ASSERT_OK(accept_config_ctx_new(STRV_MAKE("/nonexistent/test-accept-config"), &ctx));
        ASSERT_OK(accept_config_load(ctx));
        ASSERT_OK(accept_config_apply_all(ctx, /* dry_run= */ false, /* report= */ NULL, &n_selected, &n_failed));
        ASSERT_EQ(n_selected, 0u);
        ASSERT_EQ(n_failed, 0u);
}

static void apply_all_check(
                AcceptConfigContext *ctx,
                bool dry_run,
                const char *config_filename,
                unsigned expected_failed) {

        _cleanup_free_ char *buf = NULL, *expected = NULL;
        unsigned n_selected = UINT_MAX, n_failed = UINT_MAX;
        size_t size = 0;

        _cleanup_fclose_ FILE *report = open_memstream(&buf, &size);
        ASSERT_NOT_NULL(report);

        ASSERT_OK(accept_config_apply_all(ctx, dry_run, report, &n_selected, &n_failed));
        ASSERT_OK_ZERO_ERRNO(fflush(report));

        ASSERT_EQ(n_selected, 3u);
        ASSERT_EQ(n_failed, expected_failed);

        ASSERT_OK(asprintf(&expected,
                           FAKE_DEVICES_DIR "/sel-a: adversary (%1$s)\n"
                           FAKE_DEVICES_DIR "/sel-b: adversary (%1$s)\n"
                           FAKE_DEVICES_DIR "/sel-c: adversary (%1$s)\n",
                           config_filename));
        ASSERT_STREQ(buf, expected);
}

TEST(apply_all) {
        _cleanup_(rm_rf_physical_and_freep) char *root = NULL;
        _cleanup_(accept_config_ctx_freep) AcceptConfigContext *ctx = NULL;
        _cleanup_strv_free_ char **dirs = NULL;
        _cleanup_free_ char *filename = NULL;
        int r;

        if (getuid() != 0 || have_effective_cap(CAP_SYS_ADMIN) <= 0)
                return (void) log_tests_skipped("Not privileged");
        if (running_in_chroot() > 0)
                return (void) log_tests_skipped("Running in chroot");

        ASSERT_OK(mkdtemp_malloc("/tmp/test-accept-config-XXXXXX", &root));

        const char *etc = strjoina(root, "/etc");
        ASSERT_NOT_NULL(dirs = strv_new(etc));
        ASSERT_NOT_NULL(filename = path_join(etc, "10-test.conf"));

        write_file(etc, "10-test.conf",
                   "[Match]\n"
                   "Device=name:sel-*\n"
                   "\n"
                   "[Accept]\n"
                   "TrustLevel=adversary\n");

        ASSERT_OK(accept_config_ctx_new(dirs, &ctx));
        ASSERT_OK(accept_config_load(ctx));

        r = ASSERT_OK(pidref_safe_fork(
                        "(apply-all)",
                        FORK_CLOSE_ALL_FDS|FORK_DEATHSIG_SIGTERM|FORK_REOPEN_LOG|FORK_LOG|FORK_WAIT|
                        FORK_NEW_MOUNTNS|FORK_MOUNTNS_SLAVE,
                        NULL));
        if (r > 0)
                return;

        ASSERT_OK_ERRNO(setenv("SYSTEMD_DEVICE_VERIFY_SYSFS", "0", /* overwrite= */ false));

        r = mount_nofollow_verbose(LOG_ERR, "tmpfs", "/sys/devices", "tmpfs", 0, NULL);
        if (ERRNO_IS_NEG_PRIVILEGE(r)) {
                log_tests_skipped("Lacking privileges to mount a tmpfs on /sys/devices");
                _exit(EXIT_SUCCESS);
        }
        ASSERT_OK(r);
        ASSERT_OK(mount_nofollow_verbose(LOG_ERR, "tmpfs", "/sys/bus", "tmpfs", 0, NULL));
        ASSERT_OK(mount_nofollow_verbose(LOG_ERR, "tmpfs", "/sys/class", "tmpfs", 0, NULL));

        static const struct {
                const char *name;
                const char *trust_level;
        } devices[] = {
                { "sel-a", "full\n"      },
                { "sel-b", "adversary\n" },
                { "sel-c", NULL          },
                { "other", "full\n"      },
        };

        FOREACH_ELEMENT(d, devices)
                fake_subsystem_device_create(d->name, d->trust_level, /* on_bus= */ true);

        apply_all_check(ctx, /* dry_run= */ true, filename, /* expected_failed= */ 1);
        fake_device_check("sel-a", "full", /* written= */ false);
        fake_device_check("sel-b", "adversary", /* written= */ false);
        fake_device_check("other", "full", /* written= */ false);

        apply_all_check(ctx, /* dry_run= */ false, filename, /* expected_failed= */ 1);
        fake_device_check("sel-a", "adversary", /* written= */ true);
        fake_device_check("sel-b", "adversary", /* written= */ false);
        fake_device_check("other", "full", /* written= */ false);

        _cleanup_(sd_device_unrefp) sd_device *dev = NULL;
        _cleanup_free_ char *buf = NULL, *expected = NULL;
        size_t size = 0;

        _cleanup_fclose_ FILE *report = open_memstream(&buf, &size);
        ASSERT_NOT_NULL(report);

        ASSERT_OK(sd_device_new_from_syspath(&dev, FAKE_DEVICES_DIR "/other"));
        ASSERT_OK_ZERO(accept_config_apply_device(ctx, dev, /* dry_run= */ false, report));
        dev = sd_device_unref(dev);
        fake_device_check("other", "full", /* written= */ false);

        ASSERT_OK(sd_device_new_from_syspath(&dev, FAKE_DEVICES_DIR "/sel-c"));
        ASSERT_ERROR(accept_config_apply_device(ctx, dev, /* dry_run= */ false, report), ENOENT);
        dev = sd_device_unref(dev);

        fake_device_new("sel-d", "full\n", &dev);
        ASSERT_OK_EQ(accept_config_apply_device(ctx, dev, /* dry_run= */ true, report), 1);
        fake_device_check("sel-d", "full", /* written= */ false);
        ASSERT_OK_EQ(accept_config_apply_device(ctx, dev, /* dry_run= */ false, report), 1);
        dev = sd_device_unref(dev);
        fake_device_check("sel-d", "adversary", /* written= */ true);

        ASSERT_OK_ZERO_ERRNO(fflush(report));
        ASSERT_OK(asprintf(&expected,
                           FAKE_DEVICES_DIR "/sel-c: adversary (%1$s)\n"
                           FAKE_DEVICES_DIR "/sel-d: adversary (%1$s)\n"
                           FAKE_DEVICES_DIR "/sel-d: adversary (%1$s)\n",
                           filename));
        ASSERT_STREQ(buf, expected);

        _exit(EXIT_SUCCESS);
}

TEST(config_parse_accept_buses) {
        _cleanup_strv_free_ char **buses = NULL;

        ASSERT_OK(config_parse_accept_buses(NULL, "test.conf", 1, "DeviceAccept", 1, "HoldProbing", 0,
                                            "pci usb", &buses, NULL));
        ASSERT_TRUE(strv_equal(buses, STRV_MAKE("pci", "usb")));

        ASSERT_OK(config_parse_accept_buses(NULL, "test.conf", 2, "DeviceAccept", 1, "HoldProbing", 0,
                                            "netdevsim pci .. . \"\" foo/bar \"mdio_bus\"", &buses, NULL));
        ASSERT_TRUE(strv_equal(buses, STRV_MAKE("pci", "usb", "netdevsim", "mdio_bus")));

        ASSERT_OK(config_parse_accept_buses(NULL, "test.conf", 3, "DeviceAccept", 1, "HoldProbing", 0,
                                            "platform \"unterminated", &buses, NULL));
        ASSERT_TRUE(strv_equal(buses, STRV_MAKE("pci", "usb", "netdevsim", "mdio_bus", "platform")));

        ASSERT_OK(config_parse_accept_buses(NULL, "test.conf", 4, "DeviceAccept", 1, "HoldProbing", 0,
                                            "", &buses, NULL));
        ASSERT_TRUE(strv_isempty(buses));
}

static void fake_bus_mount(void) {
        int r;

        r = mount_nofollow_verbose(LOG_ERR, "tmpfs", "/sys/devices", "tmpfs", 0, NULL);
        if (ERRNO_IS_NEG_PRIVILEGE(r)) {
                log_tests_skipped("Lacking privileges to mount a tmpfs on /sys/devices");
                _exit(EXIT_SUCCESS);
        }
        ASSERT_OK(r);
        ASSERT_OK(mount_nofollow_verbose(LOG_ERR, "tmpfs", "/sys/bus", "tmpfs", 0, NULL));

        ASSERT_OK(write_string_file("/sys/bus/test/drivers_autoprobe", "1", WRITE_STRING_FILE_CREATE|WRITE_STRING_FILE_MKDIR_0755));
        ASSERT_OK(touch("/sys/bus/test/drivers_probe"));
}

static void fake_bus_check(const char *attribute, const char *expected) {
        _cleanup_free_ char *path = NULL, *value = NULL;

        ASSERT_NOT_NULL(path = path_join("/sys/bus/test", attribute));
        ASSERT_OK(read_one_line_file(path, &value));
        ASSERT_STREQ(value, expected);

        /* A write replaces the value of a sysfs attribute, but not of a regular file. */
        ASSERT_OK_ERRNO(truncate(path, 0));
}

TEST(bus_autoprobe) {
        int r;

        if (getuid() != 0 || have_effective_cap(CAP_SYS_ADMIN) <= 0)
                return (void) log_tests_skipped("Not privileged");
        if (running_in_chroot() > 0)
                return (void) log_tests_skipped("Running in chroot");

        r = ASSERT_OK(pidref_safe_fork(
                        "(bus-autoprobe)",
                        FORK_CLOSE_ALL_FDS|FORK_DEATHSIG_SIGTERM|FORK_REOPEN_LOG|FORK_LOG|FORK_WAIT|
                        FORK_NEW_MOUNTNS|FORK_MOUNTNS_SLAVE,
                        NULL));
        if (r > 0)
                return;

        fake_bus_mount();
        ASSERT_OK_EQ(accept_bus_get_autoprobe("test"), 1);
        ASSERT_OK_ERRNO(truncate("/sys/bus/test/drivers_autoprobe", 0));

        ASSERT_OK(accept_bus_set_autoprobe("test", /* enable= */ false));
        ASSERT_OK_ZERO(accept_bus_get_autoprobe("test"));
        fake_bus_check("drivers_autoprobe", "0");
        ASSERT_OK(accept_bus_set_autoprobe("test", /* enable= */ true));
        ASSERT_OK_EQ(accept_bus_get_autoprobe("test"), 1);
        fake_bus_check("drivers_autoprobe", "1");

        ASSERT_ERROR(accept_bus_get_autoprobe("nonexistent"), ENOENT);
        ASSERT_ERROR(accept_bus_get_autoprobe(".."), EINVAL);
        ASSERT_ERROR(accept_bus_set_autoprobe("nonexistent", /* enable= */ false), ENOENT);
        ASSERT_ERROR(accept_bus_set_autoprobe("..", /* enable= */ false), EINVAL);
        ASSERT_ERROR(accept_bus_set_autoprobe("test/..", /* enable= */ false), EINVAL);

        _exit(EXIT_SUCCESS);
}

static int bind_one(const AcceptConfig *config, const char *name) {
        _cleanup_(sd_device_unrefp) sd_device *dev = NULL;
        _cleanup_free_ char *syspath = NULL;

        ASSERT_NOT_NULL(syspath = path_join(FAKE_DEVICES_DIR, name));
        ASSERT_OK(sd_device_new_from_syspath(&dev, syspath));

        return accept_device_bind(config, dev);
}

TEST(bind) {
        int r;

        if (getuid() != 0 || have_effective_cap(CAP_SYS_ADMIN) <= 0)
                return (void) log_tests_skipped("Not privileged");
        if (running_in_chroot() > 0)
                return (void) log_tests_skipped("Running in chroot");

        r = ASSERT_OK(pidref_safe_fork(
                        "(bind)",
                        FORK_CLOSE_ALL_FDS|FORK_DEATHSIG_SIGTERM|FORK_REOPEN_LOG|FORK_LOG|FORK_WAIT|
                        FORK_NEW_MOUNTNS|FORK_MOUNTNS_SLAVE,
                        NULL));
        if (r > 0)
                return;

        ASSERT_OK_ERRNO(setenv("SYSTEMD_DEVICE_VERIFY_SYSFS", "0", /* overwrite= */ false));
        fake_bus_mount();

        AcceptConfig config = {
                .filename = (char*) "/etc/systemd/accept.d/10-test.conf",
                .trust_level = ACCEPT_TRUST_LEVEL_FULL,
        };
        const char *bus;

        fake_subsystem_device_create("unselected", "full\n", /* on_bus= */ true);
        ASSERT_OK_EQ(bind_one(/* config= */ NULL, "unselected"), ACCEPT_BIND_NO_DRIVER);
        fake_bus_check("drivers_probe", "unselected");
        fake_device_check("unselected", "full", /* written= */ false);

        fake_subsystem_device_create("selected", "none\n", /* on_bus= */ true);
        ASSERT_OK_EQ(bind_one(&config, "selected"), ACCEPT_BIND_NO_DRIVER);
        fake_bus_check("drivers_probe", "selected");
        fake_device_check("selected", "full", /* written= */ true);

        fake_subsystem_device_create("bound", "none\n", /* on_bus= */ true);
        ASSERT_OK_ERRNO(symlink("../../bus/test/drivers/test-driver", FAKE_DEVICES_DIR "/bound/driver"));
        ASSERT_OK_EQ(bind_one(&config, "bound"), ACCEPT_BIND_BOUND);
        fake_bus_check("drivers_probe", "bound");

        config.trust_level = ACCEPT_TRUST_LEVEL_DISABLED;
        fake_subsystem_device_create("disabled", "full\n", /* on_bus= */ true);
        ASSERT_OK_EQ(bind_one(&config, "disabled"), ACCEPT_BIND_REFUSED);
        fake_bus_check("drivers_probe", "");
        fake_device_check("disabled", "disabled", /* written= */ true);

        config.trust_level = ACCEPT_TRUST_LEVEL_ADVERSARY;
        fake_subsystem_device_create("no-attribute", /* trust_level= */ NULL, /* on_bus= */ true);
        ASSERT_ERROR(bind_one(&config, "no-attribute"), ENOENT);
        fake_bus_check("drivers_probe", "");

        fake_subsystem_device_create("class", "full\n", /* on_bus= */ false);
        _cleanup_(sd_device_unrefp) sd_device *dev = NULL;
        ASSERT_OK(sd_device_new_from_syspath(&dev, FAKE_DEVICES_DIR "/class"));
        ASSERT_ERROR(accept_device_get_bus(dev, &bus), ENOENT);
        ASSERT_ERROR(bind_one(/* config= */ NULL, "class"), ENOENT);
        fake_bus_check("drivers_probe", "");
        dev = sd_device_unref(dev);

        ASSERT_OK(sd_device_new_from_syspath(&dev, FAKE_DEVICES_DIR "/selected"));
        ASSERT_OK(accept_device_get_bus(dev, &bus));
        ASSERT_STREQ(bus, "test");

        _exit(EXIT_SUCCESS);
}

static unsigned n_steps = 0;

static int step_done(AcceptDevice *d) {
        n_steps++;
        return 0;
}

static int step_unavailable(AcceptDevice *d) {
        n_steps++;
        return -EOPNOTSUPP;
}

static int step_fail(AcceptDevice *d) {
        n_steps++;
        return -EPERM;
}

static int step_unexpected(AcceptDevice *d) {
        assert_not_reached();
}

static AcceptDevice* flow_device_new(const char *name, const char *trust_level, const AcceptConfig *config) {
        _cleanup_(sd_device_unrefp) sd_device *dev = NULL;
        _cleanup_free_ char *syspath = NULL;
        AcceptDevice *d;

        fake_subsystem_device_create(name, trust_level, /* on_bus= */ true);

        ASSERT_NOT_NULL(syspath = path_join(FAKE_DEVICES_DIR, name));
        ASSERT_OK(sd_device_new_from_syspath(&dev, syspath));
        ASSERT_OK(accept_device_new(dev, config, &d));
        ASSERT_EQ(d->state, ACCEPT_STATE_CONNECT);

        return d;
}

TEST(flow) {
        int r;

        if (getuid() != 0 || have_effective_cap(CAP_SYS_ADMIN) <= 0)
                return (void) log_tests_skipped("Not privileged");
        if (running_in_chroot() > 0)
                return (void) log_tests_skipped("Running in chroot");

        r = ASSERT_OK(pidref_safe_fork(
                        "(flow)",
                        FORK_CLOSE_ALL_FDS|FORK_DEATHSIG_SIGTERM|FORK_REOPEN_LOG|FORK_LOG|FORK_WAIT|
                        FORK_NEW_MOUNTNS|FORK_MOUNTNS_SLAVE,
                        NULL));
        if (r > 0)
                return;

        ASSERT_OK_ERRNO(setenv("SYSTEMD_DEVICE_VERIFY_SYSFS", "0", /* overwrite= */ false));
        fake_bus_mount();

        AcceptConfig config = {
                .filename = (char*) "/etc/systemd/accept.d/10-test.conf",
                .trust_level = ACCEPT_TRUST_LEVEL_FULL,
        };
        const AcceptStep done[_ACCEPT_STEP_MAX] = {
                [ACCEPT_STATE_CONNECT] = step_done,
                [ACCEPT_STATE_MEASURE] = step_done,
                [ACCEPT_STATE_LOG]     = step_done,
                [ACCEPT_STATE_EXTEND]  = step_done,
                [ACCEPT_STATE_VERIFY]  = step_done,
                [ACCEPT_STATE_RUN]     = step_done,
        };
        const AcceptStep fail_verify[_ACCEPT_STEP_MAX] = {
                [ACCEPT_STATE_CONNECT] = step_done,
                [ACCEPT_STATE_MEASURE] = step_unavailable,
                [ACCEPT_STATE_LOG]     = step_done,
                [ACCEPT_STATE_EXTEND]  = step_done,
                [ACCEPT_STATE_VERIFY]  = step_fail,
                [ACCEPT_STATE_RUN]     = step_unexpected,
        };
        const AcceptStep unexpected[_ACCEPT_STEP_MAX] = {
                [ACCEPT_STATE_CONNECT] = step_unexpected,
                [ACCEPT_STATE_MEASURE] = step_unexpected,
                [ACCEPT_STATE_LOG]     = step_unexpected,
                [ACCEPT_STATE_EXTEND]  = step_unexpected,
                [ACCEPT_STATE_VERIFY]  = step_unexpected,
                [ACCEPT_STATE_RUN]     = step_unexpected,
        };
        _cleanup_(accept_device_freep) AcceptDevice *d = NULL;

        d = flow_device_new("default-steps", "none\n", &config);
        ASSERT_EQ(accept_device_run(d, accept_steps), ACCEPT_STATE_WAITING);
        fake_bus_check("drivers_probe", "default-steps");
        fake_device_check("default-steps", "full", /* written= */ true);

        ASSERT_OK_ERRNO(symlink("../../bus/test/drivers/test-driver", FAKE_DEVICES_DIR "/default-steps/driver"));
        ASSERT_EQ(accept_device_run(d, accept_steps), ACCEPT_STATE_BOUND);
        fake_bus_check("drivers_probe", "default-steps");

        ASSERT_EQ(accept_device_run(d, accept_steps), ACCEPT_STATE_BOUND);
        fake_bus_check("drivers_probe", "");
        d = accept_device_free(d);

        n_steps = 0;
        d = flow_device_new("all-steps", "none\n", &config);
        ASSERT_EQ(accept_device_run(d, done), ACCEPT_STATE_WAITING);
        ASSERT_EQ(n_steps, (unsigned) _ACCEPT_STEP_MAX);
        fake_bus_check("drivers_probe", "all-steps");
        d = accept_device_free(d);

        n_steps = 0;
        d = flow_device_new("rejected", "full\n", &config);
        ASSERT_EQ(accept_device_run(d, fail_verify), ACCEPT_STATE_REJECTED);
        ASSERT_EQ(n_steps, 5u);
        fake_bus_check("drivers_probe", "");
        fake_device_check("rejected", "disabled", /* written= */ true);

        ASSERT_EQ(accept_device_run(d, fail_verify), ACCEPT_STATE_REJECTED);
        ASSERT_EQ(n_steps, 5u);
        d = accept_device_free(d);

        d = flow_device_new("unselected", "full\n", /* config= */ NULL);
        ASSERT_EQ(accept_device_run(d, unexpected), ACCEPT_STATE_WAITING);
        fake_bus_check("drivers_probe", "unselected");
        fake_device_check("unselected", "full", /* written= */ false);
        d = accept_device_free(d);

        n_steps = 0;
        config.trust_level = ACCEPT_TRUST_LEVEL_DISABLED;
        d = flow_device_new("disabled", "full\n", &config);
        ASSERT_EQ(accept_device_run(d, done), ACCEPT_STATE_REJECTED);
        ASSERT_EQ(n_steps, (unsigned) _ACCEPT_STEP_MAX);
        fake_bus_check("drivers_probe", "");
        fake_device_check("disabled", "disabled", /* written= */ true);
        d = accept_device_free(d);

        config.trust_level = ACCEPT_TRUST_LEVEL_FULL;
        d = flow_device_new("no-attribute", /* trust_level= */ NULL, &config);
        ASSERT_EQ(accept_device_run(d, done), ACCEPT_STATE_REJECTED);
        fake_bus_check("drivers_probe", "");

        _exit(EXIT_SUCCESS);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
