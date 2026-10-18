/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "device-private.h"
#include "rm-rf.h"
#include "tests.h"
#include "tmpfile-util.h"

static char *test_state_dir = NULL;
int device_accept_main(int argc, char *argv[]);

#define AUTOPROBE_STATE_DIR test_state_dir
#define main device_accept_main
#include "device-accept-d.c"
#undef main

STATIC_DESTRUCTOR_REGISTER(test_state_dir, freep);

static int test_autoprobe = 1;
static bool test_bus_ready = true;
static int test_probe_result = 0;
static bool test_bind_on_probe = false;
static bool test_bound = false;
static unsigned test_probe_count = 0;
static unsigned test_autoprobe_writes = 0;

int __real_read_one_line_file_at(int fd, const char *fn, char **ret);
int __wrap_read_one_line_file_at(int fd, const char *fn, char **ret);
int __real_write_string_file_full_label(int fd, const char *fn, const char *line, WriteStringFileFlags flags,
                                      const struct timespec *ts, const char *label_fn, LabelContext *label_context);
int __wrap_write_string_file_full_label(int fd, const char *fn, const char *line, WriteStringFileFlags flags,
                                      const struct timespec *ts, const char *label_fn, LabelContext *label_context);
int __real_faccessat(int fd, const char *path, int mode, int flags);
int __wrap_faccessat(int fd, const char *path, int mode, int flags);
int __real_readlink_value(const char *path, char **ret);
int __wrap_readlink_value(const char *path, char **ret);
int __real_sd_device_new_from_syspath(sd_device **ret, const char *syspath);
int __wrap_sd_device_new_from_syspath(sd_device **ret, const char *syspath);
int __real_sd_device_get_driver(sd_device *device, const char **ret);
int __wrap_sd_device_get_driver(sd_device *device, const char **ret);

int __wrap_read_one_line_file_at(int fd, const char *fn, char **ret) {
        if (!streq(fn, "/sys/bus/test/drivers_autoprobe"))
                return __real_read_one_line_file_at(fd, fn, ret);
        if (!test_bus_ready)
                return -ENOENT;

        *ret = strdup(one_zero(test_autoprobe));
        return *ret ? 0 : -ENOMEM;
}

int __wrap_write_string_file_full_label(int fd, const char *fn, const char *line, WriteStringFileFlags flags,
                                      const struct timespec *ts, const char *label_fn, LabelContext *label_context) {
        if (streq(fn, "/sys/bus/test/drivers_autoprobe")) {
                test_autoprobe = ASSERT_OK(parse_boolean(line));
                test_autoprobe_writes++;
                return 0;
        }

        if (streq(fn, "/sys/bus/test/drivers_probe")) {
                test_probe_count++;
                if (test_probe_result < 0)
                        return test_probe_result;
                test_bound = test_bind_on_probe;
                return 0;
        }

        if (fn && startswith(fn, "/sys/"))
                return -EROFS;

        return __real_write_string_file_full_label(fd, fn, line, flags, ts, label_fn, label_context);
}

int __wrap_faccessat(int fd, const char *path, int mode, int flags) {
        if (startswith(path, "/sys/bus/test/devices/test-"))
                return 0;

        return __real_faccessat(fd, path, mode, flags);
}

int __wrap_readlink_value(const char *path, char **ret) {
        if (!startswith(path, "/sys/devices/test-") || !endswith(path, "/driver"))
                return __real_readlink_value(path, ret);
        if (!test_bound)
                return -ENOENT;

        *ret = strdup("test-driver");
        return *ret ? 0 : -ENOMEM;
}

static int test_device_new(sd_device **ret, const char *syspath, const char *subsystem, const char *action) {
        _cleanup_strv_free_ char **properties = NULL;
        int r;

        r = strv_extendf(&properties, "DEVPATH=%s", ASSERT_PTR(startswith(syspath, "/sys")));
        if (r < 0)
                return r;
        r = strv_extendf(&properties, "SUBSYSTEM=%s", subsystem);
        if (r < 0)
                return r;
        r = strv_extendf(&properties, "ACTION=%s", action);
        if (r < 0)
                return r;
        r = strv_extend(&properties, "SEQNUM=1");
        if (r < 0)
                return r;

        return device_new_from_strv(ret, properties);
}

int __wrap_sd_device_new_from_syspath(sd_device **ret, const char *syspath) {
        if (startswith(syspath, "/sys/devices/test-"))
                return test_device_new(ret, syspath, "test", "add");

        return __real_sd_device_new_from_syspath(ret, syspath);
}

int __wrap_sd_device_get_driver(sd_device *device, const char **ret) {
        const char *syspath;

        ASSERT_OK(sd_device_get_syspath(device, &syspath));
        if (!startswith(syspath, "/sys/devices/test-"))
                return __real_sd_device_get_driver(device, ret);
        if (!test_bound)
                return -ENOENT;

        if (ret)
                *ret = "test-driver";
        return 0;
}

static Manager* test_manager_new(const char *root) {
        _cleanup_(manager_freep) Manager *m = NULL;
        _cleanup_free_ char *config = NULL;
        _cleanup_strv_free_ char **dirs = NULL;

        ASSERT_NOT_NULL(m = new0(Manager, 1));
        ASSERT_OK(sd_event_new(&m->event));
        ASSERT_NOT_NULL(dirs = strv_new(root));
        ASSERT_NOT_NULL(config = path_join(root, "10-test.conf"));
        ASSERT_OK(write_string_file(config,
                                   "[Match]\nDevice=name:test-existing\n[Accept]\nTrustLevel=full\n",
                                   WRITE_STRING_FILE_CREATE));
        ASSERT_OK(accept_config_ctx_new(dirs, &m->ctx));
        ASSERT_OK(accept_config_load(m->ctx));
        ASSERT_NOT_NULL(m->hold_probing = strv_new("test"));

        free(test_state_dir);
        ASSERT_NOT_NULL(test_state_dir = path_join(root, "autoprobe"));
        test_autoprobe = 1;
        test_bus_ready = true;
        test_probe_result = 0;
        test_bind_on_probe = false;
        test_bound = false;
        test_probe_count = 0;
        test_autoprobe_writes = 0;
        return TAKE_PTR(m);
}

static AcceptDevice* test_add_device(Manager *m, const char *name, AcceptState state) {
        _cleanup_(sd_device_unrefp) sd_device *device = NULL;
        _cleanup_(accept_device_freep) AcceptDevice *d = NULL;
        _cleanup_free_ char *syspath = NULL;

        ASSERT_NOT_NULL(syspath = path_join("/sys/devices", name));
        ASSERT_OK(test_device_new(&device, syspath, "test", "add"));
        ASSERT_OK(accept_device_new(device, /* config= */ NULL, &d));
        d->state = state;
        ASSERT_OK(hashmap_ensure_put(&m->devices, &accept_device_hash_ops, d->syspath, d));
        return TAKE_PTR(d);
}

TEST(hold_restore_without_logging) {
        _cleanup_(rm_rf_physical_and_freep) char *root = NULL;
        _cleanup_(manager_freep) Manager *m = NULL;
        int saved_level = log_get_max_level();

        ASSERT_OK(mkdtemp_malloc("/tmp/test-device-accept-d-XXXXXX", &root));
        m = test_manager_new(root);

        log_set_max_level(LOG_WARNING);
        ASSERT_OK(manager_hold_bus(m, "test"));
        ASSERT_STREQ(hashmap_get(m->held, "test"), "1");
        ASSERT_EQ(test_autoprobe, 0);
        manager_release_bus(m, "test", /* restore= */ true);
        ASSERT_EQ(test_autoprobe, 1);
        ASSERT_TRUE(hashmap_isempty(m->held));

        ASSERT_OK(manager_hold_bus(m, "test"));
        m->held = hashmap_free(m->held);
        ASSERT_OK(manager_adopt_held_buses(m));
        ASSERT_STREQ(hashmap_get(m->held, "test"), "1");
        manager_release_bus(m, "test", /* restore= */ true);
        ASSERT_EQ(test_autoprobe, 1);
        log_set_max_level(saved_level);
}

TEST(bus_recreation) {
        _cleanup_(rm_rf_physical_and_freep) char *root = NULL;
        _cleanup_(manager_freep) Manager *m = NULL;
        _cleanup_(sd_device_unrefp) sd_device *bus = NULL;
        _cleanup_free_ char *state = NULL;
        unsigned writes;

        ASSERT_OK(mkdtemp_malloc("/tmp/test-device-accept-d-XXXXXX", &root));
        m = test_manager_new(root);
        ASSERT_OK(manager_hold_bus(m, "test"));
        ASSERT_NOT_NULL(state = path_join(test_state_dir, "test"));
        ASSERT_OK_ERRNO(access(state, F_OK));
        writes = test_autoprobe_writes;

        ASSERT_OK(test_device_new(&bus, "/sys/bus/test", "bus", "remove"));
        ASSERT_OK(on_uevent(/* monitor= */ NULL, bus, m));
        ASSERT_TRUE(hashmap_isempty(m->held));
        ASSERT_EQ(test_autoprobe_writes, writes);
        ASSERT_LT(access(state, F_OK), 0);
        ASSERT_EQ(errno, ENOENT);

        test_autoprobe = 1;
        ASSERT_OK(device_set_action(bus, SD_DEVICE_ADD));
        ASSERT_OK(on_uevent(/* monitor= */ NULL, bus, m));
        ASSERT_TRUE(hashmap_contains(m->held, "test"));
        ASSERT_EQ(test_autoprobe, 0);
        ASSERT_EQ(test_autoprobe_writes, writes + 1);
}

TEST(adopt_recreated_bus) {
        _cleanup_(rm_rf_physical_and_freep) char *root = NULL;
        _cleanup_(manager_freep) Manager *m = NULL;
        _cleanup_free_ char *state = NULL;

        ASSERT_OK(mkdtemp_malloc("/tmp/test-device-accept-d-XXXXXX", &root));
        m = test_manager_new(root);
        test_autoprobe = 0;
        ASSERT_OK(manager_hold_bus(m, "test"));
        ASSERT_NOT_NULL(state = path_join(test_state_dir, "test"));
        m->held = hashmap_free(m->held);

        test_autoprobe = 1;
        ASSERT_OK(manager_adopt_held_buses(m));
        ASSERT_TRUE(hashmap_isempty(m->held));
        ASSERT_LT(access(state, F_OK), 0);
        ASSERT_EQ(errno, ENOENT);
        ASSERT_OK(manager_hold_buses(m));
        ASSERT_STREQ(hashmap_get(m->held, "test"), "1");
        ASSERT_EQ(test_autoprobe, 0);
        manager_release_bus(m, "test", /* restore= */ true);
        ASSERT_EQ(test_autoprobe, 1);

        ASSERT_OK(manager_hold_bus(m, "test"));
        m->held = hashmap_free(m->held);
        test_bus_ready = false;
        ASSERT_OK(manager_adopt_held_buses(m));
        ASSERT_TRUE(hashmap_isempty(m->held));
        ASSERT_LT(access(state, F_OK), 0);
        ASSERT_EQ(errno, ENOENT);
        ASSERT_OK(manager_hold_buses(m));
        ASSERT_NOT_NULL(m->bus_retry_event_source);
}

TEST(bus_registration_before_probe_files) {
        _cleanup_(rm_rf_physical_and_freep) char *root = NULL;
        _cleanup_(manager_freep) Manager *m = NULL;
        _cleanup_(sd_device_unrefp) sd_device *bus = NULL;

        ASSERT_OK(mkdtemp_malloc("/tmp/test-device-accept-d-XXXXXX", &root));
        m = test_manager_new(root);
        test_bus_ready = false;
        ASSERT_OK(test_device_new(&bus, "/sys/bus/test", "bus", "add"));
        ASSERT_OK(on_uevent(/* monitor= */ NULL, bus, m));
        ASSERT_TRUE(hashmap_isempty(m->held));
        ASSERT_NOT_NULL(m->bus_retry_event_source);

        test_bus_ready = true;
        ASSERT_OK(sd_event_source_set_time(m->bus_retry_event_source, 0));
        ASSERT_GT(sd_event_run(m->event, USEC_PER_SEC), 0);
        ASSERT_TRUE(hashmap_contains(m->held, "test"));
        ASSERT_EQ(test_autoprobe, 0);
}

TEST(deferred_probe_and_fresh_device) {
        _cleanup_(rm_rf_physical_and_freep) char *root = NULL;
        _cleanup_(manager_freep) Manager *m = NULL;
        _cleanup_(sd_device_unrefp) sd_device *original = NULL;
        AcceptDevice *d, *waiting;

        ASSERT_OK(mkdtemp_malloc("/tmp/test-device-accept-d-XXXXXX", &root));
        m = test_manager_new(root);
        ASSERT_OK(manager_hold_bus(m, "test"));
        d = test_add_device(m, "test-retry", ACCEPT_STATE_CONNECT);
        waiting = test_add_device(m, "test-waiting", ACCEPT_STATE_WAITING);

        test_probe_result = -EAGAIN;
        ASSERT_EQ(accept_device_run(d, accept_steps), ACCEPT_STATE_RETRY);
        ASSERT_EQ(test_probe_count, 1u);
        original = sd_device_ref(d->device);
        manager_schedule_rescan(m, USEC_PER_SEC);
        ASSERT_NOT_NULL(m->rescan_event_source);
        ASSERT_OK(sd_event_source_set_time(m->rescan_event_source, 0));
        ASSERT_GT(sd_event_run(m->event, USEC_PER_SEC), 0);
        ASSERT_EQ(d->state, ACCEPT_STATE_RETRY);
        ASSERT_EQ(waiting->state, ACCEPT_STATE_WAITING);
        ASSERT_EQ(test_probe_count, 2u);
        ASSERT_TRUE(d->device != original);
        ASSERT_PTR_EQ(hashmap_get(m->devices, d->syspath), d);

        ASSERT_OK(sd_event_source_set_time(m->rescan_event_source, 0));
        manager_schedule_rescan(m, 0);
        ASSERT_FALSE(m->rescan_retry_only);
        m->rescan_retry_only = true;

        test_probe_result = 0;
        test_bind_on_probe = true;
        ASSERT_OK(sd_event_source_set_time(m->rescan_event_source, 0));
        ASSERT_GT(sd_event_run(m->event, USEC_PER_SEC), 0);
        ASSERT_EQ(d->state, ACCEPT_STATE_BOUND);
        ASSERT_EQ(test_probe_count, 3u);
}

TEST(unbind_waits_for_driver) {
        _cleanup_(rm_rf_physical_and_freep) char *root = NULL;
        _cleanup_(manager_freep) Manager *m = NULL;
        _cleanup_(sd_device_unrefp) sd_device *event = NULL;
        AcceptDevice *d;

        ASSERT_OK(mkdtemp_malloc("/tmp/test-device-accept-d-XXXXXX", &root));
        m = test_manager_new(root);
        ASSERT_OK(manager_hold_bus(m, "test"));
        d = test_add_device(m, "test-unbind", ACCEPT_STATE_BOUND);

        ASSERT_OK(test_device_new(&event, d->syspath, "test", "unbind"));
        ASSERT_OK(on_uevent(/* monitor= */ NULL, event, m));
        ASSERT_EQ(d->state, ACCEPT_STATE_UNBOUND);
        manager_schedule_rescan(m, USEC_PER_SEC);
        ASSERT_NULL(m->rescan_event_source);
        ASSERT_OK(device_set_action(event, SD_DEVICE_BIND));
        ASSERT_OK(on_uevent(/* monitor= */ NULL, event, m));
        ASSERT_NULL(m->rescan_event_source);

        event = sd_device_unref(event);
        ASSERT_OK(test_device_new(&event, "/sys/bus/test/drivers/test-driver", "drivers", "add"));
        test_bind_on_probe = true;
        ASSERT_OK(on_uevent(/* monitor= */ NULL, event, m));
        ASSERT_EQ(d->state, ACCEPT_STATE_CONNECT);
        ASSERT_GT(sd_event_run(m->event, USEC_PER_SEC), 0);
        ASSERT_EQ(d->state, ACCEPT_STATE_BOUND);
        ASSERT_EQ(test_probe_count, 1u);

        d->state = ACCEPT_STATE_UNBOUND;
        manager_forget_unbound(m);
        ASSERT_TRUE(hashmap_isempty(m->devices));

        event = sd_device_unref(event);
        test_bound = false;
        ASSERT_OK(test_device_new(&event, "/sys/devices/test-existing", "test", "unbind"));
        ASSERT_OK(on_uevent(/* monitor= */ NULL, event, m));
        ASSERT_NOT_NULL(d = hashmap_get(m->devices, "/sys/devices/test-existing"));
        ASSERT_EQ(d->state, ACCEPT_STATE_UNBOUND);
        ASSERT_NOT_NULL(d->config_file);

        event = sd_device_unref(event);
        ASSERT_OK(test_device_new(&event, "/sys/bus/test/drivers/test-driver", "drivers", "add"));
        ASSERT_OK(on_uevent(/* monitor= */ NULL, event, m));
        ASSERT_EQ(d->state, ACCEPT_STATE_CONNECT);
}

DEFINE_TEST_MAIN(LOG_INFO);
