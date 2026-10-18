/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <signal.h>
#include <stdio.h>

#include "sd-device.h"
#include "sd-event.h"
#include "sd-json.h"

#include "accept-bind.h"
#include "accept-config.h"
#include "accept-flow.h"
#include "alloc-util.h"
#include "build.h"
#include "conf-parser.h"
#include "daemon-util.h"
#include "device-enumerator-private.h"
#include "device-monitor-private.h"
#include "device-util.h"
#include "dirent-util.h"
#include "event-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "fs-util.h"
#include "hashmap.h"
#include "log.h"
#include "main-func.h"
#include "options.h"
#include "parse-util.h"
#include "path-util.h"
#include "string-util.h"
#include "strv.h"
#include "time-util.h"
#include "verbs.h"

#ifndef AUTOPROBE_STATE_DIR
#define AUTOPROBE_STATE_DIR "/run/systemd/device-accept/autoprobe"
#endif

static bool arg_dry_run = false;

COMMAND(
        "systemd-device-accept-d\0",
        "Apply the device acceptance configuration.",
        .man_pages = "systemd-device-accept-d.service(8)\0",
);

typedef struct Manager {
        sd_event *event;
        sd_device_monitor *monitor;
        AcceptConfigContext *ctx;

        char **hold_probing;
        Hashmap *held;
        sd_event_source *bus_retry_event_source;

        Hashmap *devices;
        sd_event_source *rescan_event_source;
        bool rescan_retry_only;
} Manager;

static void manager_schedule_rescan(Manager *m, usec_t delay);
static int on_bus_retry(sd_event_source *s, uint64_t usec, void *userdata);

/* The key is owned by AcceptDevice. */
DEFINE_PRIVATE_HASH_OPS_WITH_VALUE_DESTRUCTOR(
                accept_device_hash_ops,
                char, string_hash_func, string_compare_func,
                AcceptDevice, accept_device_free);

static void manager_release_bus(Manager *m, const char *bus, bool restore) {
        _cleanup_free_ char *b = NULL, *original = NULL, *state = NULL;
        int r;

        assert(m);
        assert(bus);

        original = hashmap_remove2(m->held, bus, (void**) &b);
        if (!original)
                return;

        if (restore) {
                r = accept_bus_set_autoprobe(b, /* enable= */ parse_boolean(original) > 0);
                if (r < 0)
                        log_warning_errno(r, "Failed to restore automatic driver probing for bus '%s', ignoring: %m", b);
                else
                        log_info("Restored automatic driver probing for bus '%s' to %s.", b, original);
        }

        state = path_join(AUTOPROBE_STATE_DIR, b);
        if (!state)
                return (void) log_oom();

        if (unlink(state) < 0 && errno != ENOENT)
                log_debug_errno(errno, "Failed to remove %s, ignoring: %m", state);
}

static Manager* manager_free(Manager *m) {
        const char *bus, *original;

        if (!m)
                return NULL;

        HASHMAP_FOREACH_KEY(original, bus, m->held)
                manager_release_bus(m, bus, /* restore= */ true);

        hashmap_free(m->held);
        strv_free(m->hold_probing);
        hashmap_free(m->devices);
        sd_event_source_unref(m->rescan_event_source);
        sd_event_source_unref(m->bus_retry_event_source);

        sd_device_monitor_unref(m->monitor);
        sd_event_unref(m->event);
        accept_config_ctx_free(m->ctx);

        return mfree(m);
}

DEFINE_TRIVIAL_CLEANUP_FUNC(Manager*, manager_free);

static int parse_config(char ***ret_hold_probing) {
        _cleanup_strv_free_ char **hold_probing = NULL;
        int r;

        assert(ret_hold_probing);

        const ConfigTableItem items[] = {
                { "DeviceAccept", "HoldProbing", config_parse_accept_buses, 0, &hold_probing },
                {}
        };

        r = config_parse_standard_file_with_dropins(
                        "systemd/device-accept.conf",
                        "DeviceAccept\0",
                        config_item_table_lookup, items,
                        CONFIG_PARSE_WARN,
                        /* userdata= */ NULL);
        if (r < 0)
                return r;

        *ret_hold_probing = TAKE_PTR(hold_probing);
        return 0;
}

static int config_load(AcceptConfigContext **ret) {
        _cleanup_(accept_config_ctx_freep) AcceptConfigContext *ctx = NULL;
        int r;

        assert(ret);

        r = accept_config_ctx_new(/* dirs= */ NULL, &ctx);
        if (r < 0)
                return log_oom();

        r = accept_config_load(ctx);
        if (r < 0)
                return r;

        if (accept_config_is_empty(ctx))
                log_debug("No acceptance configuration found.");

        *ret = TAKE_PTR(ctx);
        return 0;
}

static int manager_load_config(Manager *m) {
        _cleanup_(accept_config_ctx_freep) AcceptConfigContext *ctx = NULL;
        _cleanup_strv_free_ char **hold_probing = NULL;
        int r;

        assert(m);

        r = parse_config(&hold_probing);
        if (r < 0)
                return r;

        r = config_load(&ctx);
        if (r < 0)
                return r;

        strv_free_and_replace(m->hold_probing, hold_probing);
        free_and_replace_full(m->ctx, ctx, accept_config_ctx_free);
        return 0;
}

static int manager_hold_bus(Manager *m, const char *bus) {
        _cleanup_free_ char *b = NULL, *original = NULL, *state = NULL;
        int r;

        assert(m);
        assert(bus);

        state = path_join(AUTOPROBE_STATE_DIR, bus);
        if (!state)
                return log_oom();

        r = accept_bus_get_autoprobe(bus);
        if (r == -ENOENT) {
                log_debug("Bus '%s' does not exist (yet), not turning automatic driver probing off for it.", bus);
                return 0;
        }
        if (r < 0)
                return log_warning_errno(r, "Failed to read automatic driver probing setting of bus '%s', ignoring: %m", bus);

        original = strdup(one_zero(r));
        b = strdup(bus);
        if (!original || !b)
                return log_oom();

        r = write_string_file(state, original, WRITE_STRING_FILE_CREATE|WRITE_STRING_FILE_ATOMIC|WRITE_STRING_FILE_MKDIR_0755);
        if (r < 0)
                log_warning_errno(r, "Failed to save the original automatic driver probing setting of bus '%s', "
                                  "it will not be restored if we are restarted, ignoring: %m", bus);

        r = accept_bus_set_autoprobe(bus, /* enable= */ false);
        if (r < 0) {
                (void) unlink(state);
                return log_warning_errno(r, "Failed to turn automatic driver probing off for bus '%s', ignoring: %m", bus);
        }

        r = hashmap_ensure_put(&m->held, &string_hash_ops_free_free, b, original);
        if (r < 0) {
                (void) accept_bus_set_autoprobe(bus, /* enable= */ parse_boolean(original) > 0);
                (void) unlink(state);
                return log_oom();
        }
        TAKE_PTR(b);

        log_info("Turned automatic driver probing off for bus '%s', it was %s.", bus, original);
        TAKE_PTR(original);
        return 0;
}

/* Takes over the buses that a crashed instance left held, to restore their original value. */
static int manager_adopt_held_buses(Manager *m) {
        _cleanup_closedir_ DIR *d = NULL;
        int r;

        assert(m);

        d = opendir(AUTOPROBE_STATE_DIR);
        if (!d) {
                if (errno == ENOENT)
                        return 0;

                return log_warning_errno(errno, "Failed to open %s, ignoring: %m", AUTOPROBE_STATE_DIR);
        }

        FOREACH_DIRENT(de, d, return log_warning_errno(errno, "Failed to read %s, ignoring: %m", AUTOPROBE_STATE_DIR)) {
                _cleanup_free_ char *b = NULL, *original = NULL;

                if (!dirent_is_file(de) || !filename_is_valid(de->d_name))
                        continue;

                r = read_one_line_file_at(dirfd(d), de->d_name, &original);
                if (r < 0) {
                        log_warning_errno(r, "Failed to read %s/%s, ignoring: %m", AUTOPROBE_STATE_DIR, de->d_name);
                        continue;
                }
                if (parse_boolean(original) < 0) {
                        log_warning("Invalid saved automatic driver probing setting '%s' of bus '%s', ignoring.",
                                    original, de->d_name);
                        continue;
                }

                r = accept_bus_get_autoprobe(de->d_name);
                if (r == -ENOENT || r > 0) {
                        if (unlinkat(dirfd(d), de->d_name, 0) < 0 && errno != ENOENT)
                                log_debug_errno(errno, "Failed to remove stale saved setting of bus '%s', ignoring: %m",
                                                de->d_name);
                        continue;
                }
                if (r < 0) {
                        log_warning_errno(r, "Failed to check automatic driver probing setting of bus '%s', ignoring: %m",
                                          de->d_name);
                        continue;
                }

                b = strdup(de->d_name);
                if (!b)
                        return log_oom();

                r = hashmap_ensure_put(&m->held, &string_hash_ops_free_free, b, original);
                if (r < 0)
                        return log_oom();
                TAKE_PTR(b);

                log_debug("Taking over bus '%s' from a previous instance, its original setting is %s.",
                          de->d_name, original);
                TAKE_PTR(original);
        }

        return 0;
}

static int manager_hold_buses(Manager *m) {
        const char *bus, *original;
        char **buses;
        bool retry = false;
        int r;

        assert(m);

        buses = accept_config_is_empty(m->ctx) ? NULL : m->hold_probing;

        HASHMAP_FOREACH_KEY(original, bus, m->held)
                if (!strv_contains(buses, bus))
                        manager_release_bus(m, bus, /* restore= */ true);

        STRV_FOREACH(b, buses) {
                if (hashmap_contains(m->held, *b))
                        continue;

                r = manager_hold_bus(m, *b);
                if (r == -ENOMEM)
                        return r;
                if (r >= 0 && !hashmap_contains(m->held, *b))
                        retry = true;
        }

        if (retry) {
                r = event_reset_time_relative(m->event, &m->bus_retry_event_source, CLOCK_MONOTONIC,
                                              USEC_PER_SEC, 0, on_bus_retry, m, 0, "bus-retry", false);
                if (r < 0)
                        return log_warning_errno(r, "Failed to schedule holding newly registered buses: %m");
        }

        return 0;
}

static bool manager_device_is_held(Manager *m, sd_device *device) {
        const char *subsystem, *driver;

        assert(m);
        assert(device);

        if (sd_device_get_subsystem(device, &subsystem) < 0 || !hashmap_contains(m->held, subsystem))
                return false;

        if (accept_device_get_bus(device, /* ret= */ NULL) < 0)
                return false;

        return sd_device_get_driver(device, &driver) == -ENOENT;
}

static int manager_add_device(Manager *m, sd_device *device, const AcceptConfig *config, AcceptDevice **ret) {
        _cleanup_(accept_device_freep) AcceptDevice *d = NULL;
        int r;

        assert(m);
        assert(device);
        assert(ret);

        r = accept_device_new(device, config, &d);
        if (r < 0)
                return log_oom();

        r = hashmap_ensure_put(&m->devices, &accept_device_hash_ops, d->syspath, d);
        if (r < 0)
                return log_oom();

        *ret = TAKE_PTR(d);
        return 0;
}

static int manager_process_held_device(Manager *m, sd_device *device, const AcceptConfig *config) {
        AcceptDevice *d;
        const char *syspath;
        int r;

        assert(m);
        assert(device);

        r = sd_device_get_syspath(device, &syspath);
        if (r < 0)
                return log_device_debug_errno(device, r, "Failed to get the syspath of the device, ignoring: %m");

        d = hashmap_get(m->devices, syspath);
        if (d) {
                if (!IN_SET(d->state, ACCEPT_STATE_CONNECT, ACCEPT_STATE_WAITING, ACCEPT_STATE_RETRY))
                        return !!config;
                sd_device_unref(d->device);
                d->device = sd_device_ref(device);
        } else {
                r = manager_add_device(m, device, config, &d);
                if (r < 0)
                        return r;
        }

        (void) accept_device_run(d, accept_steps);
        if (d->state == ACCEPT_STATE_RETRY)
                manager_schedule_rescan(m, USEC_PER_SEC);
        return !!config;
}

static int manager_process_device(Manager *m, sd_device *device) {
        AcceptDeviceIdentity identity;
        const AcceptConfig *config;
        int r;

        assert(m);
        assert(device);

        r = accept_device_identity_get(device, &identity);
        if (r < 0)
                return log_device_debug_errno(device, r, "Failed to get the identity of the device, ignoring: %m");

        config = accept_config_get(m->ctx, &identity);

        if (manager_device_is_held(m, device))
                return manager_process_held_device(m, device, config);

        if (!config)
                return 0;

        r = accept_config_apply(config, device, /* dry_run= */ false);
        return r < 0 ? r : 1;
}

static int manager_process_all(Manager *m) {
        _cleanup_(sd_device_enumerator_unrefp) sd_device_enumerator *e = NULL;
        unsigned n_selected = 0, n_failed = 0;
        sd_device *device;
        int r;

        assert(m);

        if (accept_config_is_empty(m->ctx) && hashmap_isempty(m->held))
                return 0;

        r = accept_device_enumerator_new(&e);
        if (r < 0)
                return log_error_errno(r, "Failed to enumerate devices: %m");

        FOREACH_DEVICE_AND_SUBSYSTEM(e, device) {
                r = manager_process_device(m, device);
                if (r == 0)
                        continue;

                n_selected++;

                if (r < 0 && r != -ENODEV)
                        n_failed++;
        }

        if (n_failed > 0)
                log_warning("The acceptance configuration could not be applied to %u of %u selected device(s).",
                            n_failed, n_selected);
        else
                log_debug("Applied the acceptance configuration to %u existing device(s).", n_selected);

        return 0;
}

static bool manager_has_pending(Manager *m, bool retry_only) {
        AcceptDevice *d;

        assert(m);

        HASHMAP_FOREACH(d, m->devices)
                if (d->state == ACCEPT_STATE_RETRY ||
                    (!retry_only && IN_SET(d->state, ACCEPT_STATE_CONNECT, ACCEPT_STATE_WAITING)))
                        return true;

        return false;
}

static int on_bus_retry(sd_event_source *s, uint64_t usec, void *userdata) {
        Manager *m = ASSERT_PTR(userdata);
        unsigned n_held = hashmap_size(m->held);
        int r;

        r = manager_hold_buses(m);
        if (r < 0)
                return r;
        if (hashmap_size(m->held) > n_held)
                return manager_process_all(m);

        return 0;
}

static int on_rescan(sd_event_source *s, uint64_t usec, void *userdata) {
        Manager *m = ASSERT_PTR(userdata);
        const char *syspath;
        AcceptDevice *d;

        HASHMAP_FOREACH_KEY(d, syspath, m->devices) {
                _cleanup_(sd_device_unrefp) sd_device *device = NULL;

                if (d->state != ACCEPT_STATE_RETRY &&
                    (m->rescan_retry_only || !IN_SET(d->state, ACCEPT_STATE_CONNECT, ACCEPT_STATE_WAITING)))
                        continue;

                if (sd_device_new_from_syspath(&device, syspath) < 0 || !manager_device_is_held(m, device)) {
                        accept_device_free(hashmap_remove(m->devices, syspath));
                        continue;
                }

                sd_device_unref(d->device);
                d->device = TAKE_PTR(device);
                (void) accept_device_run(d, accept_steps);
        }

        manager_schedule_rescan(m, USEC_PER_SEC);
        return 0;
}

static void manager_schedule_rescan(Manager *m, usec_t delay) {
        usec_t next;
        int r;

        assert(m);

        if (!manager_has_pending(m, /* retry_only= */ delay > 0))
                return;

        next = now(CLOCK_MONOTONIC) + delay;

        if (m->rescan_event_source) {
                int enabled;
                uint64_t scheduled;

                if (sd_event_source_get_enabled(m->rescan_event_source, &enabled) >= 0 &&
                    enabled != SD_EVENT_OFF &&
                    sd_event_source_get_time(m->rescan_event_source, &scheduled) >= 0 && scheduled <= next) {
                        if (delay == 0)
                                m->rescan_retry_only = false;
                        return;
                }
        }

        r = event_reset_time(m->event, &m->rescan_event_source, CLOCK_MONOTONIC, next, 0, on_rescan, m,
                             0, /* description= */ NULL, true);
        if (r < 0) {
                log_warning_errno(r, "Failed to schedule probing drivers again, ignoring: %m");
                return;
        }

        (void) sd_event_source_set_description(m->rescan_event_source, delay > 0 ? "retry" : "rescan");
        m->rescan_retry_only = delay > 0;
}

static void manager_retry_unbound(Manager *m, const char *bus) {
        AcceptDevice *d;

        HASHMAP_FOREACH(d, m->devices)
                if (d->state == ACCEPT_STATE_UNBOUND && device_in_subsystem(d->device, bus) > 0)
                        d->state = ACCEPT_STATE_CONNECT;
}

static int on_uevent(sd_device_monitor *monitor, sd_device *device, void *userdata) {
        Manager *m = ASSERT_PTR(userdata);
        sd_device_action_t action;
        const char *s;
        int r;

        assert(device);

        r = sd_device_get_action(device, &action);
        if (r < 0) {
                log_device_debug_errno(device, r, "Failed to get the action of the uevent, ignoring: %m");
                return 0;
        }

        switch (action) {

        case SD_DEVICE_ADD:
                if (device_in_subsystem(device, "bus") > 0) {
                        if (sd_device_get_sysname(device, &s) >= 0 &&
                            strv_contains(m->hold_probing, s) && !hashmap_contains(m->held, s) &&
                            manager_hold_buses(m) >= 0)
                                (void) manager_process_all(m);
                        return 0;
                }

                if (device_in_subsystem(device, "drivers") > 0) {
                        /* With automatic probing off, the kernel binds no new driver to the held devices. */
                        if (sd_device_get_driver_subsystem(device, &s) >= 0 && hashmap_contains(m->held, s)) {
                                manager_retry_unbound(m, s);
                                manager_schedule_rescan(m, 0);
                        }
                        return 0;
                }

                (void) manager_process_device(m, device);
                return 0;

        case SD_DEVICE_BIND:
                /* The kernel retries deferred probes after a bind, except on held buses. */
                manager_schedule_rescan(m, 0);
                return 0;

        case SD_DEVICE_UNBIND: {
                AcceptDeviceIdentity identity;
                AcceptDevice *d;

                if (sd_device_get_syspath(device, &s) < 0)
                        return 0;

                d = hashmap_get(m->devices, s);
                if (!d) {
                        const char *bus;

                        if (accept_device_get_bus(device, &bus) < 0 || !hashmap_contains(m->held, bus) ||
                            accept_device_identity_get(device, &identity) < 0)
                                return 0;

                        r = manager_add_device(m, device, accept_config_get(m->ctx, &identity), &d);
                        if (r < 0)
                                return r;
                }

                if (IN_SET(d->state, ACCEPT_STATE_BOUND, ACCEPT_STATE_CONNECT))
                        d->state = ACCEPT_STATE_UNBOUND;
                return 0;
        }

        case SD_DEVICE_REMOVE:
                if (device_in_subsystem(device, "bus") > 0 && sd_device_get_sysname(device, &s) >= 0)
                        manager_release_bus(m, s, /* restore= */ false);
                if (sd_device_get_syspath(device, &s) >= 0)
                        accept_device_free(hashmap_remove(m->devices, s));
                return 0;

        default:
                return 0;
        }
}

static void manager_forget_unbound(Manager *m) {
        const char *syspath;
        AcceptDevice *d;

        assert(m);

        HASHMAP_FOREACH_KEY(d, syspath, m->devices)
                if (IN_SET(d->state, ACCEPT_STATE_CONNECT, ACCEPT_STATE_WAITING, ACCEPT_STATE_RETRY,
                           ACCEPT_STATE_UNBOUND, ACCEPT_STATE_REJECTED))
                        accept_device_free(hashmap_remove(m->devices, syspath));
}

static int on_sighup(sd_event_source *s, const struct signalfd_siginfo *si, void *userdata) {
        Manager *m = ASSERT_PTR(userdata);

        (void) notify_reloading();

        if (manager_load_config(m) >= 0 && manager_hold_buses(m) >= 0) {
                manager_forget_unbound(m);
                (void) manager_process_all(m);
        }

        (void) sd_notify(/* unset_environment= */ false, NOTIFY_READY_MESSAGE);
        return 0;
}

static int manager_new(Manager **ret) {
        _cleanup_(manager_freep) Manager *m = NULL;
        int r;

        assert(ret);

        m = new0(Manager, 1);
        if (!m)
                return log_oom();

        r = sd_event_default(&m->event);
        if (r < 0)
                return log_error_errno(r, "Failed to allocate event loop: %m");

        (void) sd_event_set_watchdog(m->event, true);

        r = sd_event_add_signal(m->event, /* ret= */ NULL, SIGHUP | SD_EVENT_SIGNAL_PROCMASK, on_sighup, m);
        if (r < 0)
                return log_error_errno(r, "Failed to install SIGHUP handler: %m");

        r = sd_event_set_signal_exit(m->event, true);
        if (r < 0)
                return log_error_errno(r, "Failed to install SIGINT/SIGTERM handlers: %m");

        *ret = TAKE_PTR(m);
        return 0;
}

static int manager_start(Manager *m) {
        int r;

        assert(m);

        r = manager_load_config(m);
        if (r < 0)
                return r;

        /* Listen first, so that no uevent is missed. */
        r = device_monitor_new_full(&m->monitor, MONITOR_GROUP_KERNEL, /* fd= */ -EBADF);
        if (r < 0)
                return log_error_errno(r, "Failed to create device monitor: %m");

        (void) sd_device_monitor_set_description(m->monitor, "kernel");

        r = sd_device_monitor_attach_event(m->monitor, m->event);
        if (r < 0)
                return log_error_errno(r, "Failed to attach device monitor to event loop: %m");

        r = sd_device_monitor_start(m->monitor, on_uevent, m);
        if (r < 0)
                return log_error_errno(r, "Failed to start device monitor: %m");

        r = manager_adopt_held_buses(m);
        if (r < 0)
                return r;

        r = manager_hold_buses(m);
        if (r < 0)
                return r;

        return manager_process_all(m);
}

static int dry_run(void) {
        _cleanup_(accept_config_ctx_freep) AcceptConfigContext *ctx = NULL;
        _cleanup_strv_free_ char **hold_probing = NULL;
        unsigned n_selected, n_failed;
        int r;

        r = parse_config(&hold_probing);
        if (r < 0)
                return r;

        r = config_load(&ctx);
        if (r < 0)
                return r;

        if (!accept_config_is_empty(ctx))
                STRV_FOREACH(bus, hold_probing)
                        log_info("Would turn automatic driver probing off for bus '%s'.", *bus);

        r = accept_config_apply_all(ctx, /* dry_run= */ true, stdout, &n_selected, &n_failed);
        if (r < 0)
                return log_error_errno(r, "Failed to enumerate devices: %m");

        if (n_failed > 0)
                return log_warning_errno(SYNTHETIC_ERRNO(EIO),
                                         "The acceptance configuration cannot be applied to %u of %u selected device(s).",
                                         n_failed, n_selected);

        return 0;
}

static int parse_argv(int argc, char *argv[]) {
        assert(argc >= 0);
        assert(argv);

        OptionParser opts = { argc, argv };

        FOREACH_OPTION_OR_RETURN(c, &opts)
                switch (c) {

                OPTION_COMMON_HELP:
                        return command_print_help();

                OPTION_COMMON_VERSION:
                        return version();

                OPTION('n', "dry-run", NULL, "Only print what would be done, and exit"):
                        arg_dry_run = true;
                        break;

                OPTION_COMMON_INTROSPECT_CLI:
                        return introspect_cli(SD_JSON_FORMAT_OFF);
                }

        if (option_parser_get_n_args(&opts) > 0)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "This program takes no arguments.");

        return 1;
}

static int run(int argc, char *argv[]) {
        _unused_ _cleanup_(notify_on_cleanup) const char *notify_msg = NULL;
        _cleanup_(manager_freep) Manager *m = NULL;
        int r;

        log_setup();

        r = parse_argv(argc, argv);
        if (r <= 0)
                return r;

        if (arg_dry_run)
                return dry_run();

        r = manager_new(&m);
        if (r < 0)
                return r;

        r = manager_start(m);
        if (r < 0)
                return r;

        notify_msg = notify_start(NOTIFY_READY_MESSAGE, NOTIFY_STOPPING_MESSAGE);

        r = sd_event_loop(m->event);
        if (r < 0)
                return log_error_errno(r, "Event loop failed: %m");

        return 0;
}

DEFINE_MAIN_FUNCTION(run);
