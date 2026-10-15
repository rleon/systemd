/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <signal.h>
#include <stdio.h>

#include "sd-device.h"
#include "sd-event.h"
#include "sd-json.h"

#include "accept-config.h"
#include "alloc-util.h"
#include "build.h"
#include "daemon-util.h"
#include "device-enumerator-private.h"
#include "device-monitor-private.h"
#include "device-util.h"
#include "log.h"
#include "main-func.h"
#include "options.h"
#include "verbs.h"

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
} Manager;

static Manager* manager_free(Manager *m) {
        if (!m)
                return NULL;

        sd_device_monitor_unref(m->monitor);
        sd_event_unref(m->event);
        accept_config_ctx_free(m->ctx);

        return mfree(m);
}

DEFINE_TRIVIAL_CLEANUP_FUNC(Manager*, manager_free);

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
        int r;

        assert(m);

        r = config_load(&ctx);
        if (r < 0)
                return r;

        free_and_replace_full(m->ctx, ctx, accept_config_ctx_free);
        return 0;
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

        if (accept_config_is_empty(m->ctx))
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

static int on_uevent(sd_device_monitor *monitor, sd_device *device, void *userdata) {
        Manager *m = ASSERT_PTR(userdata);
        sd_device_action_t action;
        int r;

        assert(device);

        r = sd_device_get_action(device, &action);
        if (r < 0) {
                log_device_debug_errno(device, r, "Failed to get the action of the uevent, ignoring: %m");
                return 0;
        }

        switch (action) {

        case SD_DEVICE_ADD:
                (void) manager_process_device(m, device);
                return 0;

        default:
                return 0;
        }
}

static int on_sighup(sd_event_source *s, const struct signalfd_siginfo *si, void *userdata) {
        Manager *m = ASSERT_PTR(userdata);

        (void) notify_reloading();

        if (manager_load_config(m) >= 0)
                (void) manager_process_all(m);

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

        return manager_process_all(m);
}

static int dry_run(void) {
        _cleanup_(accept_config_ctx_freep) AcceptConfigContext *ctx = NULL;
        unsigned n_selected, n_failed;
        int r;

        r = config_load(&ctx);
        if (r < 0)
                return r;

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
