/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-device.h"

#include "accept-bind.h"
#include "accept-config.h"
#include "accept-flow.h"
#include "alloc-util.h"
#include "device-util.h"
#include "log.h"
#include "string-table.h"
#include "string-util.h"

static const char* const accept_state_table[_ACCEPT_STATE_MAX] = {
        [ACCEPT_STATE_CONNECT]  = "connect",
        [ACCEPT_STATE_MEASURE]  = "measure",
        [ACCEPT_STATE_LOG]      = "log",
        [ACCEPT_STATE_EXTEND]   = "extend",
        [ACCEPT_STATE_VERIFY]   = "verify",
        [ACCEPT_STATE_RUN]      = "run",
        [ACCEPT_STATE_BIND]     = "bind",
        [ACCEPT_STATE_WAITING]  = "waiting",
        [ACCEPT_STATE_RETRY]    = "retry",
        [ACCEPT_STATE_BOUND]    = "bound",
        [ACCEPT_STATE_UNBOUND]  = "unbound",
        [ACCEPT_STATE_REJECTED] = "rejected",
};

DEFINE_STRING_TABLE_LOOKUP(accept_state, AcceptState);

/* Not implemented until the kernel provides the interfaces for SPDM, measurements and TDISP. */

static int accept_step_connect(AcceptDevice *d) {
        return -EOPNOTSUPP;
}

static int accept_step_measure(AcceptDevice *d) {
        return -EOPNOTSUPP;
}

static int accept_step_log(AcceptDevice *d) {
        return -EOPNOTSUPP;
}

static int accept_step_extend(AcceptDevice *d) {
        return -EOPNOTSUPP;
}

static int accept_step_verify(AcceptDevice *d) {
        return -EOPNOTSUPP;
}

static int accept_step_run(AcceptDevice *d) {
        return -EOPNOTSUPP;
}

const AcceptStep accept_steps[_ACCEPT_STEP_MAX] = {
        [ACCEPT_STATE_CONNECT] = accept_step_connect,
        [ACCEPT_STATE_MEASURE] = accept_step_measure,
        [ACCEPT_STATE_LOG]     = accept_step_log,
        [ACCEPT_STATE_EXTEND]  = accept_step_extend,
        [ACCEPT_STATE_VERIFY]  = accept_step_verify,
        [ACCEPT_STATE_RUN]     = accept_step_run,
};

int accept_device_new(sd_device *device, const AcceptConfig *config, AcceptDevice **ret) {
        _cleanup_(accept_device_freep) AcceptDevice *d = NULL;
        const char *syspath;
        int r;

        assert(device);
        assert(ret);

        d = new(AcceptDevice, 1);
        if (!d)
                return -ENOMEM;

        *d = (AcceptDevice) {
                .device = sd_device_ref(device),
                .trust_level = config ? config->trust_level : _ACCEPT_TRUST_LEVEL_INVALID,
                .state = ACCEPT_STATE_CONNECT,
        };

        r = sd_device_get_syspath(device, &syspath);
        if (r < 0)
                return r;
        d->syspath = strdup(syspath);
        if (!d->syspath)
                return -ENOMEM;

        if (config) {
                d->config_file = strdup(config->filename);
                if (!d->config_file)
                        return -ENOMEM;
        }

        *ret = TAKE_PTR(d);
        return 0;
}

AcceptDevice* accept_device_free(AcceptDevice *d) {
        if (!d)
                return NULL;

        sd_device_unref(d->device);
        free(d->syspath);
        free(d->config_file);

        return mfree(d);
}

static void accept_device_set_state(AcceptDevice *d, AcceptState state) {
        assert(d);
        assert(state >= 0 && state < _ACCEPT_STATE_MAX);

        if (d->state == state)
                return;

        log_device_debug(d->device, "Acceptance state changed: %s -> %s",
                         accept_state_to_string(d->state), accept_state_to_string(state));
        d->state = state;
}

static void accept_device_reject(AcceptDevice *d) {
        assert(d);
        assert(d->config_file);

        accept_device_set_state(d, ACCEPT_STATE_REJECTED);

        /* Disabled, so that no driver is bound once the bus is not held anymore. */
        AcceptConfig config = {
                .filename = d->config_file,
                .trust_level = ACCEPT_TRUST_LEVEL_DISABLED,
        };
        (void) accept_config_apply(&config, d->device, /* dry_run= */ false);
}

AcceptState accept_device_run(AcceptDevice *d, const AcceptStep steps[static _ACCEPT_STEP_MAX]) {
        int r;

        assert(d);
        assert(steps);

        if ((!d->config_file && d->state < ACCEPT_STATE_BIND) ||
            IN_SET(d->state, ACCEPT_STATE_WAITING, ACCEPT_STATE_RETRY))
                accept_device_set_state(d, ACCEPT_STATE_BIND);

        while (d->state < ACCEPT_STATE_BIND) {
                AcceptState state = d->state;

                r = steps[state](d);
                if (r == -EOPNOTSUPP)
                        log_device_debug(d->device, "Acceptance step '%s' is not available, skipping.",
                                         accept_state_to_string(state));
                else if (r < 0) {
                        log_device_warning_errno(d->device, r, "Acceptance step '%s' failed, rejecting the device: %m",
                                                 accept_state_to_string(state));
                        accept_device_reject(d);
                        return d->state;
                }

                accept_device_set_state(d, state + 1);
        }

        if (d->state != ACCEPT_STATE_BIND)
                return d->state;

        AcceptConfig config = {
                .filename = d->config_file,
                .trust_level = d->trust_level,
        };

        r = accept_device_bind(d->config_file ? &config : NULL, d->device);
        accept_device_set_state(d,
                                r == ACCEPT_BIND_BOUND     ? ACCEPT_STATE_BOUND :
                                r == ACCEPT_BIND_RETRY     ? ACCEPT_STATE_RETRY :
                                r == ACCEPT_BIND_NO_DRIVER ? ACCEPT_STATE_WAITING :
                                                             ACCEPT_STATE_REJECTED);
        return d->state;
}
