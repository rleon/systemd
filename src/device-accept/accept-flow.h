/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "sd-device.h"

#include "accept-config.h"
#include "forward.h"

typedef enum AcceptState {
        ACCEPT_STATE_CONNECT,
        ACCEPT_STATE_MEASURE,
        ACCEPT_STATE_LOG,
        ACCEPT_STATE_EXTEND,
        ACCEPT_STATE_VERIFY,
        ACCEPT_STATE_RUN,
        ACCEPT_STATE_BIND,
        ACCEPT_STATE_WAITING,
        ACCEPT_STATE_RETRY,
        ACCEPT_STATE_BOUND,
        ACCEPT_STATE_UNBOUND,
        ACCEPT_STATE_REJECTED,
        _ACCEPT_STATE_MAX,
        _ACCEPT_STATE_INVALID = -EINVAL,
} AcceptState;

#define _ACCEPT_STEP_MAX ACCEPT_STATE_BIND

typedef struct AcceptDevice {
        sd_device *device;
        char *syspath;
        char *config_file;
        AcceptTrustLevel trust_level;
        AcceptState state;
} AcceptDevice;

typedef int (*AcceptStep)(AcceptDevice *d);

extern const AcceptStep accept_steps[_ACCEPT_STEP_MAX];

int accept_device_new(sd_device *device, const AcceptConfig *config, AcceptDevice **ret);
AcceptDevice* accept_device_free(AcceptDevice *d);
DEFINE_TRIVIAL_CLEANUP_FUNC(AcceptDevice*, accept_device_free);

AcceptState accept_device_run(AcceptDevice *d, const AcceptStep steps[static _ACCEPT_STEP_MAX]);

DECLARE_STRING_TABLE_LOOKUP(accept_state, AcceptState);
