/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "sd-device.h"

#include "accept-config.h"
#include "conf-parser-forward.h"
#include "forward.h"

typedef enum AcceptBindResult {
        ACCEPT_BIND_REFUSED,
        ACCEPT_BIND_NO_DRIVER,
        ACCEPT_BIND_RETRY,
        ACCEPT_BIND_BOUND,
        _ACCEPT_BIND_RESULT_MAX,
        _ACCEPT_BIND_RESULT_INVALID = -EINVAL,
} AcceptBindResult;

int accept_bus_get_autoprobe(const char *bus);
int accept_bus_set_autoprobe(const char *bus, bool enable);

int accept_device_get_bus(sd_device *device, const char **ret);

int accept_device_bind(const AcceptConfig *config, sd_device *device);

CONFIG_PARSER_PROTOTYPE(config_parse_accept_buses);
