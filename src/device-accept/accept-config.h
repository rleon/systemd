/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdio.h>

#include "sd-device.h"

#include "conf-parser-forward.h"
#include "forward.h"
#include "list.h"

typedef struct AcceptConfigContext AcceptConfigContext;
typedef struct AcceptConfig AcceptConfig;

typedef enum AcceptTrustLevel {
        ACCEPT_TRUST_LEVEL_DEFAULT,
        ACCEPT_TRUST_LEVEL_DISABLED,
        ACCEPT_TRUST_LEVEL_ADVERSARY,
        ACCEPT_TRUST_LEVEL_FULL,
        _ACCEPT_TRUST_LEVEL_MAX,
        _ACCEPT_TRUST_LEVEL_INVALID = -EINVAL,
} AcceptTrustLevel;

typedef enum AcceptSelectorType {
        ACCEPT_SELECTOR_NAME,
        ACCEPT_SELECTOR_PCI,
        ACCEPT_SELECTOR_PATH,
        _ACCEPT_SELECTOR_TYPE_MAX,
        _ACCEPT_SELECTOR_TYPE_INVALID = -EINVAL,
} AcceptSelectorType;

typedef struct AcceptSelector {
        AcceptSelectorType type;
        char *value;
} AcceptSelector;

typedef struct AcceptDeviceIdentity {
        const char *sysname;
        const char *subsystem;
        const char *devpath;
} AcceptDeviceIdentity;

struct AcceptConfig {
        char *filename;
        char **dropins;

        AcceptSelector *selectors;
        size_t n_selectors;
        AcceptTrustLevel trust_level;

        LIST_FIELDS(AcceptConfig, configs);
};

int accept_config_ctx_new(char * const *dirs, AcceptConfigContext **ret);
AcceptConfigContext* accept_config_ctx_free(AcceptConfigContext *ctx);
DEFINE_TRIVIAL_CLEANUP_FUNC(AcceptConfigContext*, accept_config_ctx_free);

int accept_config_load_one(AcceptConfigContext *ctx, const char *filename);
int accept_config_load(AcceptConfigContext *ctx);
bool accept_config_is_empty(const AcceptConfigContext *ctx);

const AcceptConfig* accept_config_get(const AcceptConfigContext *ctx, const AcceptDeviceIdentity *identity);

int accept_device_identity_get(sd_device *device, AcceptDeviceIdentity *ret);

int accept_selector_parse(const char *s, AcceptSelector *ret);
void accept_selector_done(AcceptSelector *selector);
bool accept_selector_matches(const AcceptSelector *selector, const AcceptDeviceIdentity *identity);

int accept_config_apply(const AcceptConfig *config, sd_device *device, bool dry_run);

int accept_config_apply_device(const AcceptConfigContext *ctx, sd_device *device, bool dry_run, FILE *report);

int accept_device_enumerator_new(sd_device_enumerator **ret);

int accept_config_apply_all(
                const AcceptConfigContext *ctx,
                bool dry_run,
                FILE *report,
                unsigned *ret_n_selected,
                unsigned *ret_n_failed);

DECLARE_STRING_TABLE_LOOKUP(accept_trust_level, AcceptTrustLevel);

const struct ConfigPerfItem* accept_config_gperf_lookup(const char *str, GPERF_LEN_TYPE length);

CONFIG_PARSER_PROTOTYPE(config_parse_accept_device);
CONFIG_PARSER_PROTOTYPE(config_parse_accept_trust_level);
