/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fnmatch.h>
#include <unistd.h>

#include "sd-device.h"

#include "accept-config.h"
#include "alloc-util.h"
#include "conf-files.h"
#include "conf-parser.h"
#include "constants.h"
#include "device-enumerator-private.h"
#include "device-util.h"
#include "extract-word.h"
#include "log.h"
#include "parse-util.h"
#include "path-util.h"
#include "stat-util.h"
#include "string-table.h"
#include "string-util.h"
#include "strv.h"

#define ACCEPT_TRUST_POLICY_SYSATTR "trust_policy"

#define ACCEPT_DIRS CONF_PATHS_STRV("systemd/accept.d")

struct AcceptConfigContext {
        char **dirs;
        LIST_HEAD(AcceptConfig, configs);
};

static const char* const accept_trust_level_table[_ACCEPT_TRUST_LEVEL_MAX] = {
        [ACCEPT_TRUST_LEVEL_DEFAULT]   = "default",
        [ACCEPT_TRUST_LEVEL_DISABLED]  = "disabled",
        [ACCEPT_TRUST_LEVEL_ADVERSARY] = "adversary",
        [ACCEPT_TRUST_LEVEL_FULL]      = "full",
};

DEFINE_STRING_TABLE_LOOKUP(accept_trust_level, AcceptTrustLevel);

static const char* const accept_selector_type_table[_ACCEPT_SELECTOR_TYPE_MAX] = {
        [ACCEPT_SELECTOR_NAME] = "name",
        [ACCEPT_SELECTOR_PCI]  = "pci",
        [ACCEPT_SELECTOR_PATH] = "path",
};

DEFINE_PRIVATE_STRING_TABLE_LOOKUP_FROM_STRING(accept_selector_type, AcceptSelectorType);

void accept_selector_done(AcceptSelector *selector) {
        if (!selector)
                return;

        selector->value = mfree(selector->value);
        selector->type = _ACCEPT_SELECTOR_TYPE_INVALID;
}

static int parse_hex_field(const char *s, size_t min_digits, size_t max_digits, unsigned max_value, unsigned *ret) {
        unsigned v;
        size_t l;
        int r;

        assert(s);
        assert(ret);

        l = strlen(s);
        if (l < min_digits || l > max_digits)
                return -EINVAL;

        if (!in_charset(s, "0123456789abcdefABCDEF"))
                return -EINVAL;

        r = safe_atou_full(s, 16, &v);
        if (r < 0)
                return r;
        if (v > max_value)
                return -EINVAL;

        *ret = v;
        return 0;
}

static int pci_address_normalize(const char *s, char **ret) {
        _cleanup_strv_free_ char **fields = NULL;
        _cleanup_free_ char *device_str = NULL, *normalized = NULL;
        unsigned domain = 0, bus, device, function;
        const char *dot;
        size_t n;
        int r;

        assert(s);
        assert(ret);

        r = strv_split_full(&fields, s, ":", EXTRACT_DONT_COALESCE_SEPARATORS);
        if (r < 0)
                return r;

        n = strv_length(fields);
        if (!IN_SET(n, 2, 3))
                return -EINVAL;

        if (n == 3) {
                r = parse_hex_field(fields[0], 4, 8, UINT_MAX, &domain);
                if (r < 0)
                        return r;
        }

        r = parse_hex_field(fields[n - 2], 2, 2, 0xff, &bus);
        if (r < 0)
                return r;

        dot = strchr(fields[n - 1], '.');
        if (!dot || strchr(dot + 1, '.'))
                return -EINVAL;

        device_str = strndup(fields[n - 1], dot - fields[n - 1]);
        if (!device_str)
                return -ENOMEM;

        r = parse_hex_field(device_str, 2, 2, 0x1f, &device);
        if (r < 0)
                return r;

        r = parse_hex_field(dot + 1, 1, 1, 7, &function);
        if (r < 0)
                return r;

        if (asprintf(&normalized, "%04x:%02x:%02x.%x", domain, bus, device, function) < 0)
                return -ENOMEM;

        *ret = TAKE_PTR(normalized);
        return 0;
}

static int device_path_normalize(const char *s, char **ret) {
        _cleanup_free_ char *simplified = NULL, *devpath = NULL;
        const char *e;
        int r;

        assert(s);
        assert(ret);

        if (!path_is_absolute(s))
                return -EINVAL;

        r = path_simplify_alloc(s, &simplified);
        if (r < 0)
                return r;

        if (!path_is_normalized(simplified))
                return -EINVAL;

        e = path_startswith(simplified, "/sys");
        if (e) {
                devpath = strjoin("/", e);
                if (!devpath)
                        return -ENOMEM;
        } else
                devpath = TAKE_PTR(simplified);

        e = path_startswith(devpath, "/devices");
        if (isempty(e))
                return -EINVAL;

        *ret = TAKE_PTR(devpath);
        return 0;
}

int accept_selector_parse(const char *s, AcceptSelector *ret) {
        _cleanup_free_ char *type_str = NULL, *value = NULL;
        AcceptSelectorType type;
        const char *p;
        int r;

        assert(s);
        assert(ret);

        p = strchr(s, ':');
        if (!p)
                return -EINVAL;

        type_str = strndup(s, p - s);
        if (!type_str)
                return -ENOMEM;

        type = accept_selector_type_from_string(type_str);
        if (type < 0)
                return type;

        p++;

        switch (type) {

        case ACCEPT_SELECTOR_NAME:
                if (isempty(p) || strchr(p, '/'))
                        return -EINVAL;

                value = strdup(p);
                if (!value)
                        return -ENOMEM;
                break;

        case ACCEPT_SELECTOR_PCI:
                r = pci_address_normalize(p, &value);
                if (r < 0)
                        return r;
                break;

        case ACCEPT_SELECTOR_PATH:
                r = device_path_normalize(p, &value);
                if (r < 0)
                        return r;
                break;

        default:
                assert_not_reached();
        }

        *ret = (AcceptSelector) {
                .type = type,
                .value = TAKE_PTR(value),
        };

        return 0;
}

bool accept_selector_matches(const AcceptSelector *selector, const AcceptDeviceIdentity *identity) {
        assert(selector);
        assert(identity);

        switch (selector->type) {

        case ACCEPT_SELECTOR_NAME:
                return identity->sysname && fnmatch(selector->value, identity->sysname, 0) == 0;

        case ACCEPT_SELECTOR_PCI:
                return streq_ptr(identity->subsystem, "pci") && streq_ptr(identity->sysname, selector->value);

        case ACCEPT_SELECTOR_PATH:
                return identity->devpath && fnmatch(selector->value, identity->devpath, FNM_PATHNAME) == 0;

        default:
                assert_not_reached();
        }
}

static AcceptConfig* accept_config_free(AcceptConfig *config) {
        if (!config)
                return NULL;

        free(config->filename);
        strv_free(config->dropins);

        FOREACH_ARRAY(selector, config->selectors, config->n_selectors)
                accept_selector_done(selector);
        free(config->selectors);

        return mfree(config);
}

DEFINE_TRIVIAL_CLEANUP_FUNC(AcceptConfig*, accept_config_free);

static void accept_configs_free(AcceptConfigContext *ctx) {
        if (!ctx)
                return;

        LIST_CLEAR(configs, ctx->configs, accept_config_free);
}

AcceptConfigContext* accept_config_ctx_free(AcceptConfigContext *ctx) {
        if (!ctx)
                return NULL;

        accept_configs_free(ctx);
        strv_free(ctx->dirs);

        return mfree(ctx);
}

int accept_config_ctx_new(char * const *dirs, AcceptConfigContext **ret) {
        _cleanup_(accept_config_ctx_freep) AcceptConfigContext *ctx = NULL;

        assert(ret);

        ctx = new(AcceptConfigContext, 1);
        if (!ctx)
                return -ENOMEM;

        *ctx = (AcceptConfigContext) {};

        ctx->dirs = strv_copy(dirs ?: ACCEPT_DIRS);
        if (!ctx->dirs)
                return -ENOMEM;

        *ret = TAKE_PTR(ctx);
        return 0;
}

int accept_config_load_one(AcceptConfigContext *ctx, const char *filename) {
        _cleanup_(accept_config_freep) AcceptConfig *config = NULL;
        _cleanup_free_ char *name = NULL, *file_basename = NULL;
        const char *dropin_dirname;
        int r;

        assert(ctx);
        assert(filename);

        r = null_or_empty_path(filename);
        if (r < 0)
                return log_warning_errno(r, "Failed to check if \"%s\" is empty: %m", filename);
        if (r > 0) {
                log_debug("Skipping empty file: %s", filename);
                return 0;
        }

        name = strdup(filename);
        if (!name)
                return log_oom();

        config = new(AcceptConfig, 1);
        if (!config)
                return log_oom();

        *config = (AcceptConfig) {
                .filename = TAKE_PTR(name),
                .trust_level = _ACCEPT_TRUST_LEVEL_INVALID,
        };

        r = path_extract_filename(filename, &file_basename);
        if (r < 0)
                return log_error_errno(r, "Failed to extract file name of '%s': %m", filename);

        dropin_dirname = strjoina(file_basename, ".d");
        r = config_parse_many_full(
                        STRV_MAKE_CONST(filename),
                        (const char* const*) ctx->dirs,
                        dropin_dirname,
                        /* root= */ NULL,
                        /* root_fd= */ -EBADF,
                        "Match\0"
                        "Accept\0",
                        config_item_perf_lookup, accept_config_gperf_lookup,
                        CONFIG_PARSE_WARN,
                        config,
                        /* ret_stats_by_path= */ NULL,
                        &config->dropins);
        if (r < 0)
                return r;

        if (config->n_selectors == 0) {
                log_warning("%s: No valid Device= setting found in the [Match] section, ignoring file.", filename);
                return 0;
        }

        if (config->trust_level < 0) {
                log_warning("%s: No valid TrustLevel= setting found in the [Accept] section, ignoring file.", filename);
                return 0;
        }

        log_debug("Parsed configuration file \"%s\"", filename);

        LIST_PREPEND(configs, ctx->configs, TAKE_PTR(config));
        return 0;
}

int accept_config_load(AcceptConfigContext *ctx) {
        _cleanup_strv_free_ char **files = NULL;
        int r;

        assert(ctx);

        accept_configs_free(ctx);

        r = conf_files_list_strv(&files, ".conf", /* root= */ NULL, CONF_FILES_WARN, (const char* const*) ctx->dirs);
        if (r < 0)
                return log_error_errno(r, "Failed to enumerate acceptance configuration files: %m");

        STRV_FOREACH_BACKWARDS(f, files)
                (void) accept_config_load_one(ctx, *f);

        return 0;
}

bool accept_config_is_empty(const AcceptConfigContext *ctx) {
        return !ctx || !ctx->configs;
}

const AcceptConfig* accept_config_get(const AcceptConfigContext *ctx, const AcceptDeviceIdentity *identity) {
        assert(ctx);
        assert(identity);

        LIST_FOREACH(configs, config, ctx->configs)
                FOREACH_ARRAY(selector, config->selectors, config->n_selectors)
                        if (accept_selector_matches(selector, identity))
                                return config;

        return NULL;
}

int accept_device_identity_get(sd_device *device, AcceptDeviceIdentity *ret) {
        AcceptDeviceIdentity identity = {};
        int r;

        assert(device);
        assert(ret);

        r = sd_device_get_devpath(device, &identity.devpath);
        if (r < 0)
                return r;

        identity.sysname = last_path_component(identity.devpath);

        r = sd_device_get_subsystem(device, &identity.subsystem);
        if (r < 0 && r != -ENOENT)
                return r;

        *ret = identity;
        return 0;
}

static bool device_is_gone(sd_device *device) {
        const char *syspath;

        if (sd_device_get_syspath(device, &syspath) < 0)
                return false;

        return access(syspath, F_OK) < 0 && errno == ENOENT;
}

int accept_config_apply(const AcceptConfig *config, sd_device *device, bool dry_run) {
        const char *token, *current = NULL;
        int r;

        assert(config);
        assert(device);

        token = ASSERT_PTR(accept_trust_level_to_string(config->trust_level));

        /* The kernel refuses any write once a driver has been probed, even of the current value. */
        r = sd_device_get_sysattr_value(device, ACCEPT_TRUST_POLICY_SYSATTR, &current);
        if (r >= 0 && streq(current, token)) {
                log_device_debug(device, "'%s' is already set to '%s', not writing it.",
                                 ACCEPT_TRUST_POLICY_SYSATTR, token);
                return 0;
        }
        if (r == -ENOENT) {
                if (device_is_gone(device))
                        return log_device_debug_errno(device, SYNTHETIC_ERRNO(ENODEV),
                                                      "Device vanished while applying trust level, ignoring.");

                return log_device_warning_errno(device, r,
                                                "Cannot apply trust level '%s' from %s, device has no '%s' attribute "
                                                "(kernel without support for it?), ignoring.",
                                                token, config->filename, ACCEPT_TRUST_POLICY_SYSATTR);
        }

        if (dry_run) {
                log_device_debug(device, "Dry run, not writing '%s' to '%s' (current value: '%s').",
                                 token, ACCEPT_TRUST_POLICY_SYSATTR, r >= 0 ? current : "n/a");
                return 0;
        }

        r = sd_device_set_sysattr_value(device, ACCEPT_TRUST_POLICY_SYSATTR, token);
        if (r >= 0) {
                log_device_info(device, "Set '%s' to '%s', as configured in %s.",
                                ACCEPT_TRUST_POLICY_SYSATTR, token, config->filename);
                return 0;
        }

        /* The failed write dropped the cached value, hence this reads it again. */
        if (r == -EBUSY &&
            sd_device_get_sysattr_value(device, ACCEPT_TRUST_POLICY_SYSATTR, &current) >= 0 &&
            streq(current, token)) {
                log_device_debug(device, "'%s' is already set to '%s', not changing it.",
                                 ACCEPT_TRUST_POLICY_SYSATTR, token);
                return 0;
        }

        if (r == -EBUSY)
                return log_device_warning_errno(device, r,
                                                "Cannot apply trust level '%s' from %s, it can only be changed "
                                                "before a driver is probed for the device, ignoring.",
                                                token, config->filename);

        if (r == -ENOENT && device_is_gone(device))
                return log_device_debug_errno(device, SYNTHETIC_ERRNO(ENODEV),
                                              "Device vanished while applying trust level, ignoring.");

        return log_device_warning_errno(device, r,
                                        "Failed to write '%s' to '%s', as configured in %s, ignoring: %m",
                                        token, ACCEPT_TRUST_POLICY_SYSATTR, config->filename);
}

int accept_config_apply_device(const AcceptConfigContext *ctx, sd_device *device, bool dry_run, FILE *report) {
        AcceptDeviceIdentity identity;
        const AcceptConfig *config;
        const char *syspath;
        int r;

        assert(ctx);
        assert(device);

        r = accept_device_identity_get(device, &identity);
        if (r < 0) {
                log_device_debug_errno(device, r, "Failed to get the identity of the device, ignoring: %m");
                return 0;
        }

        config = accept_config_get(ctx, &identity);
        if (!config)
                return 0;

        if (report && sd_device_get_syspath(device, &syspath) >= 0)
                fprintf(report, "%s: %s (%s)\n",
                        syspath, accept_trust_level_to_string(config->trust_level), config->filename);

        r = accept_config_apply(config, device, dry_run);
        if (r < 0)
                return r;

        return 1;
}

int accept_device_enumerator_new(sd_device_enumerator **ret) {
        _cleanup_(sd_device_enumerator_unrefp) sd_device_enumerator *e = NULL;
        int r;

        assert(ret);

        r = sd_device_enumerator_new(&e);
        if (r < 0)
                return r;

        /* We are typically run before udev, hence no device is initialized yet. */
        r = sd_device_enumerator_allow_uninitialized(e);
        if (r < 0)
                return r;

        r = device_enumerator_scan_devices(e);
        if (r < 0)
                return r;

        *ret = TAKE_PTR(e);
        return 0;
}

int accept_config_apply_all(
                const AcceptConfigContext *ctx,
                bool dry_run,
                FILE *report,
                unsigned *ret_n_selected,
                unsigned *ret_n_failed) {

        _cleanup_(sd_device_enumerator_unrefp) sd_device_enumerator *e = NULL;
        unsigned n_selected = 0, n_failed = 0;
        sd_device *device;
        int r;

        assert(ctx);

        if (!accept_config_is_empty(ctx)) {
                r = accept_device_enumerator_new(&e);
                if (r < 0)
                        return r;

                FOREACH_DEVICE_AND_SUBSYSTEM(e, device) {
                        r = accept_config_apply_device(ctx, device, dry_run, report);
                        if (r == 0)
                                continue;

                        n_selected++;

                        if (r < 0 && r != -ENODEV)
                                n_failed++;
                }
        }

        if (ret_n_selected)
                *ret_n_selected = n_selected;
        if (ret_n_failed)
                *ret_n_failed = n_failed;

        return 0;
}

int config_parse_accept_device(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        AcceptConfig *config = ASSERT_PTR(userdata);
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        if (isempty(rvalue)) {
                FOREACH_ARRAY(selector, config->selectors, config->n_selectors)
                        accept_selector_done(selector);

                config->selectors = mfree(config->selectors);
                config->n_selectors = 0;
                return 0;
        }

        for (const char *p = rvalue;;) {
                _cleanup_(accept_selector_done) AcceptSelector selector = {
                        .type = _ACCEPT_SELECTOR_TYPE_INVALID,
                };
                _cleanup_free_ char *word = NULL;

                r = extract_first_word(&p, &word, /* separators= */ NULL, EXTRACT_UNQUOTE|EXTRACT_RETAIN_ESCAPE);
                if (r == 0)
                        return 0;
                if (r == -ENOMEM)
                        return log_oom();
                if (r < 0) {
                        log_syntax(unit, LOG_WARNING, filename, line, r,
                                   "Invalid syntax, ignoring: %s", rvalue);
                        return 0;
                }

                r = accept_selector_parse(word, &selector);
                if (r == -ENOMEM)
                        return log_oom();
                if (r < 0) {
                        log_syntax(unit, LOG_WARNING, filename, line, r,
                                   "Invalid device selector '%s', expected 'name:<name>', 'pci:<address>' or "
                                   "'path:<sysfs path>', ignoring: %m", word);
                        continue;
                }

                if (!GREEDY_REALLOC(config->selectors, config->n_selectors + 1))
                        return log_oom();

                config->selectors[config->n_selectors++] = TAKE_STRUCT(selector);
        }
}

DEFINE_CONFIG_PARSE_ENUM_WITH_DEFAULT(config_parse_accept_trust_level, accept_trust_level, AcceptTrustLevel,
                                      _ACCEPT_TRUST_LEVEL_INVALID);
