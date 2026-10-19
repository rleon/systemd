/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdio.h>
#include <unistd.h>

#include "sd-device.h"

#include "accept-bind.h"
#include "accept-cmdline.h"
#include "accept-config.h"
#include "alloc-util.h"
#include "device-enumerator-private.h"
#include "device-util.h"
#include "extract-word.h"
#include "fd-util.h"
#include "fileio.h"
#include "fs-util.h"
#include "log.h"
#include "path-util.h"
#include "proc-cmdline.h"
#include "set.h"
#include "string-util.h"
#include "strv.h"

struct AcceptKernelModules {
        Set *modules;
        char **builtin_aliases;
};

AcceptKernelModules* accept_kernel_modules_free(AcceptKernelModules *m) {
        if (!m)
                return NULL;

        set_free(m->modules);
        strv_free(m->builtin_aliases);
        return mfree(m);
}

static char* module_name_normalize(char *name) {
        return string_replace_char(name, '-', '_');
}

static int modules_load(const char *dir, Set **modules) {
        _cleanup_fclose_ FILE *f = NULL;
        _cleanup_free_ char *path = NULL;
        int r;

        assert(dir);
        assert(modules);

        path = path_join(dir, "modules.dep");
        if (!path)
                return -ENOMEM;

        f = fopen(path, "re");
        if (!f)
                return -errno;

        for (;;) {
                _cleanup_free_ char *line = NULL, *name = NULL;

                r = read_line(f, LONG_LINE_MAX, &line);
                if (r < 0)
                        return r;
                if (r == 0)
                        return 0;

                line[strcspn(line, ":")] = 0;
                if (path_extract_filename(line, &name) < 0)
                        continue;

                name[strcspn(name, ".")] = 0;
                if (isempty(name))
                        continue;

                r = set_ensure_consume(modules, &string_hash_ops_free, module_name_normalize(TAKE_PTR(name)));
                if (r < 0)
                        return r;
        }
}

static int builtin_aliases_load(const char *dir, char ***aliases) {
        _cleanup_free_ char *path = NULL, *data = NULL;
        size_t size;
        int r;

        assert(dir);
        assert(aliases);

        path = path_join(dir, "modules.builtin.modinfo");
        if (!path)
                return -ENOMEM;

        r = read_full_file(path, &data, &size);
        if (r < 0)
                return r;

        /* read_full_file() appends a NUL byte, which terminates the last string. */
        for (const char *s = data; s < data + size; s += strlen(s) + 1) {
                const char *dot, *alias;

                dot = strchr(s, '.');
                if (!dot)
                        continue;

                alias = startswith(dot + 1, "alias=");
                if (isempty(alias))
                        continue;

                r = strv_extend(aliases, alias);
                if (r < 0)
                        return r;
        }

        return 0;
}

int accept_kernel_modules_load(const char *dir, AcceptKernelModules **ret) {
        _cleanup_(accept_kernel_modules_freep) AcceptKernelModules *m = NULL;
        int r;

        assert(dir);
        assert(ret);

        m = new0(AcceptKernelModules, 1);
        if (!m)
                return -ENOMEM;

        r = modules_load(dir, &m->modules);
        if (r < 0)
                return r;

        r = builtin_aliases_load(dir, &m->builtin_aliases);
        if (r < 0)
                return r;

        *ret = TAKE_PTR(m);
        return 0;
}

static int device_get_driver_module(sd_device *device, char **ret) {
        _cleanup_free_ char *path = NULL;
        const char *driver, *syspath;
        int r;

        assert(device);
        assert(ret);

        r = sd_device_get_driver(device, &driver);
        if (r == -ENOENT)
                return -ENXIO;
        if (r < 0)
                return r;

        r = sd_device_get_syspath(device, &syspath);
        if (r < 0)
                return r;

        path = path_join(syspath, "driver/module");
        if (!path)
                return -ENOMEM;

        return readlink_value(path, ret);
}

int accept_device_is_bound_to_builtin(sd_device *device) {
        _cleanup_free_ char *module = NULL, *path = NULL;
        int r;

        assert(device);

        r = device_get_driver_module(device, &module);
        if (r == -ENXIO)
                return false;
        if (r == -ENOENT)
                return true;
        if (r < 0)
                return r;

        /* Only modules that can be loaded and unloaded have this attribute. */
        path = path_join("/sys/module", module, "initstate");
        if (!path)
                return -ENOMEM;

        if (access(path, F_OK) >= 0)
                return false;
        if (errno != ENOENT)
                return -errno;

        return true;
}

int accept_device_might_bind_builtin(sd_device *device, const AcceptKernelModules *modules) {
        _cleanup_free_ char *module = NULL;
        const char *modalias;
        int r;

        assert(device);

        if (!modules)
                return true;

        /* modules.builtin misses some built-in modules, e.g. pcieportdrv, hence check modules.dep. */
        r = device_get_driver_module(device, &module);
        if (r == -ENOENT)
                return true;
        if (r >= 0 && !set_contains(modules->modules, module_name_normalize(module)))
                return true;
        if (r < 0 && r != -ENXIO)
                return r;

        r = sd_device_get_property_value(device, "MODALIAS", &modalias);
        if (r == -ENOENT)
                return false;
        if (r < 0)
                return r;

        return strv_fnmatch(modules->builtin_aliases, modalias);
}

static int kernel_cmdline_devices(Set **ret) {
        _cleanup_set_free_ Set *devices = NULL;
        _cleanup_free_ char *value = NULL;
        int r;

        assert(ret);

        r = proc_cmdline_get_key(ACCEPT_KERNEL_CMDLINE_KEY, /* flags= */ 0, &value);
        if (r < 0)
                return r;

        for (const char *p = value;;) {
                _cleanup_free_ char *word = NULL;
                char *e;

                r = extract_first_word(&p, &word, ",", /* flags= */ 0);
                if (r < 0)
                        return r;
                if (r == 0)
                        break;

                e = strrchr(word, '=');
                if (!e)
                        continue;
                *e = 0;

                r = set_ensure_consume(&devices, &string_hash_ops_free, TAKE_PTR(word));
                if (r < 0)
                        return r;
        }

        *ret = TAKE_PTR(devices);
        return 0;
}

static int device_append_option(
                const AcceptConfigContext *ctx,
                const AcceptKernelModules *modules,
                const Set *listed,
                sd_device *device,
                char **option) {

        AcceptDeviceIdentity identity;
        const AcceptConfig *config;
        const char *bus, *name, *level;
        int r;

        assert(ctx);
        assert(device);
        assert(option);

        if (accept_device_identity_get(device, &identity) < 0)
                return 0;

        config = accept_config_get(ctx, &identity);
        if (!config)
                return 0;

        if (accept_device_get_bus(device, &bus) < 0)
                return 0;

        name = identity.sysname;

        /* A device disabled by the running kernel's option has no driver to look at. */
        if (set_contains(listed, strjoina(bus, ":", name)))
                log_device_debug(device, "The device is listed on the kernel command line already.");
        else {
                r = accept_device_might_bind_builtin(device, modules);
                if (r < 0)
                        log_device_debug_errno(device, r,
                                               "Failed to determine whether a built-in driver might be bound to "
                                               "the device, assuming it might: %m");
                else if (r == 0) {
                        log_device_debug(device, "No built-in driver is bound to or matches the device.");
                        return 0;
                }
        }

        if (strpbrk(name, WHITESPACE ",=\"") || string_has_cc(name, /* ok= */ NULL)) {
                log_device_warning(device,
                                   "Cannot pass the trust level of the device on the kernel command line, as its "
                                   "name contains special characters, ignoring.");
                return 0;
        }

        level = accept_trust_level_to_string(config->trust_level);
        log_device_debug(device, "Passing trust level '%s' from %s on the kernel command line.",
                         level, config->filename);

        return strextendf_with_separator(option, ",", "%s:%s=%s", bus, name, level);
}

int accept_kernel_cmdline(const AcceptConfigContext *ctx, const AcceptKernelModules *modules, char **ret) {
        _cleanup_(sd_device_enumerator_unrefp) sd_device_enumerator *e = NULL;
        _cleanup_set_free_ Set *listed = NULL;
        _cleanup_free_ char *option = NULL;
        sd_device *device;
        int r;

        assert(ctx);
        assert(ret);

        if (accept_config_is_empty(ctx)) {
                *ret = NULL;
                return 0;
        }

        r = kernel_cmdline_devices(&listed);
        if (r < 0)
                log_debug_errno(r, "Failed to read the kernel command line, ignoring: %m");

        r = accept_device_enumerator_new(&e);
        if (r < 0)
                return r;

        FOREACH_DEVICE_AND_SUBSYSTEM(e, device) {
                r = device_append_option(ctx, modules, listed, device, &option);
                if (r < 0)
                        return r;
        }

        if (!option) {
                *ret = NULL;
                return 0;
        }

        if (!strprepend(&option, ACCEPT_KERNEL_CMDLINE_KEY "="))
                return -ENOMEM;

        *ret = TAKE_PTR(option);
        return 1;
}
