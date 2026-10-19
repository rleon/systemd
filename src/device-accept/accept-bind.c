/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <unistd.h>

#include "sd-device.h"

#include "accept-bind.h"
#include "accept-config.h"
#include "alloc-util.h"
#include "conf-parser.h"
#include "device-util.h"
#include "extract-word.h"
#include "fileio.h"
#include "fs-util.h"
#include "log.h"
#include "parse-util.h"
#include "path-util.h"
#include "string-util.h"
#include "strv.h"

int accept_bus_get_autoprobe(const char *bus) {
        _cleanup_free_ char *value = NULL;
        const char *p;
        int r;

        assert(bus);

        if (!filename_is_valid(bus))
                return -EINVAL;

        p = strjoina("/sys/bus/", bus, "/drivers_autoprobe");
        r = read_one_line_file(p, &value);
        if (r < 0)
                return r;

        return parse_boolean(value);
}

int accept_bus_set_autoprobe(const char *bus, bool enable) {
        const char *p;

        assert(bus);

        if (!filename_is_valid(bus))
                return -EINVAL;

        p = strjoina("/sys/bus/", bus, "/drivers_autoprobe");
        return write_string_file(p, one_zero(enable), WRITE_STRING_FILE_DISABLE_BUFFER);
}

/* Unlike the sysname, this keeps '!' rather than replacing it with '/'. */
static int device_get_kernel_name(sd_device *device, char **ret) {
        const char *syspath;
        int r;

        assert(device);
        assert(ret);

        r = sd_device_get_syspath(device, &syspath);
        if (r < 0)
                return r;

        return path_extract_filename(syspath, ret);
}

int accept_device_get_bus(sd_device *device, const char **ret) {
        _cleanup_free_ char *name = NULL;
        const char *subsystem, *p;
        int r;

        assert(device);

        r = sd_device_get_subsystem(device, &subsystem);
        if (r < 0)
                return r;

        r = device_get_kernel_name(device, &name);
        if (r < 0)
                return r;

        /* A class may have the same name as a bus. */
        p = strjoina("/sys/bus/", subsystem, "/devices/", name);
        if (faccessat(AT_FDCWD, p, F_OK, AT_SYMLINK_NOFOLLOW) < 0)
                return -errno;

        if (ret)
                *ret = subsystem;
        return 0;
}

int accept_device_bind(const AcceptConfig *config, sd_device *device) {
        _cleanup_free_ char *name = NULL, *driver = NULL;
        const char *bus, *syspath, *p;
        int r;

        assert(device);

        r = accept_device_get_bus(device, &bus);
        if (r < 0)
                return log_device_debug_errno(device, r, "Failed to determine the bus of the device: %m");

        if (config) {
                r = accept_config_apply(config, device, /* dry_run= */ false);
                if (r == -ENODEV)
                        return r;
                if (r < 0)
                        return log_device_warning_errno(device, r,
                                                        "Not binding a driver to the device, as its trust level "
                                                        "could not be applied.");

                if (config->trust_level == ACCEPT_TRUST_LEVEL_DISABLED) {
                        log_device_debug(device, "Not binding a driver to the device, as it is disabled by %s.",
                                         config->filename);
                        return ACCEPT_BIND_REFUSED;
                }
        }

        r = device_get_kernel_name(device, &name);
        if (r < 0)
                return log_device_debug_errno(device, r, "Failed to get the name of the device: %m");

        p = strjoina("/sys/bus/", bus, "/drivers_probe");
        r = write_string_file(p, name, WRITE_STRING_FILE_DISABLE_BUFFER);
        if (r == -EAGAIN)
                return ACCEPT_BIND_RETRY;
        if (r == -ENODEV)
                return log_device_debug_errno(device, r, "Device vanished while probing its drivers, ignoring.");
        if (r < 0)
                return log_device_warning_errno(device, r, "Failed to probe the drivers for the device: %m");

        r = sd_device_get_syspath(device, &syspath);
        if (r < 0)
                return r;

        p = strjoina(syspath, "/driver");
        r = readlink_value(p, &driver);
        if (r == -ENOENT) {
                log_device_debug(device, "No driver is bound to the device.");
                return ACCEPT_BIND_NO_DRIVER;
        }
        if (r < 0)
                return log_device_debug_errno(device, r, "Failed to read the driver of the device: %m");

        if (config)
                log_device_info(device, "Bound driver '%s' to the device, as configured in %s.",
                                driver, config->filename);
        else
                log_device_debug(device, "Bound driver '%s' to the device.", driver);

        return ACCEPT_BIND_BOUND;
}

int config_parse_accept_buses(
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

        char ***buses = ASSERT_PTR(data);
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        if (isempty(rvalue)) {
                *buses = strv_free(*buses);
                return 0;
        }

        for (const char *p = rvalue;;) {
                _cleanup_free_ char *word = NULL;

                r = extract_first_word(&p, &word, /* separators= */ NULL, EXTRACT_UNQUOTE);
                if (r == -ENOMEM)
                        return log_oom();
                if (r < 0) {
                        log_syntax(unit, LOG_WARNING, filename, line, r, "Invalid syntax, ignoring: %s", rvalue);
                        return 0;
                }
                if (r == 0)
                        return 0;

                if (!filename_is_valid(word)) {
                        log_syntax(unit, LOG_WARNING, filename, line, 0, "Invalid bus name '%s', ignoring.", word);
                        continue;
                }

                if (strv_contains(*buses, word))
                        continue;

                r = strv_consume(buses, TAKE_PTR(word));
                if (r < 0)
                        return log_oom();
        }
}
