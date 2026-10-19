/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "sd-device.h"

#include "accept-config.h"
#include "forward.h"

#define ACCEPT_KERNEL_CMDLINE_KEY "device_trust"

typedef struct AcceptKernelModules AcceptKernelModules;

int accept_kernel_modules_load(const char *dir, AcceptKernelModules **ret);
AcceptKernelModules* accept_kernel_modules_free(AcceptKernelModules *m);
DEFINE_TRIVIAL_CLEANUP_FUNC(AcceptKernelModules*, accept_kernel_modules_free);

int accept_device_is_bound_to_builtin(sd_device *device);

int accept_device_might_bind_builtin(sd_device *device, const AcceptKernelModules *modules);

int accept_kernel_cmdline(const AcceptConfigContext *ctx, const AcceptKernelModules *modules, char **ret);
