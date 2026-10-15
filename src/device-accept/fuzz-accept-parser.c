/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "accept-config.h"
#include "fd-util.h"
#include "fuzz.h"
#include "strv.h"
#include "tmpfile-util.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
        _cleanup_(accept_config_ctx_freep) AcceptConfigContext *ctx = NULL;
        _cleanup_(unlink_tempfilep) char filename[] = "/tmp/fuzz-accept-config.XXXXXX";
        _cleanup_fclose_ FILE *f = NULL;

        if (outside_size_range(size, 0, 65536))
                return 0;

        fuzz_setup_logging();

        assert_se(fmkostemp_safe(filename, "r+", &f) == 0);
        if (size != 0)
                assert_se(fwrite(data, size, 1, f) == 1);

        fflush(f);

        assert_se(accept_config_ctx_new(STRV_MAKE("/nonexistent/fuzz-accept-config"), &ctx) >= 0);
        (void) accept_config_load_one(ctx, filename);

        const AcceptDeviceIdentity identities[] = {
                {
                        .sysname = "0000:01:00.0",
                        .subsystem = "pci",
                        .devpath = "/devices/pci0000:00/0000:00:1c.0/0000:01:00.0",
                },
                {
                        .sysname = "eth0",
                        .subsystem = "net",
                        .devpath = "/devices/pci0000:00/0000:00:1c.0/0000:01:00.0/net/eth0",
                },
                {
                        .sysname = "mlx5_0",
                        .devpath = "/devices/virtual/mlx5_0",
                },
        };

        FOREACH_ELEMENT(identity, identities)
                (void) accept_config_get(ctx, identity);

        return 0;
}
