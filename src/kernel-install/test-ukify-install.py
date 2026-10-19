#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later

import os
import pathlib
import runpy
import subprocess
import sys
import tempfile
import types
import unittest.mock

ns = runpy.run_path(sys.argv[1], run_name='not_main')


class FakePath:
    files = {
        '/conf-root/cmdline': 'root=conf\n# ignored\nquiet splash\n',
        '/proc/cmdline': 'BOOT_IMAGE=/vmlinuz initrd=/initrd root=fake quiet\n',
    }

    def __init__(self, path):
        self.path = os.fspath(path)

    def __truediv__(self, name):
        return type(self)(os.path.join(self.path, name))

    def exists(self):
        return self.path in self.files

    def read_text(self):
        return self.files[self.path]


module_globals = ns['kernel_cmdline_base'].__globals__
module_globals['Path'] = FakePath

# Mock subprocess.run to simulate not being in a container, so the test
# works regardless of the environment (including container-based CI).
os.environ.pop('KERNEL_INSTALL_CONF_ROOT', None)
with unittest.mock.patch.object(subprocess, 'run', return_value=subprocess.CompletedProcess([], 1)):
    assert ns['kernel_cmdline_base']() == ['root=fake', 'quiet']

os.environ['KERNEL_INSTALL_CONF_ROOT'] = '/conf-root'
assert ns['kernel_cmdline_base']() == ['root=conf', 'quiet', 'splash']

os.environ['KERNEL_INSTALL_CONF_ROOT'] = '/empty-conf-root'
assert ns['kernel_cmdline_base']() == []

# Test that /proc/cmdline is skipped in containers
os.environ.pop('KERNEL_INSTALL_CONF_ROOT', None)
with unittest.mock.patch.object(subprocess, 'run', return_value=subprocess.CompletedProcess([], 0)):
    assert ns['kernel_cmdline_base']() == [], 'should return empty in container'

with tempfile.TemporaryDirectory() as staging_area:
    opts = types.SimpleNamespace(
        staging_area=pathlib.Path(staging_area), entry_token='entry', machine_id='machine',
        kernel_version='1.2.3', kernel_image=pathlib.Path('/kernel'), initrd=[])
    assert ns['kernel_cmdline_staged'](opts) == []

    (opts.staging_area / 'cmdline-b').write_text('opt3\n')
    (opts.staging_area / 'cmdline-a').write_text('opt1  opt2\n')
    (opts.staging_area / 'initrd').write_text('not a command line\n')
    assert ns['kernel_cmdline_staged'](opts) == ['opt1', 'opt2', 'opt3']

    old_policy = 'device_trust=pci:0000:01:00.0=disabled'
    older_policy = 'device_trust=pci:0000:02:00.0=adversary'
    new_policy = 'device_trust=pci:0000:01:00.0=default'
    FakePath.files['/proc/cmdline'] = f'BOOT_IMAGE=/vmlinuz root=fake {older_policy} quiet {old_policy}\n'
    with unittest.mock.patch.object(subprocess, 'run', return_value=subprocess.CompletedProcess([], 1)):
        # A skipped generator must not change inherited policy.
        assert ns['kernel_cmdline'](opts).split() == ['root=fake', older_policy, 'quiet', old_policy]

        generated = opts.staging_area / 'cmdline-device-accept'
        generated.write_text(new_policy + '\n')
        assert ns['kernel_cmdline'](opts).split() == ['root=fake', 'quiet']
        assert ns['kernel_cmdline_staged'](opts) == ['opt1', 'opt2', 'opt3', new_policy]

        # Removing the last rule still discards the previous boot's policy.
        generated.write_text('')
        assert ns['kernel_cmdline'](opts).split() == ['root=fake', 'quiet']
        assert ns['kernel_cmdline_staged'](opts) == ['opt1', 'opt2', 'opt3']

    generated.write_text(new_policy + '\n')
    FakePath.files['/conf-root/cmdline'] = f'root=conf {old_policy}\n'
    os.environ['KERNEL_INSTALL_CONF_ROOT'] = '/conf-root'
    assert ns['kernel_cmdline'](opts).split() == ['root=conf', old_policy]
    assert ns['kernel_cmdline_staged'](opts, device_trust_configured=True) == ['opt1', 'opt2', 'opt3']

    # Explicit UKI/Cmdline= and @file policies also win over generated options.
    explicit = f'root=explicit quoted="two  spaces" {old_policy}'
    cmdline_file = opts.staging_area / 'explicit'
    cmdline_file.write_text(explicit)
    for other_staged in (True, False):
        if not other_staged:
            (opts.staging_area / 'cmdline-a').unlink()
            (opts.staging_area / 'cmdline-b').unlink()
        for cmdline in (explicit, f'@{cmdline_file}'):
            ukify_options = types.SimpleNamespace(cmdline=cmdline)
            ukify = types.SimpleNamespace(
                create_parser=lambda: types.SimpleNamespace(parse_args=lambda args: ukify_options),
                apply_config=lambda options: None,
                resolve_at_path=lambda value: pathlib.Path(value[1:]) if value.startswith('@') else value,
                finalize_options=lambda options: None,
                check_inputs=lambda options: None,
                make_uki=lambda options: None)
            with unittest.mock.patch.dict(module_globals, {
                'Path': pathlib.Path,
                'load_module': lambda name, path: ukify,
                'uki_conf_location': lambda: None,
                'devicetree_file_location': lambda options: None,
            }):
                ns['call_ukify'](opts)
            if other_staged:
                assert ukify_options.cmdline.split() == [*explicit.split(), 'opt1', 'opt2', 'opt3']
            else:
                # Ignoring generated policy must preserve the original @file reference and contents.
                assert ukify_options.cmdline == cmdline
            assert cmdline_file.read_text() == explicit
