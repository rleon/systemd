# SPDX-License-Identifier: LGPL-2.1-or-later

device_accept_gperf_gperf = files('accept-config-gperf.gperf')

accept_config_gperf_c = custom_target(
        input : device_accept_gperf_gperf,
        output : 'accept-config-gperf.c',
        command : [gperf_cmdline, '@INPUT@', '--output-file', '@OUTPUT@'])

generated_sources += accept_config_gperf_c

executables += [
        libexec_template + {
                'name' : 'systemd-device-accept-d',
                'sources' : files('device-accept-d.c'),
                'export' : files(
                        'accept-config.c',
                        'accept-bind.c',
                        'accept-flow.c',
                ) + accept_config_gperf_c,
                'install_tag' : 'udev',
        },
        test_template + {
                'sources' : files('test-accept-config.c'),
                'import' : ['systemd-device-accept-d'],
        },
        test_template + {
                'sources' : files('test-device-accept-d.c'),
                'import' : ['systemd-device-accept-d'],
                'link_args' : [
                        '-Wl,--wrap=read_one_line_file_at',
                        '-Wl,--wrap=write_string_file_full_label',
                        '-Wl,--wrap=faccessat',
                        '-Wl,--wrap=readlink_value',
                        '-Wl,--wrap=sd_device_new_from_syspath',
                        '-Wl,--wrap=sd_device_get_driver',
                ],
        },
        fuzz_template + {
                'sources' : files('fuzz-accept-parser.c'),
                'import' : ['systemd-device-accept-d'],
        },
]

install_emptydir(libexecdir / 'accept.d', install_tag : 'udev')

if install_sysconfdir_samples
        install_data('device-accept.conf',
                     install_dir : pkgconfigfiledir,
                     install_tag : 'udev')
endif

if install_sysconfdir
        install_emptydir(sysconfdir / 'systemd/accept.d', install_tag : 'udev')
endif
