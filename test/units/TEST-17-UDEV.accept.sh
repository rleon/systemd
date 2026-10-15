#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

DAEMON=/usr/lib/systemd/systemd-device-accept-d
NET=/sys/devices/virtual/net

at_exit() {
    set +e

    systemctl stop systemd-device-accept-d.service
    rm -rf /run/systemd/accept.d /run/systemd/device-accept.conf.d
    for i in 0 1 2 3 4; do
        ip link del "testaccept$i"
    done
    for i in 4242 4243; do
        if [[ -e "/sys/bus/netdevsim/devices/netdevsim$i" ]]; then
            echo "$i" >/sys/bus/netdevsim/del_device
        fi
    done
}

trap at_exit EXIT

dry_run() {
    if [[ -e "$NET/lo/trust_policy" ]]; then
        output="$("$DAEMON" --dry-run)"
    else
        output="$("$DAEMON" --dry-run 2>/dev/null || :)"
    fi
}

assert_selected() {
    local line="${1:?}: ${2:?} (${3:?})"

    if ! grep -F -x -e "$line" >/dev/null <<<"$output"; then
        echo "'$line' not found in the output of --dry-run:" >&2
        echo "$output" >&2
        return 1
    fi
}

assert_not_selected() {
    if grep -F -e "${1:?}: " >/dev/null <<<"$output"; then
        echo "'$1' found in the output of --dry-run:" >&2
        echo "$output" >&2
        return 1
    fi
}

mkdir -p /run/systemd/accept.d

for i in 0 1 2 3; do
    ip link add "testaccept$i" type dummy
done
udevadm wait --timeout=30 --settle "$NET"/testaccept{0,1,2,3}

cat >/run/systemd/accept.d/10-test.conf <<EOF
[Match]
Device=name:testaccept0
Device=path:$NET/testaccept1 path:$NET/nonexistent

[Accept]
TrustLevel=adversary
EOF

cat >/run/systemd/accept.d/20-test.conf <<EOF
[Match]
Device=name:testaccept*

[Accept]
TrustLevel=full
EOF

cat >/run/systemd/accept.d/30-invalid.conf <<EOF
[Match]
Device=testaccept0 pci:zz path:/sys/class/net/testaccept0

[Accept]
TrustLevel=bogus
EOF

dry_run
assert_selected "$NET/testaccept0" adversary /run/systemd/accept.d/10-test.conf
assert_selected "$NET/testaccept1" adversary /run/systemd/accept.d/10-test.conf
assert_selected "$NET/testaccept2" full /run/systemd/accept.d/20-test.conf
assert_selected "$NET/testaccept3" full /run/systemd/accept.d/20-test.conf
assert_not_selected "$NET/lo"

mkdir /run/systemd/accept.d/20-test.conf.d
cat >/run/systemd/accept.d/20-test.conf.d/50-override.conf <<EOF
[Match]
Device=
Device=name:testaccept2

[Accept]
TrustLevel=default
EOF

dry_run
assert_selected "$NET/testaccept0" adversary /run/systemd/accept.d/10-test.conf
assert_selected "$NET/testaccept2" default /run/systemd/accept.d/20-test.conf
assert_not_selected "$NET/testaccept3"

ln -sf /dev/null /run/systemd/accept.d/10-test.conf

dry_run
assert_not_selected "$NET/testaccept0"
assert_not_selected "$NET/testaccept1"
assert_selected "$NET/testaccept2" default /run/systemd/accept.d/20-test.conf

rm -rf /run/systemd/accept.d/10-test.conf /run/systemd/accept.d/20-test.conf /run/systemd/accept.d/20-test.conf.d

dry_run
assert_eq "$output" ""

(! "$DAEMON" argument)
"$DAEMON" --help >/dev/null

before="$(systemctl show --property=Before --value systemd-device-accept-d.service)"
assert_in "systemd-udevd.service" "$before"
assert_in "systemd-udev-trigger.service" "$before"
assert_in "systemd-modules-load.service" "$before"
assert_in "initrd-switch-root.target" "$before"
assert_in "sysinit.target" "$(systemctl show --property=WantedBy --value systemd-device-accept-d.service)"

cat >/run/systemd/accept.d/46-hotplug.conf <<EOF
[Match]
Device=name:testaccept4

[Accept]
TrustLevel=adversary
EOF

systemctl start systemd-device-accept-d.service
assert_eq "$(systemctl show --property=ActiveState --value systemd-device-accept-d.service)" active
invocation="$(systemctl show --property=InvocationID --value systemd-device-accept-d.service)"

wait_for_log() {
    timeout 30 bash -c "until journalctl --sync && journalctl -b _SYSTEMD_INVOCATION_ID=$invocation -o cat | grep \"$1\" >/dev/null; do sleep .5; done"
}

ip link add testaccept4 type dummy
wait_for_log "testaccept4: .*'adversary'.*/run/systemd/accept.d/46-hotplug.conf"
if [[ -e "$NET/testaccept4/trust_policy" ]]; then
    assert_eq "$(cat "$NET/testaccept4/trust_policy")" adversary
    assert_eq "$(cat "$NET/testaccept4/trust")" disabled
fi

sed -i 's/TrustLevel=adversary/TrustLevel=disabled/' /run/systemd/accept.d/46-hotplug.conf
systemctl reload systemd-device-accept-d.service
wait_for_log "testaccept4: .*'disabled'.*/run/systemd/accept.d/46-hotplug.conf"
if [[ -e "$NET/testaccept4/trust_policy" ]]; then
    assert_eq "$(cat "$NET/testaccept4/trust_policy")" disabled
fi
assert_eq "$(systemctl show --property=ActiveState --value systemd-device-accept-d.service)" active

systemctl stop systemd-device-accept-d.service
assert_eq "$(systemctl show --property=Result --value systemd-device-accept-d.service)" success

if modprobe netdevsim; then
    mkdir -p /run/systemd/device-accept.conf.d
    cat >/run/systemd/device-accept.conf.d/50-test.conf <<EOF
[DeviceAccept]
HoldProbing=netdevsim
EOF

    cat >/run/systemd/accept.d/47-hold.conf <<EOF
[Match]
Device=name:netdevsim4243

[Accept]
TrustLevel=disabled
EOF

    systemctl start systemd-device-accept-d.service
    assert_eq "$(cat /sys/bus/netdevsim/drivers_autoprobe)" 0
    invocation="$(systemctl show --property=InvocationID --value systemd-device-accept-d.service)"

    echo "4242 1" >/sys/bus/netdevsim/new_device
    timeout 30 bash -c 'until [[ -e /sys/bus/netdevsim/devices/netdevsim4242/driver ]]; do sleep .5; done'

    echo "4243 1" >/sys/bus/netdevsim/new_device
    wait_for_log "netdevsim4243: .*'disabled'"
    if [[ -e /sys/bus/netdevsim/devices/netdevsim4243/trust_policy ]]; then
        assert_eq "$(cat /sys/bus/netdevsim/devices/netdevsim4243/trust_policy)" disabled
    fi
    [[ ! -e /sys/bus/netdevsim/devices/netdevsim4243/driver ]]

    systemctl stop systemd-device-accept-d.service
    assert_eq "$(cat /sys/bus/netdevsim/drivers_autoprobe)" 1

    rm -rf /run/systemd/device-accept.conf.d /run/systemd/accept.d/47-hold.conf
fi

pci_devices=(/sys/bus/pci/devices/*)
if [[ -e "${pci_devices[0]}" ]]; then
    bdf="$(basename "${pci_devices[0]}")"
    syspath="$(readlink -f "${pci_devices[0]}")"

    for address in "$bdf" "${bdf#0000:}" "${bdf^^}"; do
        cat >/run/systemd/accept.d/05-pci.conf <<EOF
[Match]
Device=pci:$address

[Accept]
TrustLevel=full
EOF

        dry_run
        assert_selected "$syspath" full /run/systemd/accept.d/05-pci.conf
    done

    cat >/run/systemd/accept.d/05-pci.conf <<EOF
[Match]
Device=pci:0000:ff:1f.7

[Accept]
TrustLevel=full
EOF

    dry_run
    assert_not_selected "$syspath"
fi
