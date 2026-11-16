#!/bin/bash
set -e
echo 'Apple Find My People 登录在 Home Assistant 主机上的隔离 Linux 容器运行。'
echo '请在这个窗口输入 Apple 账号、密码和需要时的验证码。'
exec ssh -t ha 'sudo -n docker run --rm -it --name findmy-people-login --network host -e COREADI_PATH=/workspace/external/CoreADI.x86_64 -e FINDMY_MAC_ADI_CLI=/workspace/external/adi/tools/machoadi/mac_anisette.py -e FINDMY_MAC_ADI_STATE=/workspace/state/adi -e FINDMY_STATE_DIR=/workspace/state -e FINDMY_PROXY= -v /mnt/data/supervisor/homeassistant/.findmy-people-headless:/workspace findmy-people-research:local sh -c "python scripts/apple_probe.py login && python scripts/prepare_people.py"'
