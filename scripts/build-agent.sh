#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
TASK_ROOT=$(pwd)
TC="$TASK_ROOT/work/toolchains/mingw/usr"
export PATH="$TC/bin:$PATH"
CC="$TC/bin/i686-w64-mingw32-gcc-posix"
MBED="$TASK_ROOT/work/toolchains/mbedtls-3.6.7"
# Rebuild TLS when its caller-supplied configuration or compiler flags change.
CONFIG_HASH=$(cat agent/windows/pilot_config.h scripts/build-agent.sh | sha256sum | cut -d ' ' -f 1)
if [ ! -f "$MBED/.pilot-config-hash" ] || [ "$(cat "$MBED/.pilot-config-hash")" != "$CONFIG_HASH" ]; then
 make -C "$MBED/library" clean
 printf '%s\n' "$CONFIG_HASH" > "$MBED/.pilot-config-hash"
fi
# Paths contain spaces; pass each include as an argument, not through CFLAGS splitting.
make -C "$MBED/library" -j2 CC=i686-w64-mingw32-gcc-posix AR=i686-w64-mingw32-ar CFLAGS="-O2 -ffunction-sections -fdata-sections -D__USE_MINGW_ANSI_STDIO=1 -D_WIN32_WINNT=0x0501 -DWINVER=0x0501 -DMBEDTLS_USER_CONFIG_FILE='\"$TASK_ROOT/agent/windows/pilot_config.h\"'" libmbedtls.a libmbedx509.a libmbedcrypto.a
mkdir -p work/bin
python3 scripts/agent_artifacts.py prepare
"$CC" -std=c99 -O2 -s -ffunction-sections -fdata-sections -D__USE_MINGW_ANSI_STDIO=1 -Wall -Wextra -D_WIN32_WINNT=0x0501 -DWINVER=0x0501 -DMBEDTLS_USER_CONFIG_FILE='"pilot_config.h"' -Iagent/windows -Icollectors/windows -Iwork/bin -I"$MBED/include" agent/windows/agent.c collectors/windows/*.c "$MBED/library/libmbedtls.a" "$MBED/library/libmbedx509.a" "$MBED/library/libmbedcrypto.a" -static -static-libgcc -Wl,--gc-sections,--no-insert-timestamp -Wl,--major-subsystem-version,5,--minor-subsystem-version,1 -lws2_32 -ladvapi32 -liphlpapi -o work/bin/forensics-agent-x86.exe
"$TC/bin/i686-w64-mingw32-objdump" -p work/bin/forensics-agent-x86.exe > work/bin/agent-imports.txt

if rg -q "_vsnprintf_s|BCryptGenRandom|GetTickCount64|InitializeCriticalSectionEx" work/bin/agent-imports.txt; then
 echo "Forbidden legacy import" >&2; exit 1
fi

python3 scripts/agent_artifacts.py package
