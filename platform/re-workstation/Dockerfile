# Reverse-engineering workstation — Binary Ninja over carved memory regions.
#
# Carved regions are live malware, so this is the most hazardous interactive surface in
# the platform. The threat direction is the reverse of the analyst workstation: that tier
# is hardened to stop evidence getting OUT, this one to stop malware getting ANYWHERE.
#
# Binary Ninja is fetched at BUILD time. The free edition needs no licence, activation or
# call-home, so a session needs no network at all — which is why `launch.sh` runs the
# container with `--network none`. Network exists only while this image is built.
FROM docker.io/library/debian:12@sha256:813017f3d62be4b5891a7acca6a01bdcd4b8513daa81b1ab99d3a50385b26931

ENV DEBIAN_FRONTEND=noninteractive \
    QT_QPA_PLATFORM=xcb \
    QT_QPA_PLATFORM_PLUGIN_PATH=/binja/binaryninja

# LANG is set after this step, not before it. `update-locale` validates the environment it
# runs in, so declaring LANG=en_US.UTF-8 up front makes it reject the very locale this step
# is generating — the build fails on the line that was supposed to fix locales.
RUN groupadd -g 1001 binja \
    && useradd -u 1001 -g 1001 -m -s /bin/bash binja \
    && apt-get update \
    && apt-get install -y --no-install-recommends \
        bash ca-certificates coreutils locales unzip wget \
        libxcb-cursor0 libxcb-icccm4 libxcb-keysyms1 libxcb-shape0 libxcb-xkb1 \
        libxkbcommon-x11-0 libxcb-xinerama0 libxcb-randr0 libxcb-image0 libxcb-shm0 \
        libxcb-sync1 libxcb-xfixes0 libxkbcommon0 libxcb1 libx11-6 \
        libstdc++6 libglib2.0-0 libgtk-3-0 libnss3 libfontconfig1 libglu1-mesa \
        libegl1 libgl1-mesa-glx libdbus-1-3 libexpat1 libuuid1 liblzma5 liblz4-1 \
        libgcrypt20 libgpg-error0 libcurl4 python3 fontconfig \
    && sed -i 's/^# *en_US.UTF-8 UTF-8/en_US.UTF-8 UTF-8/' /etc/locale.gen \
    && locale-gen \
    && printf 'LANG=en_US.UTF-8\n' > /etc/default/locale \
    && rm -rf /var/lib/apt/lists/*

# Now that the locale exists, Qt can be told to use it.
ENV LANG=en_US.UTF-8 \
    LC_ALL=en_US.UTF-8

RUN mkdir -p /binja /regions \
    && cd /binja \
    && wget -q --progress=bar:force https://cdn.binary.ninja/installers/binaryninja_free_linux.zip -O binja.zip \
    && unzip -q binja.zip \
    && chmod +x /binja/binaryninja \
    && rm -f binja.zip \
    && chown -R binja:binja /binja /regions

# No plugins are installed: nothing here should extend what the tool does, and a plugin
# directory is one more thing a malicious sample could try to write into.

# Defence in depth against a future build gaining a call-home: settings are pinned so
# external fetches and telemetry stay off even though this session has no route out.
#
# The key names are the ones Binary Ninja writes back itself. An invented or renamed key is
# silently discarded when it loads the file, which looks identical to a pin that is working.
RUN mkdir -p /home/binja/.binaryninja \
    && printf '%s\n' '{' \
        '  "network.enableExternalResources": false,' \
        '  "updates.showAllVersions": false,' \
        '  "analysis.suppressInformationalWarnings": true,' \
        '  "corePlugins.enable": false,' \
        '  "python.autoLoadPluginModules": false,' \
        '  "python.autoLoadUserPluginModules": false' \
        '}' > /home/binja/.binaryninja/settings.json \
    && chown -R binja:binja /home/binja/.binaryninja

WORKDIR /binja/binaryninja
USER binja
CMD ["./binaryninja"]
