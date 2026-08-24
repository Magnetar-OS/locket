# Locket's build and install recipes.
#
# This is the packager's path: it builds and copies files, and stops there. It
# does not take the `org.freedesktop.secrets` name, enable the user unit, or
# touch a PAM stack — those are decisions for the person using the machine, and
# `scripts/locket-setup` is what walks them through it, reversibly.

# Binaries this workspace produces. NAME and APPID are exported the way the
# rest of the ecosystem does it, so a nested justfile would inherit them.
export NAME := 'locket'
daemon := 'locketd'
cli := 'locket-cli'
applet := 'locket-applet'
native-host := 'locket-native-host'
pam-module := 'libpam_locket.so'

# The unique ids of the two desktop components.
export APPID := 'io.github.entro314labs.Locket'
applet-appid := 'io.github.entro314labs.LocketApplet'

# Path to root file system, which defaults to `/`.
rootdir := ''
# The prefix for the `/usr` directory.
prefix := '/usr'
# The location of the cargo target directory.
cargo-target-dir := env('CARGO_TARGET_DIR', 'target')
# `just debug=1 install` installs the debug build, for testing an install
# without paying for a release compile.
debug := '0'

base-dir := absolute_path(clean(rootdir / prefix))
release-dir := cargo-target-dir / (if debug == '1' { 'debug' } else { 'release' })

bin-dst := base-dir / 'bin'
desktop-dst := base-dir / 'share' / 'applications'
metainfo-dst := base-dir / 'share' / 'metainfo' / (APPID + '.metainfo.xml')
icons-dst := base-dir / 'share' / 'icons' / 'hicolor'
icon-svg-dst := icons-dst / 'scalable' / 'apps' / (APPID + '.svg')
icon-symbolic-dst := icons-dst / 'symbolic' / 'apps' / (APPID + '-symbolic.svg')
systemd-dst := base-dir / 'lib' / 'systemd' / 'user' / 'locket-daemon.service'
# xdg-desktop-portal only scans XDG_DATA_DIRS, so a portal backend genuinely
# has to be system-wide — a copy under ~/.local/share is never found.
portal-dst := base-dir / 'share' / 'xdg-desktop-portal' / 'portals' / 'locket.portal'
# Where PAM modules live differs by distribution; `pam-dir` is overridable for
# Debian's `/usr/lib/<triplet>/security`.
pam-dir := base-dir / 'lib' / 'security'

metainfo-src := 'res' / (APPID + '.metainfo.xml')
desktop-src := 'res' / (APPID + '.desktop')
applet-desktop-src := 'res' / (applet-appid + '.desktop')
icon-src := 'res' / 'icons' / 'hicolor' / 'scalable' / 'apps' / (APPID + '.svg')
icon-symbolic-src := 'res' / 'icons' / 'hicolor' / 'symbolic' / 'apps' / (APPID + '-symbolic.svg')

# Default recipe which runs `just build-release`
default: build-release

# Everything CI runs, cheapest failure first
#
# `fmt-check` is deliberately not in here: the tree is not rustfmt-clean, and
# making it so is a decision about house style rather than something a check
# should force. The recipe exists for when that decision is made.
check-all: validate-metadata check test

# Runs `cargo clean`
clean:
    cargo clean

# Removes vendored dependencies
clean-vendor:
    rm -rf .cargo vendor vendor.tar

# `cargo clean` and removes vendored dependencies
clean-dist: clean clean-vendor

# Compiles with debug profile
build-debug *args:
    cargo build --locked {{args}}

# Compiles with release profile
build-release *args: (build-debug '--release' args)

# Compiles release profile with vendored dependencies
build-vendored *args: vendor-extract (build-release '--frozen --offline' args)

# Runs a clippy check
check *args:
    cargo clippy --all-features --all-targets --locked {{args}} -- -W clippy::pedantic

# Runs a clippy check with JSON message format
check-json: (check '--message-format=json')

# Checks formatting without rewriting anything
fmt-check:
    cargo fmt --all -- --check

# Rewrites formatting
fmt:
    cargo fmt --all

# Runs the test suite (GUI crates included; none of it needs a display)
test *args:
    cargo test --locked --workspace {{args}}

# Checks the desktop entries and AppStream metadata against their specs
validate-metadata:
    desktop-file-validate {{desktop-src}}
    desktop-file-validate {{applet-desktop-src}}
    appstreamcli validate --no-net {{metainfo-src}}

# Also checks that the URLs in the metadata actually resolve
validate-metadata-urls:
    appstreamcli validate {{metainfo-src}}

# Run the application for testing purposes
run *args:
    env RUST_LOG=locket=debug RUST_BACKTRACE=full cargo run --bin {{NAME}} {{args}}

# Runs the daemon in the foreground
run-daemon *args:
    env RUST_LOG=locket=debug cargo run --bin {{daemon}} -- {{args}}

# Installs every component, without wiring any of them up
install:
    install -Dm0755 {{ release-dir / NAME }} {{ bin-dst / NAME }}
    install -Dm0755 {{ release-dir / daemon }} {{ bin-dst / daemon }}
    install -Dm0755 {{ release-dir / cli }} {{ bin-dst / cli }}
    install -Dm0755 {{ release-dir / applet }} {{ bin-dst / applet }}
    install -Dm0755 {{ release-dir / native-host }} {{ bin-dst / native-host }}
    install -Dm0755 {{ release-dir / pam-module }} {{ pam-dir / 'pam_locket.so' }}
    install -Dm0644 {{desktop-src}} {{ desktop-dst / (APPID + '.desktop') }}
    install -Dm0644 {{applet-desktop-src}} {{ desktop-dst / (applet-appid + '.desktop') }}
    install -Dm0644 {{metainfo-src}} {{metainfo-dst}}
    install -Dm0644 {{icon-src}} {{icon-svg-dst}}
    install -Dm0644 {{icon-symbolic-src}} {{icon-symbolic-dst}}
    install -Dm0644 res/locket-daemon.service {{systemd-dst}}
    install -Dm0644 res/locket.portal {{portal-dst}}
    # Both are caches and neither notices a new file on its own; "Open With"
    # reads the first. Only poked on a live install — a staged tree
    # (rootdir set) belongs to a package manager with hooks of its own.
    if [ -z '{{rootdir}}' ]; then \
        update-desktop-database {{desktop-dst}} 2>/dev/null || true; \
        gtk-update-icon-cache -t {{icons-dst}} 2>/dev/null || true; \
    fi
    @echo 'Installed. Nothing is wired up yet — run scripts/locket-setup to'
    @echo 'import your existing keyring and take over the Secret Service.'

# Uninstalls installed files
uninstall:
    rm -f {{ bin-dst / NAME }} {{ bin-dst / daemon }} {{ bin-dst / cli }}
    rm -f {{ bin-dst / applet }} {{ bin-dst / native-host }}
    rm -f {{ pam-dir / 'pam_locket.so' }}
    rm -f {{ desktop-dst / (APPID + '.desktop') }} {{ desktop-dst / (applet-appid + '.desktop') }}
    rm -f {{metainfo-dst}} {{icon-svg-dst}} {{icon-symbolic-dst}}
    rm -f {{systemd-dst}} {{portal-dst}}

# Vendor dependencies locally
vendor:
    mkdir -p .cargo
    cargo vendor | head -n -1 > .cargo/config.toml
    echo 'directory = "vendor"' >> .cargo/config.toml
    tar pcf vendor.tar vendor
    rm -rf vendor

# Extracts vendored dependencies
vendor-extract:
    rm -rf vendor
    tar pxf vendor.tar
