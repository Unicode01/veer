# shellcheck shell=sh
# Sourced by the scripts that run cargo. Under sudo, rustup looks for its
# toolchains in root's home; when cargo cannot run there, use the invoking
# user's toolchains, as `sudo env "PATH=$PATH" sh scripts/...` runs expect.
if [ "$(id -u)" = 0 ] && [ -n "${SUDO_USER:-}" ] && [ -z "${RUSTUP_HOME:-}" ] &&
	! cargo --version >/dev/null 2>&1; then
	veer_rust_home=$(getent passwd "$SUDO_USER" | cut -d: -f6)
	if [ -n "$veer_rust_home" ] && [ -d "$veer_rust_home/.rustup" ]; then
		RUSTUP_HOME="$veer_rust_home/.rustup"
		export RUSTUP_HOME
	fi
	unset veer_rust_home
fi
