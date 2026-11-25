#!/usr/bin/env bash
# Uninstall with-secrets (GSeal): remove the program and its entry links.
#
#   uninstall.sh [--prefix DIR]
#
# Removes only what install.sh made: the version directories, current,
# previous and state in <prefix>/lib/gseal, and the bin/with-secrets and
# bin/gseal links. Entry links that install.sh replaced are put back.
#
# For every store whose entry install.sh switched (--link-store-bin, recorded
# in <prefix>/lib/gseal/state/store-bin), <store>/bin/with-secrets is put back
# from the backup made by that switch; nothing else in <store>/bin is touched,
# and the backup is kept. If that cannot be done (backup missing, copy fails),
# nothing is removed and the exit code is 1, so the switched entry keeps
# working.
#
# Never removes a store (env/, logs/, bin/ files), the config file or any
# backup.
set -uo pipefail

PROG=uninstall.sh
say()  { printf '%s\n' "$*"; }
warn() { printf '%s: %s\n' "$PROG" "$*" >&2; }

prefix=""
while [ $# -gt 0 ]; do
  case "$1" in
    --prefix) [ $# -ge 2 ] || exit 2; prefix=$2; shift 2 ;;
    --store) [ $# -ge 2 ] || exit 2; shift 2 ;;   # accepted for compatibility; stores come from the state
    -h|--help) sed -n '2,19p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) warn "unknown argument: $1"; exit 2 ;;
  esac
done
if [ -z "$prefix" ]; then
  if [ "$(id -u)" = 0 ]; then prefix=/usr/local; else prefix=$HOME/.local; fi
fi
case "$prefix" in /*) ;; *) prefix=$(pwd)/$prefix ;; esac
lib=$prefix/lib/gseal
bindir=$prefix/bin
state=$lib/state
entry=../lib/gseal/current/with-secrets
[ -L "$lib/current" ] || [ -d "$state" ] || { warn "with-secrets is not installed in $prefix"; exit 1; }

under() { case "$1/" in "$2"/*) return 0 ;; esac; return 1; }

# canon PATH: absolute path with symlinks of the existing part resolved and
# "." / ".." removed (the path need not exist), for comparing paths.
canon() {
  local p=$1 tail="" c out=()
  case "$p" in /*) ;; *) p=$(pwd)/$p ;; esac
  while [ ! -d "$p" ]; do tail=/$(basename "$p")$tail; p=$(dirname "$p"); done
  p=$(cd "$p" && pwd -P) || return 1
  local IFS=/
  for c in $p$tail; do
    case "$c" in
      ""|.) ;;
      ..) [ ${#out[@]} -gt 0 ] && unset 'out[${#out[@]}-1]' ;;
      *) out+=("$c") ;;
    esac
  done
  printf '/%s\n' "${out[*]}"
}
# resolve PATH: like canon, but a final symlink (also a chain) is followed.
resolve() {
  local p=$1 t n=0
  case "$p" in /*) ;; *) p=$(pwd)/$p ;; esac
  while [ -L "$p" ] && [ $n -lt 40 ]; do
    t=$(readlink "$p"); case "$t" in /*) p=$t ;; *) p=$(dirname "$p")/$t ;; esac; n=$((n + 1))
  done
  canon "$p"
}
# inside A B: A is B or below B, comparing resolved paths.
inside() { local a b; a=$(resolve "$1") && b=$(resolve "$2") && { [ "$a" = "$b" ] || under "$a" "$b"; }; }

# The lock. One mkdir lock directory per prefix is the mutual exclusion for
# every install.sh / uninstall.sh, with or without flock(1); it lives in /tmp
# (named after the canonical prefix), so it does not depend on the prefix or
# lib/ existing and is never removed together with them. flock(1), where
# available, only serialises taking over a lock directory whose holder died:
# a process holding the flock may remove a lock directory whose pid is no
# longer running; a process without flock never takes one over (it reports it).
if command -v sha256sum >/dev/null 2>&1; then lsha() { sha256sum | cut -c1-16; }; else lsha() { shasum -a 256 | cut -c1-16; }; fi
lockbase=${GSEAL_INSTALL_LOCK_BASE:-/tmp}
lockkey=$(printf '%s' "$(canon "$prefix" 2>/dev/null || printf '%s' "$prefix")" | lsha)
lockdir=$lockbase/gseal-install-$lockkey.lock.d
lockfile=$lockbase/gseal-install-$lockkey.lock
have_lock="" have_flock=""
release_lock() {
  [ -n "$have_lock" ] && rm -rf "$lockdir"
  [ -n "$have_flock" ] && exec 9>&-
  have_lock="" have_flock=""
}
acquire_lock() {
  local wait=${GSEAL_INSTALL_LOCK_WAIT:-300} waited=0 pid
  if command -v flock >/dev/null 2>&1 && [ -z "${GSEAL_INSTALL_NO_FLOCK:-}" ]; then
    if { exec 9>>"$lockfile"; } 2>/dev/null || { exec 9<"$lockfile"; } 2>/dev/null; then
      if ! flock -n 9; then
        say "waiting for another install.sh / uninstall.sh on $prefix ..."; waited=1
        flock -w "$wait" 9 || { warn "another install.sh / uninstall.sh is still running on $prefix"; exit 1; }
      fi
      have_flock=1
    fi
  fi
  while ! mkdir "$lockdir" 2>/dev/null; do
    pid=$(cat "$lockdir/pid" 2>/dev/null || true)
    if [ -n "$pid" ] && ! kill -0 "$pid" 2>/dev/null; then
      if [ -n "$have_flock" ]; then
        rm -rf "$lockdir" && say "took over the lock left by process $pid (no longer running)"
        continue
      fi
      warn "a lock left by process $pid (no longer running) is in $lockdir; if no install.sh / uninstall.sh is running, remove it (rm -r $lockdir) and run again"
      exit 1
    fi
    [ $waited = 0 ] && say "waiting for another install.sh / uninstall.sh on $prefix (pid ${pid:-?}) ..."
    [ $waited -ge "$wait" ] && { warn "another install.sh / uninstall.sh is still running on $prefix (pid ${pid:-?})"; exit 1; }
    sleep 1; waited=$((waited + 1))
  done
  echo $$ > "$lockdir/pid"
  have_lock=1
}
trap release_lock EXIT
acquire_lock

# 1. Put back every switched store entry first; stop if any cannot be.
failed=0
if [ -f "$state/store-bin" ]; then
  while IFS=$'\t' read -r store bak had made; do
    [ -n "$store" ] || continue
    [ "$bak" = - ] && bak=""
    sbin=$store/bin
    if [ "$(readlink "$sbin/with-secrets" 2>/dev/null)" != "$bindir/with-secrets" ]; then
      say "$sbin/with-secrets no longer links to this installation; left as it is"
      continue
    fi
    if inside "$store" "$lib" || { [ -n "$bak" ] && inside "$bak" "$lib"; }; then
      warn "$store or its backup lies inside $lib; not touching it"; failed=1; continue
    fi
    if [ "${had:-entry}" = none ]; then
      # There was no entry before the switch: remove the link (and bin/ if install made it and it is empty).
      if rm -f "$sbin/with-secrets"; then
        say "removed $sbin/with-secrets (there was no entry before the install)"
        [ "${made:-0}" = 1 ] && rmdir "$sbin" 2>/dev/null && say "removed the empty $sbin made by install"
      else
        failed=1
      fi
      continue
    fi
    if [ ! -e "$bak/with-secrets" ] && [ ! -L "$bak/with-secrets" ]; then
      warn "the backup $bak/with-secrets is missing; $sbin/with-secrets is kept linked to this installation"; failed=1; continue
    fi
    tmp=$sbin/.with-secrets.restore.$$
    rm -f "$tmp"
    if cp -a "$bak/with-secrets" "$tmp" && mv -f "$tmp" "$sbin/with-secrets"; then
      say "put back $sbin/with-secrets from $bak (backup kept)"
    else
      rm -f "$tmp"; warn "could not put back $sbin/with-secrets from $bak; it stays linked to this installation"; failed=1
    fi
  done < "$state/store-bin"
fi
if [ $failed = 1 ]; then
  warn "not uninstalling: a store entry still depends on this installation (fix the problem above and run uninstall.sh again)"
  exit 1
fi

# 2. Entry links: put back what install replaced, else remove.
for name in with-secrets gseal; do
  link=$bindir/$name
  [ -L "$link" ] && [ "$(readlink "$link")" = "$entry" ] || continue
  if [ -f "$state/replaced-$name" ]; then
    old=$(cat "$state/replaced-$name")
    tmp=$bindir/.$name.restore.$$
    rm -f "$tmp"
    ln -s "$old" "$tmp" && mv -f "$tmp" "$link" && say "put back $link -> $old" || { rm -f "$tmp"; warn "could not put back $link -> $old"; exit 1; }
  else
    if ! rm -f "$link" 2>/dev/null || [ -L "$link" ]; then
      warn "could not remove $link; not removing the program it points to (run uninstall.sh again once it can be removed)"; exit 1
    fi
    say "removed $link"
  fi
done

# The config file (followed through symlinks) is never removed, wherever it is.
cfg=${GSEAL_CONFIG:-}
if [ -z "$cfg" ]; then base=${XDG_CONFIG_HOME:-}; case "$base" in /*) ;; *) base=$HOME/.config ;; esac; cfg=$base/gseal/config.ini; fi
# Every config path: this session's and every one an install recorded.
cfgs=("$cfg")
if [ -f "$state/config-paths" ]; then while IFS= read -r c; do [ -n "$c" ] && cfgs+=("$c"); done < "$state/config-paths"; fi
keeps_config() {
  local c r
  for c in "${cfgs[@]}"; do
    { [ -e "$c" ] || [ -L "$c" ]; } || continue
    r=$(resolve "$c" 2>/dev/null) || continue
    if inside "$r" "$1"; then cfg=$c; return 0; fi
  done
  return 1
}

# 3. Only what install.sh owns in lib/gseal.
for d in "$lib"/*; do
  [ -e "$d" ] || [ -L "$d" ] || continue
  n=$(basename "$d")
  case "$n" in
    current|previous) [ -L "$d" ] && rm -f "$d" ;;
    state)
      # Only the files install.sh writes there; anything else (e.g. a config
      # someone put there) stays.
      # Exact names only (install.sh never leaves temp files: write_state renames
      # or removes them), so no pattern can catch a file someone else put here.
      for f in "$d/store-bin" "$d/replaced-with-secrets" "$d/replaced-gseal" "$d/config-paths"; do
        [ -e "$f" ] || [ -L "$f" ] || continue
        if keeps_config "$f"; then say "kept $f: the config file $cfg is (links to) it"; continue; fi
        rm -f "$f"
      done
      rmdir "$d" 2>/dev/null || true ;;
    *) if [ -d "$d" ] && [ ! -L "$d" ] && [ "$(ls -A "$d")" = with-secrets ]; then
         if keeps_config "$d"; then say "kept $d: the config file $cfg is (links to) a file in it"; else rm -rf "$d"; fi
       fi ;;
  esac
done
release_lock
if rmdir "$lib" 2>/dev/null; then
  say "removed $lib"
else
  say "kept $lib: it holds files install.sh did not make: $(ls -A "$lib" | tr '\n' ' ')"
fi
say "kept: every store, the config file and every backup"
exit 0
