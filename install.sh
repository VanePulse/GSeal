#!/usr/bin/env bash
# Install with-secrets (GSeal).
#
#   install.sh [--prefix DIR] [--binary FILE] [--version V] [--store DIR] [--link-store-bin]
#   install.sh --check    [--prefix DIR] [--store DIR]
#   install.sh --rollback [--prefix DIR]
#
# Layout (several versions side by side, switched atomically):
#   <prefix>/lib/gseal/<version>/with-secrets
#   <prefix>/lib/gseal/current  -> <version>        (symlink, replaced with rename(2))
#   <prefix>/lib/gseal/previous -> <version>        (what --rollback switches back to)
#   <prefix>/lib/gseal/state/                       (what install changed outside lib/, for uninstall)
#   <prefix>/bin/with-secrets   -> ../lib/gseal/current/with-secrets
#   <prefix>/bin/gseal          -> ../lib/gseal/current/with-secrets
#
# --prefix     default /usr/local for root, ~/.local for everyone else
# --binary     a prebuilt executable; default: the with-secrets next to this
#              script (release archive), else build from this source tree with
#              go (version from the VERSION file)
# --store      the store root; written to a new config file as [store] path
# --link-store-bin
#              replace <store>/bin/with-secrets by a link to the new entry, so
#              scripts calling the old path keep working. <store>/bin is copied
#              to <store>/bin.bak-<time> first; the old path is then called the
#              way a cron job would (only HOME and PATH=/usr/bin:/bin set) and
#              must reach exactly this store, else everything is put back.
#
# The first install writes the config file ($GSEAL_CONFIG, else
# $XDG_CONFIG_HOME/gseal/config.ini, else ~/.config/gseal/config.ini), mode
# 600, created atomically; an existing one is never changed, only the
# differences are shown. Installs, rollbacks and uninstalls of one prefix run
# one at a time (lock <prefix>/lib/gseal/.lock).
#
# Exit codes: 0 done; 1 failed, everything put back as it was; 2 usage;
# 3 failed and putting things back did not complete (the message says what).
set -uo pipefail

PROG=install.sh
say()  { printf '%s\n' "$*"; }
warn() { printf '%s: %s\n' "$PROG" "$*" >&2; }
usage() { sed -n '2,7p' "$0" | sed 's/^# \{0,1\}//' >&2; exit 2; }

prefix="" binary="" version="" store="" link_store=0 mode=install
while [ $# -gt 0 ]; do
  case "$1" in
    --prefix) [ $# -ge 2 ] || usage; prefix=$2; shift 2 ;;
    --binary) [ $# -ge 2 ] || usage; binary=$2; shift 2 ;;
    --version) [ $# -ge 2 ] || usage; version=$2; shift 2 ;;
    --store) [ $# -ge 2 ] || usage; store=$2; shift 2 ;;
    --link-store-bin) link_store=1; shift ;;
    --check) mode=check; shift ;;
    --rollback) mode=rollback; shift ;;
    --lock-path) mode=lockpath; shift ;;
    -h|--help) usage ;;
    *) warn "unknown argument: $1"; usage ;;
  esac
done

here=$(cd "$(dirname "$0")" && pwd)
if [ -z "$prefix" ]; then
  if [ "$(id -u)" = 0 ]; then prefix=/usr/local; else prefix=$HOME/.local; fi
fi
case "$prefix" in /*) ;; *) prefix=$(pwd)/$prefix ;; esac
case "$store" in ""|/*) ;; *) store=$(pwd)/$store ;; esac
store=${store%/}
lib=$prefix/lib/gseal
bindir=$prefix/bin
state=$lib/state
entry=../lib/gseal/current/with-secrets

config_file() {
  if [ -n "${GSEAL_CONFIG:-}" ]; then printf '%s\n' "$GSEAL_CONFIG"; return; fi
  local base=${XDG_CONFIG_HOME:-}
  case "$base" in /*) ;; *) base=$HOME/.config ;; esac
  printf '%s\n' "$base/gseal/config.ini"
}

# [store] path from the config file, if any.
config_store() {
  local f; f=$(config_file)
  [ -f "$f" ] || return 0
  awk '
    /^[ \t]*\[/ { sec = tolower($0); gsub(/[][ \t]/, "", sec); next }
    sec == "store" && /^[ \t]*path[ \t]*=/ { sub(/^[^=]*=[ \t]*/, ""); sub(/[ \t]+[;#].*$/, ""); sub(/[ \t]+$/, ""); print; exit }
  ' "$f"
}

# Atomically point symlink $1 at $2 (create a temp link, rename it over).
relink() {
  local link=$1 target=$2 tmp
  tmp=$(dirname "$link")/.$(basename "$link").new.$$
  rm -f "$tmp"
  ln -s "$target" "$tmp" || return 1
  if mv --version >/dev/null 2>&1; then mv -fT "$tmp" "$link"; else mv -fh "$tmp" "$link"; fi
}

# Test hooks: GSEAL_INSTALL_FAULT=<step> makes that step fail after it ran;
# GSEAL_INSTALL_HOLD=<seconds> pauses right after the current version is read.
fault() { [ "${GSEAL_INSTALL_FAULT:-}" = "$1" ] && { warn "injected fault at $1"; return 1; }; return 0; }

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

# The store a cron-like environment reaches through <store>/bin/with-secrets
# (only HOME and PATH=/usr/bin:/bin). Prints the store path; fails if the
# call fails.
job_store() {
  local out
  out=$(env -i HOME="$HOME" PATH=/usr/bin:/bin "$1/bin/with-secrets" --where 2>/dev/null) || return 1
  printf '%s\n' "$out" | sed -n '1{s/^store: *//;s/  (from .*$//;p;}'
}

# Stores whose entry install switched, one line each:
#   <store> \t <backup dir, or - for none> \t entry|none (was there an old entry) \t 1|0 (bin/ made by install)
linked_stores() { [ -f "$state/store-bin" ] && cat "$state/store-bin"; return 0; }
linked_backup() { linked_stores | awk -F '\t' -v s="$1" '$1 == s { if ($2 != "-") print $2; exit }'; }
is_linked()     { linked_stores | awk -F '\t' -v s="$1" '$1 == s { f = 1 } END { exit !f }'; }

# ----------------------------------------------------------------- lock ----
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

# --------------------------------------------------------------- check ----
check() {
  local bad=0 cur prev target s b got
  : > "$tmpcheck"
  ok()   { say "OK    $*"; }
  fail() { say "FAIL  $*"; bad=1; }
  runs() { [ -x "$lib/$1/with-secrets" ] && "$lib/$1/with-secrets" --version >/dev/null 2>&1; }
  if [ -L "$lib/current" ]; then
    cur=$(readlink "$lib/current")
    if runs "$cur"; then ok "current version: $cur ($("$lib/$cur/with-secrets" --version))"
    else fail "current points to $cur, which is missing or does not run"; fi
  else
    fail "not installed in $prefix (no $lib/current)"
  fi
  if [ -L "$lib/previous" ]; then
    prev=$(readlink "$lib/previous")
    if runs "$prev"; then ok "previous version (for --rollback): $prev"
    else fail "previous points to $prev, which is missing or does not run (--rollback would fail)"; fi
  fi
  for name in with-secrets gseal; do
    target=$(readlink "$bindir/$name" 2>/dev/null || true)
    if [ "$target" = "$entry" ]; then ok "$bindir/$name -> $entry"; else fail "$bindir/$name does not point to $entry"; fi
  done
  # The config must load (otherwise every command fails). --where prints its
  # "config:" line whenever the config loaded, even if no store exists yet.
  if [ -e "$(config_file)" ] && [ ! -f "$(config_file)" ]; then fail "config path $(config_file) is not a regular file"; fi
  if [ -f "$(config_file)" ] && [ -x "$lib/current/with-secrets" ]; then
    if { "$lib/current/with-secrets" --where 2>/dev/null || true; } | grep -q '^config: '; then ok "config $(config_file) loads"
    else fail "config $(config_file) cannot be loaded: run $bindir/with-secrets --where"; fi
  fi
  # Every store entry install switched, plus --store / the config's store if linked.
  { linked_stores | cut -f1; [ -n "$store" ] && printf '%s\n' "$store"; } | sort -u | while IFS= read -r s; do
    [ -n "$s" ] || continue
    b=$(linked_backup "$s")
    if ! is_linked "$s" && [ "$(readlink "$s/bin/with-secrets" 2>/dev/null)" != "$bindir/with-secrets" ]; then continue; fi  # not switched by install
    target=$(readlink "$s/bin/with-secrets" 2>/dev/null || true)
    if [ "$target" != "$bindir/with-secrets" ]; then
      say "FAIL  $s/bin/with-secrets is missing or does not link to $bindir/with-secrets"; echo bad >> "$tmpcheck"; continue
    fi
    got=$(job_store "$s") || got=""
    if [ "$got" = "$s" ]; then say "OK    $s/bin/with-secrets -> $target, reaches $s as a cron job would"
    else say "FAIL  $s/bin/with-secrets does not reach $s with only HOME and PATH set (got: ${got:-an error})"; echo bad >> "$tmpcheck"; fi
    if [ -n "$b" ] && [ ! -d "$b" ]; then say "FAIL  the backup of $s/bin ($b) is missing (uninstall could not put it back)"; echo bad >> "$tmpcheck"; fi
  done
  [ -s "$tmpcheck" ] && bad=1
  return $bad
}

if [ "$mode" = lockpath ]; then printf '%s\n' "$lockdir"; exit 0; fi
tmpcheck=$(mktemp) || exit 1
tmpd=$(mktemp -d) || exit 1
trap 'release_lock; rm -rf "$tmpd" "$tmpcheck"' EXIT

if [ "$mode" = check ]; then check; exit $?; fi

# --------------------------------------------------------------- undo log ----
# Every change pushes the shell command that reverts it; on failure they run
# in reverse order.
undo=()
push_undo() { undo+=("$1"); }
rollback_changes() {
  local i failed=0
  for ((i = ${#undo[@]} - 1; i >= 0; i--)); do
    eval "${undo[$i]}" || { warn "could not undo: ${undo[$i]}"; failed=1; }
  done
  return $failed
}
lib_dirs=()
die() {
  warn "$*"
  local ok=0 i
  rollback_changes || ok=1
  # Directories this run made (prefix, lib/): removed while still holding the
  # lock, so the next install never finds them disappearing under it.
  for ((i = ${#lib_dirs[@]} - 1; i >= 0; i--)); do rmdir "${lib_dirs[$i]}" 2>/dev/null || ok=1; done
  release_lock
  [ -n "${GSEAL_INSTALL_DIE_HOLD:-}" ] && sleep "$GSEAL_INSTALL_DIE_HOLD"   # test hook: linger after releasing
  if [ $ok = 0 ]; then warn "nothing changed (everything put back as it was)"; exit 1; fi
  warn "putting things back did not complete; see the messages above"; exit 3
}
q() { printf '%q' "$1"; }

# mkdir -p that records each directory it creates (removed again on undo,
# only if still empty).
mkdirs() {
  local d=$1 missing=()
  while [ ! -d "$d" ]; do missing+=("$d"); d=$(dirname "$d"); done
  local i
  for ((i = ${#missing[@]} - 1; i >= 0; i--)); do
    mkdir "${missing[$i]}" || return 1
    push_undo "rmdir $(q "${missing[$i]}")"
  done
}

# The previous state of a symlink, as an undo command.
undo_link() {
  local link=$1
  if [ -L "$link" ]; then push_undo "relink $(q "$link") $(q "$(readlink "$link")")"
  elif [ -e "$link" ]; then return 1
  else push_undo "rm -f $(q "$link")"; fi
}

# Write state file $1 (content on stdin) atomically, with undo.
write_state() {
  local f=$state/$1 tmp=$state/.$1.new.$$
  mkdirs "$state" || return 1
  cat > "$tmp" || { rm -f "$tmp"; return 1; }
  if [ -f "$f" ]; then
    cp "$f" "$tmpd/state.$1.bak" || { rm -f "$tmp"; return 1; }
    push_undo "cp $(q "$tmpd/state.$1.bak") $(q "$f")"
  else
    push_undo "rm -f $(q "$f")"
  fi
  mv -f "$tmp" "$f" || { rm -f "$tmp"; return 1; }   # never leaves a temp file behind
}

if [ "$mode" = install ]; then
  # Everything that does not change anything first.
  if [ -z "$binary" ] && [ -x "$here/with-secrets" ] && [ ! -f "$here/go.mod" ]; then
    binary=$here/with-secrets            # an extracted release archive
  fi
  if [ -z "$binary" ]; then
    [ -f "$here/go.mod" ] && command -v go >/dev/null 2>&1 || { warn "no --binary given and no Go source tree with go to build from"; exit 2; }
    [ -n "$version" ] || version=$(tr -d ' \n' < "$here/VERSION")
    say "building with-secrets $version ..."
    (cd "$here" && CGO_ENABLED=0 go build -mod=vendor -trimpath \
       -ldflags "-s -w -X github.com/VanePulse/GSeal/internal/cli.Version=$version" -o "$tmpd/with-secrets" ./cmd/with-secrets) || { warn "build failed"; exit 1; }
    binary=$tmpd/with-secrets
  fi
  [ -x "$binary" ] || { warn "not an executable: $binary"; exit 2; }
  [ -n "$version" ] || version=$("$binary" --version 2>/dev/null | awk '{print $2}')
  case "$version" in ""|*/*|.*|state|current|previous) warn "cannot tell the version (use --version V)"; exit 2 ;; esac
  cfgpath=$(config_file)
  if inside "$cfgpath" "$lib"; then warn "the config file ($cfgpath) must not be inside $lib"; exit 2; fi
  if [ -d "$cfgpath" ]; then warn "the config path $cfgpath is a directory"; exit 2; fi
  if [ $link_store = 1 ]; then
    [ -n "$store" ] || store=$(config_store)
    store=${store%/}
    [ -n "$store" ] || { warn "--link-store-bin needs --store <dir> (or [store] path in the config)"; exit 2; }
    [ -d "$store/env" ] || { warn "not a store (no env/ directory): $store"; exit 2; }
    if inside "$store" "$prefix" || inside "$prefix" "$store"; then
      warn "the store ($store) and the prefix ($prefix) must not contain each other"; exit 2
    fi
  fi
fi

# The lock first (it does not need the prefix); directories only under it,
# so a failing run that removes what it made cannot pull them away from a
# waiting one.
acquire_lock
d=$lib
while [ ! -d "$d" ]; do lib_dirs=("$d" ${lib_dirs[@]+"${lib_dirs[@]}"}); d=$(dirname "$d"); done
mkdir -p "$lib" || die "cannot create $lib"
# Re-check the path overlaps on the directories as they now exist.
if [ $mode = install ] && inside "$(config_file)" "$lib"; then die "the config file ($(config_file)) must not be inside $lib"; fi

# --------------------------------------------------------------- rollback ----
if [ "$mode" = rollback ]; then
  [ -L "$lib/previous" ] || { warn "no previous version to roll back to in $lib"; exit 1; }
  cur=$(readlink "$lib/current" 2>/dev/null || true)
  prev=$(readlink "$lib/previous")
  [ -x "$lib/$prev/with-secrets" ] || { warn "previous version $prev is missing"; exit 1; }
  undo_link "$lib/current"; undo_link "$lib/previous"
  relink "$lib/current" "$prev" || die "cannot switch to $prev"
  if [ -n "$cur" ]; then relink "$lib/previous" "$cur" || die "cannot record $cur as previous"; fi
  fault rollback || die "rollback failed"
  check >/dev/null || die "check after rollback failed"
  say "rolled back: $cur -> $prev"
  exit 0
fi

# --------------------------------------------------------------- install ----
mkdirs "$bindir" || die "cannot create $bindir"

# 1. the version directory
vdir=$lib/$version
if [ -e "$vdir" ]; then
  cmp -s "$binary" "$vdir/with-secrets" || die "version $version is already installed with a different executable (use another --version)"
  say "version $version already present"
else
  stage=$lib/.$version.new.$$
  mkdir -p "$stage" && cp "$binary" "$stage/with-secrets" && chmod 755 "$stage/with-secrets" || { rm -rf "$stage"; die "cannot copy the executable"; }
  mv "$stage" "$vdir" || { rm -rf "$stage"; die "cannot create $vdir"; }
  push_undo "rm -rf $(q "$vdir")"
  "$vdir/with-secrets" --version >/dev/null 2>&1 || die "the installed executable does not run"
fi
fault binary || die "install failed"

# 2. switch current (and remember the previous version), under the lock
old=$(readlink "$lib/current" 2>/dev/null || true)
[ -n "${GSEAL_INSTALL_HOLD:-}" ] && sleep "$GSEAL_INSTALL_HOLD" 9>&-   # test hook (sleep must not hold the lock fd)
undo_link "$lib/current" || die "$lib/current exists and is not a link"
relink "$lib/current" "$version" || die "cannot switch $lib/current"
fault switch || die "install failed"
if [ -n "$old" ] && [ "$old" != "$version" ]; then
  undo_link "$lib/previous" || die "$lib/previous exists and is not a link"
  relink "$lib/previous" "$old" || die "cannot record the previous version"
fi
fault previous || die "install failed"

# 3. entry points
for name in with-secrets gseal; do
  link=$bindir/$name
  if [ -e "$link" ] && [ ! -L "$link" ]; then die "$link exists and is not a link (not replacing it)"; fi
  # A link to something else (e.g. an older entry) is remembered, so
  # uninstall.sh can put it back.
  if [ -L "$link" ] && [ "$(readlink "$link")" != "$entry" ] && [ ! -e "$state/replaced-$name" ]; then
    readlink "$link" > "$tmpd/replaced" || die "cannot record $link"
    write_state "replaced-$name" < "$tmpd/replaced" || die "cannot record $link"
    say "remembered the previous $link -> $(readlink "$link") (uninstall.sh puts it back)"
  fi
  undo_link "$link" || die "cannot record $link"
  relink "$link" "$entry" || die "cannot create $link"
done
fault links || die "install failed"

# The config path this install uses is recorded (uninstall.sh never removes
# what any recorded config path leads to, whatever its own environment).
cfgrec=$(config_file)
{ [ -f "$state/config-paths" ] && grep -vxF -- "$cfgrec" "$state/config-paths"; printf '%s\n' "$cfgrec"; } > "$tmpd/config-paths"
write_state config-paths < "$tmpd/config-paths" || die "cannot record the config path"

# 4. config (first install only): written to a temp file (mode 600) and
#    linked into place, which fails if a config appeared meanwhile.
cfg=$(config_file)
template=$tmpd/config.ini
{
  say "; with-secrets (GSeal) configuration; see README for every setting."
  say ""
  say "[store]"
  if [ -n "$store" ]; then say "path = $store"; else say "; path = /path/to/store      ; default: ~/.local/share/gseal"; fi
  say ""
  say "[encrypt]"
  say "keys = @mask                ; empty = every key; or names / patterns: PSWD, *_SECRET"
  say ""
  say "[redact]"
  say "plain = HOST, PORT, DB, DATABASE, USER, USERNAME, NAME, SCHEMA, ENDPOINT, BUCKET, BUCKETNAME"
  say ""
  say "[backup]"
  say "; dir = /path/to/backups    ; default: the remembered dir, else \$TMPDIR/with-secrets-backup"
  say ""
  say "[audit]"
  say "enabled = true"
} > "$template"
show_diff() { say "config $cfg exists; not changed. Differences from the template:"; diff -u "$cfg" "$template" | sed '1,2d' || true; }
if [ -e "$cfg" ]; then
  show_diff
else
  mkdirs "$(dirname "$cfg")" || die "cannot create $(dirname "$cfg")"
  ctmp=$(dirname "$cfg")/.$(basename "$cfg").new.$$
  { (umask 077 && cat "$template" > "$ctmp") && fault config-write && chmod 600 "$ctmp" && fault config-chmod; } || { rm -f "$ctmp"; die "cannot write $cfg"; }
  [ "${GSEAL_INSTALL_FAULT:-}" = config-race ] && printf '; created by someone else meanwhile\n' > "$cfg"   # test hook
  [ "${GSEAL_INSTALL_FAULT:-}" = config-race-dir ] && mkdir "$cfg"                                         # test hook
  if ln "$ctmp" "$cfg" 2>/dev/null && [ "$cfg" -ef "$ctmp" ]; then
    rm -f "$ctmp"
    push_undo "rm -f $(q "$cfg")"
    say "config written: $cfg"
  elif [ -d "$cfg" ]; then
    # A directory appeared at the path: ln put the file inside it; take it out.
    [ "$cfg/$(basename "$ctmp")" -ef "$ctmp" ] && rm -f "$cfg/$(basename "$ctmp")"
    rm -f "$ctmp"
    die "the config path $cfg is a directory (created meanwhile); no config written"
  else
    rm -f "$ctmp"
    [ -e "$cfg" ] || die "cannot write $cfg"
    show_diff
  fi
fi
fault config || die "install failed"

# 5. <store>/bin/with-secrets -> the new entry
if [ $link_store = 1 ]; then
  sbin=$store/bin
  if [ -L "$sbin/with-secrets" ] && [ "$(readlink "$sbin/with-secrets")" = "$bindir/with-secrets" ]; then
    got=$(job_store "$store") || got=""
    [ "$got" = "$store" ] || die "$sbin/with-secrets is linked, but with only HOME and PATH set it does not reach $store (got: ${got:-an error}); set [store] path in ~/.config/gseal/config.ini"
    say "$sbin/with-secrets already links to $bindir/with-secrets and reaches $store"
  else
    had=none made=0
    if [ -e "$sbin/with-secrets" ] || [ -L "$sbin/with-secrets" ]; then had=entry; fi
    if [ -d "$sbin" ]; then
      bak=$store/bin.bak-$(date +%Y%m%dT%H%M%S)-$$
      cp -a "$sbin" "$bak" || { rm -rf "$bak"; die "cannot back up $sbin"; }
      say "backed up $sbin to $bak"
      if [ -e "$sbin/with-secrets" ] || [ -L "$sbin/with-secrets" ]; then
        push_undo "rm -f $(q "$sbin/with-secrets") && cp -a $(q "$bak/with-secrets") $(q "$sbin/with-secrets") && rm -rf $(q "$bak")"
      else
        push_undo "rm -f $(q "$sbin/with-secrets") && rm -rf $(q "$bak")"
      fi
    else
      bak="" made=1
      mkdirs "$sbin" || die "cannot create $sbin"
      push_undo "rm -f $(q "$sbin/with-secrets")"
    fi
    tmpl=$sbin/.with-secrets.new.$$
    ln -s "$bindir/with-secrets" "$tmpl" && mv -f "$tmpl" "$sbin/with-secrets" || { rm -f "$tmpl"; die "cannot link $sbin/with-secrets"; }
    fault store-bin || die "install failed"
    # The old path must reach this store the way a cron job calls it.
    got=$(job_store "$store") || got=""
    [ "$got" = "$store" ] || die "with only HOME and PATH set, $sbin/with-secrets does not reach $store (got: ${got:-an error}); jobs would break. Put [store] path = $store in ~/.config/gseal/config.ini (GSEAL_CONFIG is not seen by jobs)"
    fault verify || die "install failed"
    { linked_stores | awk -F '\t' -v s="$store" '$1 != s'; printf '%s\t%s\t%s\t%s\n' "$store" "${bak:--}" "$had" "$made"; } > "$tmpd/store-bin"
    write_state store-bin < "$tmpd/store-bin" || die "cannot record the store entry"
    say "$sbin/with-secrets -> $bindir/with-secrets (reaches $store as a cron job would)"
  fi
fi

check >/dev/null || die "check after install failed (run install.sh --check)"
say "installed with-secrets $version in $prefix (previous: ${old:-none})"
case ":$PATH:" in *":$bindir:"*) ;; *) say "note: $bindir is not on PATH" ;; esac
exit 0
