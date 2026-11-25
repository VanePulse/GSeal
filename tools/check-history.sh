#!/usr/bin/env bash
# Check a ref (every reachable commit) or a directory before publishing.
#
#   tools/check-history.sh <ref>             every commit reachable from <ref>
#   tools/check-history.sh --tree <dir>      one directory (no Git needed)
#
# The checks of test/clean_test.go (M4.C1), on each commit's full tree
# (vendor/, testdata/norm/, *.wsbk and go.sum excluded): internal names
# (compared by SHA-256; the hashes are read from test/clean_test.go), e-mail
# addresses other than *.invalid / noreply@, personal paths (under /data,
# /home or /Users), host names other than *.invalid and the allowed public
# ones, IP addresses other than the fixtures' (lists below, kept equal to
# test/clean_test.go by test M4.C2).
#
# Exit 0: clean. 1: findings (listed). 2: the check could not be done (bad
# ref, Git or archive failure, missing hash list) - never reported as clean.
#
# Publishing without the development history: make a branch with a single
# commit holding the final tree (e.g. `git checkout --orphan release`, then
# `git commit`), run this script on it, and push only that branch.
set -uo pipefail
repo=$(cd "$(dirname "$0")/.." && pwd)

ALLOW_HOSTS="github.com golang.org go.dev pkg.go.dev opensource.org semver.org keepachangelog.com"
ALLOW_IPS="10.0.0.1 10.0.0.2 10.0.0.3 10.9.9.9 127.0.0.1"

err() { echo "check-history: $*" >&2; exit 2; }
hashes=$(grep -oE '"[0-9a-f]{64}"' "$repo/test/clean_test.go" 2>/dev/null | tr -d '"' | sort -u)
[ -n "$hashes" ] || err "no hashes found in $repo/test/clean_test.go"
if command -v sha256sum >/dev/null 2>&1; then shacmd=(sha256sum); else shacmd=(shasum -a 256); fi
work=$(mktemp -d) || exit 2
trap 'rm -rf "$work"' EXIT

# grep over the files of a tree, without the excluded parts (the tree is
# never modified). Status 0 = done (matches or none), 2 = error.
tgrep() {
  local dir=$1; shift
  : > "$work/grep.err"
  find "$dir" \( -path "$dir/.git" -o -path "$dir/vendor" -o -path "$dir/testdata/norm" \) -prune \
       -o -type f ! -name '*.wsbk' ! -name go.sum -print0 2>>"$work/grep.err" \
    | xargs -0 grep -I -H "$@" 2>>"$work/grep.err"
  [ -s "$work/grep.err" ] && { cat "$work/grep.err" >&2; return 2; }
  return 0
}

# scan_tree <dir> <label>: prints findings; returns 0 clean, 1 findings, 2 error.
scan_tree() {
  local dir=$1 label=$2 found=0 st w f line v
  [ -d "$dir" ] || { echo "check-history: not a directory: $dir" >&2; return 2; }
  tgrep "$dir" -h -o -E '[A-Za-z0-9-]+' > "$work/tokens"; st=$?
  if [ $st -le 1 ]; then
    tr 'A-Z' 'a-z' < "$work/tokens" | sort -u > "$work/words"
    # Hash every word in one go: one file per word, one sha256 run.
    rm -rf "$work/w"; mkdir "$work/w"
    awk -v d="$work/w" '{ f = d "/" NR; printf "%s", $0 > f; close(f) }' "$work/words"
    if [ -s "$work/words" ]; then
      (cd "$work/w" && find . -type f -print0 | xargs -0 "${shacmd[@]}") > "$work/sums" || return 2
      printf '%s\n' "$hashes" > "$work/forbidden"
      if awk 'NR == FNR { bad[$1] = 1; next } ($1 in bad) { n++ } END { exit n ? 0 : 1 }' "$work/forbidden" "$work/sums"; then
        echo "$label: internal name (a word whose SHA-256 is listed in test/clean_test.go)"; found=1
      fi
    fi
    for f in emails paths hosts ips; do
      case $f in
        emails) tgrep "$dir" -n -o -E '[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+' > "$work/$f" ;;
        paths)  tgrep "$dir" -n -o -E '/(data|home|Users)/[A-Za-z0-9._-]+' > "$work/$f" ;;
        hosts)  tgrep "$dir" -n -o -E '(^|[^A-Za-z0-9_])[a-z0-9-]+(\.[a-z0-9-]+)*\.(com|net|org|cn|io|local|lan|corp|internal|intra)([^A-Za-z0-9_]|$)' > "$work/$f" ;;
        ips)    tgrep "$dir" -n -o -E '(^|[^A-Za-z0-9_])([0-9]{1,3}\.){3}[0-9]{1,3}([^A-Za-z0-9_]|$)' > "$work/$f" ;;
      esac
      st=$?
      [ $st -le 1 ] || break
      st=0
      while IFS= read -r line; do
        v=${line#*:}; v=${v#*:}                       # drop "file:line:"
        case $f in hosts|ips) v=$(printf '%s' "$v" | sed -E 's/^[^a-z0-9]//; s/[^a-z0-9]$//') ;; esac
        case $f in
          emails) case "$v" in *.invalid|noreply@*) continue ;; esac ;;
          hosts)  case " $ALLOW_HOSTS " in *" $v "*) continue ;; esac; case "$v" in *.invalid) continue ;; esac ;;
          ips)    case " $ALLOW_IPS " in *" $v "*) continue ;; esac; case "$v" in 192.0.2.*) continue ;; esac ;;
        esac
        echo "$label: $f: ${line#"$dir"/}"; found=1
      done < "$work/$f"
    done
  fi
  [ $st -le 1 ] || return 2
  return $found
}

if [ "${1:-}" = --tree ]; then
  [ $# = 2 ] || err "usage: tools/check-history.sh --tree <dir>"
  scan_tree "$2" "$2"; st=$?
  case $st in 0) echo "clean: $2" ;; 1) echo "NOT clean: $2" >&2 ;; *) echo "check-history: could not check $2" >&2 ;; esac
  exit $st
fi

ref=${1:?usage: tools/check-history.sh <ref> | --tree <dir>}
command -v git >/dev/null 2>&1 || err "git not found"
commits=$(git -C "$repo" rev-list "$ref") || err "cannot list the commits of $ref"
[ -n "$commits" ] || err "no commits reachable from $ref"
n=0 bad=0
for c in $commits; do
  n=$((n + 1))
  rm -rf "$work/tree"; mkdir "$work/tree"
  git -C "$repo" archive --format=tar "$c" > "$work/tree.tar" || err "cannot read commit $c"
  tar -x -C "$work/tree" -f "$work/tree.tar" || err "cannot unpack commit $c"
  scan_tree "$work/tree" "$c"; st=$?
  [ $st -le 1 ] || err "could not check commit $c"
  [ $st = 1 ] && bad=1
done
if [ $bad = 0 ]; then echo "clean: $n commit(s) reachable from $ref"; exit 0; fi
echo "NOT clean (see above); do not publish $ref" >&2
exit 1
