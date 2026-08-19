#!/bin/bash

set -euo pipefail

source "$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)/base-test.sh"

# Exercises the Omarchy side of face auth: the lock service skeleton, the
# one-backend rule, and removal's discovery. The backend is a fake facelock
# that logs its argv and edits the staged PAM directory the way the real one
# edits /etc/pam.d, so nothing here proves facelock's own PAM writer.
#
# Layout: fixtures and fakes first, then one block per case, each headed
# "# --- setup N: ..." or "# --- remove N: ...", staging its own state with
# reset() and ending in a pass line.

# ============================================================================
# Fixtures
# ============================================================================

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

pam_dir="$tmp/pam.d"      # stands in for /etc/pam.d via OMARCHY_PAM_DIR
bin_dir="$tmp/bin"        # fakes, ahead of $ROOT/bin on PATH
log="$tmp/log"            # every fake appends its argv here
installed="$tmp/facelock-installed"   # marker: omarchy-cmd-present facelock
enrolled="$tmp/facelock-enrolled"     # marker: facelock is-enrolled
mkdir -p "$pam_dir" "$bin_dir"

skeleton='#%PAM-1.0
auth       required                    pam_deny.so
account    include                     system-local-login'

# A lock service already carrying another backend's line, above the terminator.
foreign_lock_service='#%PAM-1.0
auth sufficient pam_howdy.so
auth       required                    pam_deny.so
account    include                     system-local-login'

# Fresh machine: sudo and polkit-1 present, no lock service, nothing installed
# or enrolled, empty log.
reset() {
  rm -rf "$pam_dir" "$log" "$installed" "$enrolled"
  mkdir -p "$pam_dir"
  printf '#%%PAM-1.0\nauth include system-auth\n' >"$pam_dir/sudo"
  printf '#%%PAM-1.0\nauth include system-auth\n' >"$pam_dir/polkit-1"
  : >"$log"
}

# Configured machine: facelock installed and enrolled, all three services wired.
configure() {
  reset
  touch "$installed" "$enrolled"
  run omarchy-setup-security-face
  : >"$log"
}

# Runs a script from $ROOT/bin with the fakes in front and the staged PAM
# directory, capturing exit status and combined output.
run() {
  local out
  out=$(PATH="$bin_dir:$ROOT/bin:$PATH" OMARCHY_PAM_DIR="$pam_dir" TEST_LOG="$log" \
    TEST_INSTALLED="$installed" TEST_ENROLLED="$enrolled" "$ROOT/bin/$@" </dev/null 2>&1) && status=0 || status=$?
  output=$out
}

facelock_lines() {
  grep -c 'pam_facelock\.so' "$pam_dir/$1" 2>/dev/null || true
}

# ============================================================================
# Fakes
# ============================================================================

cat >"$bin_dir/sudo" <<'EOF'
#!/bin/bash
exec "$@"
EOF

# Logs argv, answers the probes the scripts make, and edits the staged PAM
# directory: `pam add` validates every service before writing any and is
# idempotent, `pam remove` strips the line, `clear` drops the enrolled marker.
cat >"$bin_dir/facelock" <<'EOF'
#!/bin/bash
echo "facelock $*" >>"$TEST_LOG"
case "$1" in
--version) echo "facelock 0.0-test" ;;
capabilities) printf '%s\n' is-enrolled pam-multi-service pam-if-present setup-no-pam setup-systemd ;;
is-enrolled) [[ -f $TEST_ENROLLED ]] ;;
setup) ;;
clear) rm -f "$TEST_ENROLLED" ;;
pam)
  verb=$2; shift 2
  services=()
  while (($# > 0)); do
    [[ $1 == "--service" ]] && services+=("$2") && shift
    shift
  done
  if [[ $verb == "add" ]]; then
    for service in "${services[@]}"; do
      [[ -f $OMARCHY_PAM_DIR/$service ]] || { echo "Error: PAM service file not found: $service" >&2; exit 1; }
    done
  fi
  for service in "${services[@]}"; do
    file="$OMARCHY_PAM_DIR/$service"
    [[ -f $file ]] || continue
    if [[ $verb == "add" ]] && ! grep -q pam_facelock.so "$file"; then
      sed -i '1a auth      sufficient pam_facelock.so' "$file"
    elif [[ $verb == "remove" ]]; then
      sed -i '/pam_facelock\.so/d' "$file"
    fi
  done
  ;;
esac
EOF

cat >"$bin_dir/omarchy-cmd-present" <<'EOF'
#!/bin/bash
[[ $1 == "facelock" && -f $TEST_INSTALLED ]]
EOF
cat >"$bin_dir/omarchy-cmd-missing" <<'EOF'
#!/bin/bash
! [[ $1 == "facelock" && -f $TEST_INSTALLED ]]
EOF
cat >"$bin_dir/omarchy-pkg-aur-add" <<'EOF'
#!/bin/bash
echo "omarchy-pkg-aur-add $*" >>"$TEST_LOG"
touch "$TEST_INSTALLED"
EOF
cat >"$bin_dir/omarchy-pkg-drop" <<'EOF'
#!/bin/bash
echo "omarchy-pkg-drop $*" >>"$TEST_LOG"
rm -f "$TEST_INSTALLED"
EOF
cat >"$bin_dir/omarchy-notification-send" <<'EOF'
#!/bin/bash
echo "notification $*" >>"$TEST_LOG"
EOF
chmod +x "$bin_dir"/*

# ============================================================================
# Setup cases
# ============================================================================

# --- setup 1: unknown provider is refused before anything happens ---
reset
run omarchy-setup-security-face nonsense
(( status == 1 )) || fail "unknown provider exits 1" "$output"
[[ $output == *"Usage: omarchy-setup-security-face"* ]] || fail "unknown provider prints usage" "$output"
[[ ! -e $pam_dir/omarchy-lock-face && ! -s $log ]] || fail "unknown provider writes nothing"
pass "setup rejects an unknown provider before touching anything"

# --- setup 2: another backend's line in the lock service blocks setup ---
reset
printf '%s\n' "$foreign_lock_service" >"$pam_dir/omarchy-lock-face"
run omarchy-setup-security-face facelock
(( status == 1 )) || fail "second backend is refused" "$output"
[[ $output == *"Another face backend is already set up"* ]] || fail "second backend refusal names the remedy" "$output"
grep -q pam_howdy.so "$pam_dir/omarchy-lock-face" && ! grep -q 'facelock setup' "$log" ||
  fail "second backend refusal leaves the other backend and its wizard alone"
pass "setup allows one backend at a time"

# --- setup 3: fresh machine, no argument: install, wizard, skeleton, PAM line ---
reset
run omarchy-setup-security-face
(( status == 0 )) || fail "setup succeeds on a fresh machine" "$output"
grep -qx 'omarchy-pkg-aur-add facelock-git' "$log" || fail "setup installs facelock when missing"
grep -qx 'facelock capabilities' "$log" || fail "setup probes facelock capabilities"
grep -qx 'facelock setup --no-pam --systemd' "$log" || fail "setup runs the wizard without its PAM step"
grep -qx 'facelock pam add --service omarchy-lock-face --service sudo --service polkit-1 --no-confirm' "$log" ||
  fail "setup wires all three services in one facelock call"
[[ $(head -n1 "$pam_dir/omarchy-lock-face") == '#%PAM-1.0' ]] || fail "lock service starts with the PAM header"
grep -q '^auth      sufficient pam_facelock.so' "$pam_dir/omarchy-lock-face" || fail "backend line is in the lock service"
[[ $(grep -n 'pam_facelock\|pam_deny' "$pam_dir/omarchy-lock-face" | cut -d: -f1 | tr '\n' ' ') == "2 3 " ]] ||
  fail "backend line sits above the pam_deny terminator" "$(cat "$pam_dir/omarchy-lock-face")"
grep -q '^account    include                     system-local-login' "$pam_dir/omarchy-lock-face" || fail "lock service includes the account stack"
[[ $output == *"no face is enrolled yet"* && $output == *"facelock enroll"* ]] || fail "setup names the enroll command when nothing is enrolled" "$output"
[[ $(grep -c '^notification' "$log") -eq 1 ]] || fail "setup notifies once"
pass "setup installs, runs the wizard, writes the skeleton, then the backend line"

# --- setup 4: re-run on the machine setup 3 left, now enrolled ---
lock_face_before=$(cat "$pam_dir/omarchy-lock-face")
touch "$enrolled"
: >"$log"
run omarchy-setup-security-face facelock
(( status == 0 )) || fail "re-run succeeds" "$output"
[[ $(cat "$pam_dir/omarchy-lock-face") == "$lock_face_before" ]] || fail "re-run leaves the lock service untouched"
[[ $output == *"Face authentication is now configured"* ]] || fail "re-run reports an enrolled face" "$output"
! grep -q 'omarchy-pkg-aur-add' "$log" || fail "re-run does not reinstall facelock"
pass "setup is idempotent and reports enrollment"

# --- setup 5: a service facelock refuses (polkit-1 missing) ---
reset
rm "$pam_dir/polkit-1"
run omarchy-setup-security-face
(( status == 1 )) || fail "refused service fails setup" "$output"
[[ $output == *"Failed to configure face authentication"* && $output == *"omarchy-remove-security-face"* ]] ||
  fail "refused service names the undo" "$output"
(( $(facelock_lines sudo) == 0 )) || fail "refused service leaves sudo unwritten"
pass "setup reports a refused service and leaves the other services alone"

# ============================================================================
# Remove cases
# ============================================================================

# --- remove 1: configured machine, discovered from the lock service ---
configure
run omarchy-remove-security-face
(( status == 0 )) || fail "remove succeeds when configured" "$output"
grep -qx 'facelock pam remove --service sudo --service polkit-1 --service omarchy-lock-face --if-present --no-confirm' "$log" ||
  fail "remove withdraws the backend line through facelock"
grep -qx 'facelock clear --yes' "$log" || fail "remove clears enrollment"
grep -qx 'omarchy-pkg-drop facelock facelock-bin facelock-git' "$log" || fail "remove drops the package"
[[ ! -e $pam_dir/omarchy-lock-face ]] || fail "remove deletes the bare lock service"
(( $(facelock_lines sudo) == 0 && $(facelock_lines polkit-1) == 0 )) || fail "remove leaves no backend line behind"
pass "remove discovers facelock from the lock service and tears it down"

# --- remove 2: lock service deleted by hand, facelock still installed ---
configure
rm "$pam_dir/omarchy-lock-face"
run omarchy-remove-security-face
(( status == 0 )) || fail "remove succeeds without the lock service" "$output"
grep -q '^facelock pam remove' "$log" && (( $(facelock_lines sudo) == 0 )) ||
  fail "remove still withdraws sudo and polkit lines when the lock service was deleted by hand"
pass "remove falls back to the installed backend"

# --- remove 3: lines still wired, but the facelock binary is gone ---
configure
rm "$installed"
run omarchy-remove-security-face
(( status == 1 )) || fail "remove fails when the backend is gone but its lines remain" "$output"
[[ $output == *"facelock is not installed"* ]] || fail "remove says the backend is missing" "$output"
(( $(facelock_lines sudo) == 1 )) && [[ -f $pam_dir/omarchy-lock-face && ! -s $log ]] ||
  fail "remove touches nothing it cannot withdraw"
pass "remove refuses to guess at a missing backend's lines"

# --- remove 4: bare skeleton left by an interrupted setup, no backend ---
reset
printf '%s\n' "$skeleton" >"$pam_dir/omarchy-lock-face"
run omarchy-remove-security-face
(( status == 0 )) && [[ ! -e $pam_dir/omarchy-lock-face && ! -s $log ]] || fail "bare skeleton is removed without a backend" "$output"
pass "remove deletes a bare skeleton"

# --- remove 5: another backend's line in the lock service, no facelock ---
reset
printf '%s\n' "$foreign_lock_service" >"$pam_dir/omarchy-lock-face"
run omarchy-remove-security-face
(( status == 0 )) && [[ -f $pam_dir/omarchy-lock-face ]] && [[ $output == *"Another face backend still uses the lock screen"* ]] ||
  fail "another backend's line keeps the lock service" "$output"
pass "remove leaves another backend's lock service in place"
