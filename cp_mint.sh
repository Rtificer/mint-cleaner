#!/usr/bin/env bash
# =============================================================================
# DESIGN RULES
#   * Nothing is deleted or disabled without a prompt.
#   * Configs are backed up to /root/cp_mint/backup/<timestamp>/ at startup.
#   * Every change is logged to /root/cp_mint/logs/cp_mint.log
#   * Reports (scans, persistence, file searches) go to /root/cp_mint/reports/
# =============================================================================
set -uo pipefail

PASS_MAX_DAYS=90
PASS_MIN_DAYS=7
PASS_WARN_AGE=14
PW_MINLEN=12
FAIL_DENY=5     # failed logins before lockout
FAIL_UNLOCK=900 # seconds until lockout expires
SSH_MAX_AUTH_TRIES=4
SCAN_DIRS=(/home /root /tmp /var/tmp /opt /srv /usr/local /etc /var/www /media /mnt)
MEDIA_EXT=(mp3 mp4 m4a m4v avi mkv mov wmv flv wav flac ogg ogv aac wma mpg mpeg webm)

# Services that are commonly unwanted. You are asked about each one that is
# active/enabled - answer "n" if the README says it is required.
BAD_SERVICES=(telnet telnetd vsftpd proftpd pure-ftpd apache2 nginx lighttpd smbd nmbd
	snmpd avahi-daemon cups cups-browsed isc-dhcp-server rpcbind nfs-server bind9 named
	slapd dovecot postfix sendmail exim4 xinetd inetd tftpd-hpa rsh-server ypserv
	mysql mariadb postgresql)

# Packages commonly prohibited (hacking tools, games). Asked one by one.
BAD_PKGS=(john john-data hydra hydra-gtk nmap zenmap ncrack medusa aircrack-ng wireshark
	wireshark-qt tshark ophcrack ophcrack-cli nikto sqlmap kismet netcat-traditional
	ettercap-text-only ettercap-graphical dsniff hashcat wifite crack freeciv
	freeciv-client-gtk minetest supertux frozen-bubble gnome-mahjongg gnome-mines
	gnome-sudoku aisleriot quadrapassel five-or-more iagno lightsoff tali hitori
	four-in-a-row gnome-nibbles gnome-robots gnome-taquin tetravex gnome-klotski
	bsdgames openarena pingus wesnoth xonotic 0ad)

SYSCTL_SETTINGS=(
	net.ipv4.tcp_syncookies=1
	net.ipv4.ip_forward=0
	net.ipv4.conf.all.send_redirects=0
	net.ipv4.conf.default.send_redirects=0
	net.ipv4.conf.all.accept_redirects=0
	net.ipv4.conf.default.accept_redirects=0
	net.ipv4.conf.all.secure_redirects=0
	net.ipv4.conf.default.secure_redirects=0
	net.ipv6.conf.all.accept_redirects=0
	net.ipv6.conf.default.accept_redirects=0
	net.ipv4.conf.all.accept_source_route=0
	net.ipv4.conf.default.accept_source_route=0
	net.ipv6.conf.all.accept_source_route=0
	net.ipv6.conf.default.accept_source_route=0
	net.ipv4.conf.all.rp_filter=1
	net.ipv4.conf.default.rp_filter=1
	net.ipv4.conf.all.log_martians=1
	net.ipv4.conf.default.log_martians=1
	net.ipv4.icmp_echo_ignore_broadcasts=1
	net.ipv4.icmp_ignore_bogus_error_responses=1
	kernel.randomize_va_space=2
	kernel.dmesg_restrict=1
	kernel.kptr_restrict=2
	fs.protected_hardlinks=1
	fs.protected_symlinks=1
	fs.suid_dumpable=0
)

# Heuristic patterns used by the persistence report
SUSPICIOUS_RE='((^|[^a-z])nc[[:space:]]+|ncat|netcat|socat|/dev/tcp/|bash[[:space:]]+-i|mkfifo|python[0-9.]*[[:space:]]+-c|perl[[:space:]]+-e|ruby[[:space:]]+-e|php[[:space:]]+-r|(curl|wget)[^|]*\|[[:space:]]*(ba)?sh|base64[[:space:]]+-d|/dev/shm|LD_PRELOAD)'
GTFO_RE='^(find|vim|vi|nano|less|more|cp|mv|bash|dash|sh|python[0-9.]*|perl|awk|gawk|env|tar|zip|nmap|nc|ncat|socat|php|ruby|gdb|strace|tcpdump|rsync|wget|curl|cat|dd|tee|sed|xxd|base64|man|ed|vim\.basic|vim\.tiny|busybox|node)$'

# ------------------------------- GLOBALS -------------------------------------
[[ $EUID -eq 0 ]] || {
	echo "Run as root:  sudo $0 $*"
	exit 1
}

SCRIPT_PATH=$(readlink -f "${BASH_SOURCE[0]}")
BASE=/root/cp_mint
LOG_DIR=$BASE/logs
REPORT_DIR=$BASE/reports
BACKUP_ROOT=$BASE/backup
DATA_DIR=$BASE/data
mkdir -p "$LOG_DIR" "$REPORT_DIR" "$BACKUP_ROOT" "$DATA_DIR"
TS=$(date +%Y%m%d-%H%M%S)
BACKUP_DIR=$BACKUP_ROOT/$TS
LOG=$LOG_DIR/cp_mint.log
ME=${SUDO_USER:-$(logname 2>/dev/null || true)}
AUTH_LOADED=0
AUTH_USERS=()
AUTH_ADMINS=()

export DEBIAN_FRONTEND=noninteractive
APT_OPTS=(-y -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold)

C_R=$'\e[31m'
C_G=$'\e[32m'
C_Y=$'\e[33m'
C_B=$'\e[34m'
C_0=$'\e[0m'

# ------------------------------- HELPERS -------------------------------------
_log() { printf '%s [%s] %s\n' "$(date '+%F %T')" "$1" "$2" >>"$LOG"; }
info() {
	echo "${C_B}[*]${C_0} $*"
	_log INFO "$*"
}
change() {
	echo "${C_G}[+]${C_0} $*"
	_log CHANGE "$*"
}
warn() {
	echo "${C_Y}[!]${C_0} $*"
	_log WARN "$*"
}
review() {
	echo "${C_R}[REVIEW]${C_0} $*"
	_log REVIEW "$*"
}
hdr() {
	echo
	echo "${C_B}=== $* ===${C_0}"
	_log INFO "=== $* ==="
}
flag() { echo "[!] $*"; }

ask() { # ask "question" [y|n default]  -> returns 0 for yes
	local def=${2:-n} reply prompt
	[[ $def == y ]] && prompt="[Y/n]" || prompt="[y/N]"
	read -r -p "${C_Y}?${C_0} $1 $prompt " reply
	reply=${reply:-$def}
	[[ $reply =~ ^[Yy] ]]
}

apt_install() { apt-get install "${APT_OPTS[@]}" --no-install-recommends "$@" >>"$LOG" 2>&1; }
pkg_installed() { dpkg-query -W -f='${Status}' "$1" 2>/dev/null | grep -q '^install ok installed'; }
human_users() { awk -F: '$3>=1000 && $3<65534 {print $1}' /etc/passwd; }
in_list() {
	local x=$1 i
	shift
	for i in "$@"; do [[ $i == "$x" ]] && return 0; done
	return 1
}
norm() { tr -s '[:space:]=' ' ' <<<"$1" | sed -E 's/^ //; s/ $//'; }

# set_kv FILE KEY VALUE [SEP] [append|prepend]
# Comments out every active line for KEY, then writes "KEY<SEP>VALUE". Idempotent.
set_kv() {
	local file=$1 key=$2 val=$3 sep=${4:- } where=${5:-append}
	local kre=${key//./\\.} want="$key$sep$val" active n tmp
	[[ -e $file ]] || : >"$file"
	active=$(grep -E "^[[:space:]]*${kre}[[:space:]=]" "$file" || true)
	n=$(grep -cE "^[[:space:]]*${kre}[[:space:]=]" "$file" || true)
	if [[ $n -eq 1 && "$(norm "$active")" == "$(norm "$want")" ]]; then return 0; fi
	sed -i -E "s/^([[:space:]]*${kre}[[:space:]=].*)$/# cp_mint disabled: \1/" "$file"
	if [[ $where == prepend ]]; then
		tmp=$(mktemp)
		{
			echo "$want"
			cat "$file"
		} >"$tmp"
		cat "$tmp" >"$file"
		rm -f "$tmp"
	else
		[[ -s $file && -n $(tail -c1 "$file") ]] && echo >>"$file"
		echo "$want" >>"$file"
	fi
	change "$file: $want"
}

purge_pkg() { # simulates first, refuses to remove desktop/Mint core packages
	local pkg=$1 sim
	sim=$(apt-get -s purge "$pkg" 2>/dev/null | awk '/^Remv/{print $2}' | tr '\n' ' ')
	echo "   apt would remove: ${sim:-$pkg}"
	if grep -qE '(^| )(cinnamon|mint-|ubuntu-desktop|lightdm|xorg|linuxmint|nemo|mintsystem|mintupdate)' <<<"$sim"; then
		warn "Removal list includes desktop/Mint core packages - NOT purging $pkg."
		return 1
	fi
	ask "   Proceed with purge of $pkg?" y || return 1
	if apt-get purge "${APT_OPTS[@]}" "$pkg" >>"$LOG" 2>&1; then change "Purged $pkg"; else warn "purge of $pkg failed"; fi
}

unit_package() {
	local fp p out
	fp=$(systemctl show -p FragmentPath --value "$1.service" 2>/dev/null)
	for p in "$fp" "${fp#/usr}"; do
		[[ -n $p ]] || continue
		out=$(dpkg -S "$p" 2>/dev/null | head -1)
		if [[ -n $out ]]; then
			echo "${out%%:*}" | cut -d, -f1
			return
		fi
	done
}

unit_exists() { systemctl list-unit-files --no-legend "$1.service" 2>/dev/null | grep -q "^$1.service"; }

# ------------------------------- 1. BACKUP -----------------------------------
backup_configs() {
	hdr "Backing up configs"
	mkdir -p "$BACKUP_DIR"
	local f
	for f in /etc/ssh /etc/pam.d /etc/security /etc/login.defs /etc/sudoers /etc/sudoers.d \
		/etc/passwd /etc/shadow /etc/group /etc/gshadow /etc/lightdm /etc/sysctl.conf \
		/etc/sysctl.d /etc/apt /etc/hosts /etc/crontab /etc/cron.d /etc/ufw \
		/etc/default/ufw /etc/rc.local /etc/ld.so.preload /etc/rkhunter.conf; do
		[[ -e $f ]] && cp -a --parents "$f" "$BACKUP_DIR"/ 2>/dev/null
	done
	change "Backup saved to $BACKUP_DIR"
}

# ------------------------------- 2. UPDATES ----------------------------------
do_updates() {
	hdr "Updates & APT checks"
	local held f
	held=$(apt-mark showhold)
	if [[ -n $held ]]; then
		review "Held packages (blocks updates): $held"
		ask "   Unhold them?" y && apt-mark unhold $held >>"$LOG" 2>&1 && change "Unheld: $held"
	fi
	for f in $(grep -rlEi 'AllowUnauthenticated|AllowInsecureRepositories|AllowDowngradeToInsecure' \
		/etc/apt/apt.conf /etc/apt/apt.conf.d 2>/dev/null); do
		review "Insecure APT option in $f:"
		grep -nEi 'AllowUnauthenticated|AllowInsecureRepositories|AllowDowngradeToInsecure' "$f"
		if ask "   Comment those lines out?" y; then
			sed -i -E 's#^(.*(AllowUnauthenticated|AllowInsecureRepositories|AllowDowngradeToInsecure).*)$#// cp_mint disabled: \1#I' "$f"
			change "Disabled insecure APT options in $f"
		fi
	done
	info "Package sources - anything that is not Linux Mint/Ubuntu is suspicious:"
	grep -rhEv '^\s*(#|$)' /etc/apt/sources.list /etc/apt/sources.list.d/ 2>/dev/null | sed 's/^/     /'
	if ask "Run apt update + upgrade + dist-upgrade now? (can take a while)" y; then
		{ apt-get update && apt-get "${APT_OPTS[@]}" upgrade && apt-get "${APT_OPTS[@]}" dist-upgrade; } 2>&1 | tee -a "$LOG" | tail -n 15
		change "System updated"
	fi
	pkg_installed unattended-upgrades || apt_install unattended-upgrades
	cat >/etc/apt/apt.conf.d/20auto-upgrades <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
EOF
	change "Automatic security updates enabled (/etc/apt/apt.conf.d/20auto-upgrades)"
}

# ------------------------------- 3. USERS ------------------------------------
load_authorized() {
	[[ $AUTH_LOADED -eq 1 ]] && return
	local uf=$DATA_DIR/authorized_users.txt af=$DATA_DIR/authorized_admins.txt u
	if [[ -s $uf && -s $af ]] && ask "Reuse saved authorized-user lists from $DATA_DIR?" y; then
		mapfile -t AUTH_USERS <"$uf"
		mapfile -t AUTH_ADMINS <"$af"
	else
		echo "Current human accounts: $(human_users | tr '\n' ' ')"
		echo "Type the names from the README, separated by spaces."
		read -r -p "ALL authorized users (include admins): " -a AUTH_USERS
		read -r -p "Authorized ADMINISTRATORS (sudo):      " -a AUTH_ADMINS
		for u in "${AUTH_ADMINS[@]}"; do in_list "$u" "${AUTH_USERS[@]}" || AUTH_USERS+=("$u"); done
		printf '%s\n' "${AUTH_USERS[@]}" >"$uf"
		printf '%s\n' "${AUTH_ADMINS[@]}" >"$af"
	fi
	AUTH_LOADED=1
}

users_audit() {
	hdr "Users & groups audit"
	load_authorized
	local u g a c members

	# unauthorized human accounts
	for u in $(human_users); do
		in_list "$u" "${AUTH_USERS[@]}" && continue
		review "Unauthorized account: $u (uid $(id -u "$u"))"
		if [[ $u == "$ME" ]]; then
			warn "   that is the account running this script - skipping"
			continue
		fi
		read -r -p "   [d]elete (removes home) / [l]ock / [s]kip ? " a
		case ${a,,} in
		d)
			pkill -KILL -u "$u" 2>/dev/null
			if deluser --remove-home "$u" >>"$LOG" 2>&1; then change "Deleted user $u"; else warn "deluser failed for $u"; fi
			;;
		l) usermod -L -s /usr/sbin/nologin "$u" && change "Locked $u" ;;
		*) info "   skipped $u" ;;
		esac
	done

	# authorized users that don't exist
	for u in "${AUTH_USERS[@]}"; do
		id "$u" &>/dev/null || warn "Authorized user '$u' does not exist (README may want it created)"
	done

	# sudo group vs authorized admins
	for u in $(getent group sudo | cut -d: -f4 | tr ',' ' '); do
		in_list "$u" "${AUTH_ADMINS[@]}" && continue
		review "'$u' is in group sudo but is not an authorized admin"
		ask "   Remove $u from sudo?" y && gpasswd -d "$u" sudo >>"$LOG" 2>&1 && change "Removed $u from sudo"
	done
	for u in "${AUTH_ADMINS[@]}"; do
		id "$u" &>/dev/null || continue
		id -nG "$u" | tr ' ' '\n' | grep -qx sudo && continue
		review "'$u' should be an admin but is not in sudo"
		ask "   Add $u to sudo?" y && usermod -aG sudo "$u" && change "Added $u to sudo"
	done

	# other privileged groups
	for g in adm admin; do
		members=$(getent group "$g" 2>/dev/null | cut -d: -f4)
		[[ -n $members ]] && info "Group $g members: $members"
	done
	# Mint/LightDM: members of nopasswdlogin can log in with NO password
	members=$(getent group nopasswdlogin 2>/dev/null | cut -d: -f4)
	if [[ -n $members ]]; then
		for u in ${members//,/ }; do
			review "'$u' is in nopasswdlogin (passwordless login at the greeter)"
			ask "   Remove $u from nopasswdlogin?" y && gpasswd -d "$u" nopasswdlogin >>"$LOG" 2>&1 && change "Removed $u from nopasswdlogin"
		done
	fi

	# extra UID 0
	awk -F: '$3==0 && $1!="root"{print $1}' /etc/passwd | while read -r u; do
		review "EXTRA UID 0 ACCOUNT: $u  (fix manually: vipw / userdel)"
	done

	# empty passwords
	for u in $(awk -F: '$2==""{print $1}' /etc/shadow); do
		review "Empty password: $u"
		ask "   Lock $u's password now?" y && passwd -l "$u" >>"$LOG" 2>&1 && change "Locked password of $u"
	done

	# system accounts with login shells
	awk -F: '$3<1000 && $1!="root" && $7!~/(nologin|false|sync|shutdown|halt)$/ {print $1" ("$7")"}' /etc/passwd |
		while read -r c; do review "System account with login shell: $c"; done

	# root
	if [[ $(passwd -S root 2>/dev/null | awk '{print $2}') != L ]]; then
		ask "Root account is not locked. Lock it?" y && passwd -l root >>"$LOG" 2>&1 && change "Locked root password"
	else
		info "Root account already locked"
	fi

	# sudoers
	c=$(grep -rnE 'NOPASSWD|!authenticate' /etc/sudoers /etc/sudoers.d 2>/dev/null)
	[[ -n $c ]] && {
		review "sudoers NOPASSWD/!authenticate entries (edit with visudo):"
		echo "$c" | sed 's/^/     /'
	}
	info "Files in /etc/sudoers.d: $(ls /etc/sudoers.d 2>/dev/null | tr '\n' ' ')"
	visudo -c >>"$LOG" 2>&1 && info "visudo -c: syntax OK" || warn "visudo -c reports problems"

	# PAM oddities
	c=$(grep -rnE 'sufficient[[:space:]]+pam_permit|pam_exec|nullok' /etc/pam.d 2>/dev/null)
	[[ -n $c ]] && {
		review "PAM lines worth a look:"
		echo "$c" | sed 's/^/     /'
	}
}

# ------------------------------- 4. PASSWORD POLICY --------------------------
password_policy() {
	hdr "Password & login policy"
	local pf=/etc/pam.d/common-password af=/etc/pam.d/common-auth u

	set_kv /etc/login.defs PASS_MAX_DAYS "$PASS_MAX_DAYS"
	set_kv /etc/login.defs PASS_MIN_DAYS "$PASS_MIN_DAYS"
	set_kv /etc/login.defs PASS_WARN_AGE "$PASS_WARN_AGE"
	set_kv /etc/login.defs UMASK 027
	for u in $(human_users); do chage -M "$PASS_MAX_DAYS" -m "$PASS_MIN_DAYS" -W "$PASS_WARN_AGE" "$u" 2>>"$LOG"; done
	info "Applied aging policy to existing human accounts"

	pkg_installed libpam-pwquality || apt_install libpam-pwquality
	set_kv /etc/security/pwquality.conf minlen "$PW_MINLEN" " = "
	set_kv /etc/security/pwquality.conf minclass 4 " = "
	set_kv /etc/security/pwquality.conf dcredit -1 " = "
	set_kv /etc/security/pwquality.conf ucredit -1 " = "
	set_kv /etc/security/pwquality.conf lcredit -1 " = "
	set_kv /etc/security/pwquality.conf ocredit -1 " = "
	set_kv /etc/security/pwquality.conf difok 3 " = "
	if grep -qE '^password[[:space:]]+(requisite|required)[[:space:]]+pam_pwquality\.so' "$pf"; then
		local before
		before=$(md5sum <"$pf")
		sed -i -E "s/^(password[[:space:]]+(requisite|required)[[:space:]]+pam_pwquality\.so).*/\1 retry=3 minlen=$PW_MINLEN difok=3 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1/" "$pf"
		[[ $before == "$(md5sum <"$pf")" ]] || change "$pf: pam_pwquality options set"
	else
		warn "No pam_pwquality line in $pf - check 'pam-auth-update'"
	fi

	if ! grep -q pam_pwhistory "$pf"; then
		sed -i -E 's/^(password[[:space:]].*pam_unix\.so.*)$/password required pam_pwhistory.so remember=5 use_authtok\n\1/' "$pf"
		change "$pf: pam_pwhistory remember=5 added"
	fi

	if grep -q nullok "$af"; then
		sed -i -E 's/[[:space:]]+nullok(_secure)?//' "$af"
		change "$af: removed nullok"
	fi

	# account lockout
	if ask "Configure account lockout ($FAIL_DENY tries / ${FAIL_UNLOCK}s)? RISKY - keep a root shell open" n; then
		if find /lib /usr/lib -name pam_faillock.so 2>/dev/null | grep -q .; then
			set_kv /etc/security/faillock.conf deny "$FAIL_DENY" " = "
			set_kv /etc/security/faillock.conf unlock_time "$FAIL_UNLOCK" " = "
			set_kv /etc/security/faillock.conf fail_interval "$FAIL_UNLOCK" " = "
			cat >/usr/share/pam-configs/faillock <<'EOF'
Name: Enforce failed login attempt counter
Default: no
Priority: 0
Auth-Type: Primary
Auth:
	[default=die] pam_faillock.so authfail
EOF
			cat >/usr/share/pam-configs/faillock_notify <<'EOF'
Name: Notify on failed login attempts and reset on success
Default: no
Priority: 1024
Auth-Type: Primary
Auth:
	requisite pam_faillock.so preauth
Account-Type: Primary
Account:
	required pam_faillock.so
EOF
			if pam-auth-update --enable faillock faillock_notify >>"$LOG" 2>&1; then
				change "pam_faillock enabled via pam-auth-update"
				warn "TEST NOW: open a second terminal and run 'su - <user>' to confirm logins still work"
			else
				warn "pam-auth-update failed - lockout NOT enabled"
			fi
		elif find /lib /usr/lib -name pam_tally2.so 2>/dev/null | grep -q .; then
			grep -q pam_tally2 "$af" || sed -i "1i auth required pam_tally2.so deny=$FAIL_DENY unlock_time=$FAIL_UNLOCK onerr=fail audit" "$af"
			change "pam_tally2 lockout added to $af"
		else
			warn "Neither pam_faillock nor pam_tally2 found"
		fi
	fi
}

set_passwords() {
	hdr "Set passwords for authorized users"
	load_authorized
	warn "One password will be applied to every authorized user EXCEPT '$ME' (change yours with: passwd)."
	warn "If the README specifies passwords or says not to change one, skip this step."
	ask "Continue?" n || return
	local p1 p2 u
	read -r -s -p "New password: " p1
	echo
	read -r -s -p "Again:        " p2
	echo
	[[ $p1 == "$p2" ]] || {
		warn "Passwords do not match"
		return
	}
	if ((${#p1} < PW_MINLEN)) || ! [[ $p1 =~ [A-Z] && $p1 =~ [a-z] && $p1 =~ [0-9] && $p1 =~ [^[:alnum:]] ]]; then
		warn "Need >= $PW_MINLEN chars with upper, lower, digit and symbol"
		return
	fi
	for u in "${AUTH_USERS[@]}"; do
		id "$u" &>/dev/null || continue
		if [[ $u == "$ME" ]]; then
			info "skipping $u (you)"
			continue
		fi
		if echo "$u:$p1" | chpasswd 2>>"$LOG"; then change "Password reset for $u"; else warn "chpasswd failed for $u"; fi
	done
}

# ------------------------------- 5. LIGHTDM ----------------------------------
lightdm_harden() {
	hdr "LightDM (Mint login screen)"
	if ! command -v lightdm >/dev/null 2>&1; then
		warn "lightdm not found - if this image uses GDM3, check /etc/gdm3/custom.conf manually"
		return
	fi
	local f drop=/etc/lightdm/lightdm.conf.d/99-cp-hardening.conf pat='^\s*(autologin-user|autologin-guest|allow-guest)\s*='
	mkdir -p /etc/lightdm/lightdm.conf.d
	for f in /etc/lightdm/lightdm.conf /etc/lightdm/lightdm.conf.d/*.conf; do
		[[ -f $f && $f != "$drop" ]] || continue
		if grep -qEi "$pat" "$f"; then
			grep -nEi "$pat" "$f" | sed "s|^|     $f:|"
			sed -i -E 's/^[[:space:]]*(autologin-user|autologin-guest|allow-guest)[[:space:]]*=.*/# cp_mint disabled: &/I' "$f"
			change "Commented out autologin/guest lines in $f"
		fi
	done
	{
		echo "[Seat:*]"
		echo "allow-guest=false"
		echo "autologin-user="
		echo "autologin-guest=false"
	} >"$drop"
	if ask "Also hide the user list on the login screen (needs manual login)?" n; then
		{
			echo "greeter-hide-users=true"
			echo "greeter-show-manual-login=true"
		} >>"$drop"
	fi
	change "Wrote $drop (takes effect at next login-screen restart / reboot)"
}

# ------------------------------- 6. SSH --------------------------------------
ssh_harden() {
	hdr "SSH"
	if ! pkg_installed openssh-server; then
		info "openssh-server not installed - nothing to do"
		return
	fi
	if ! ask "Does the README say SSH must stay installed/running?" n; then
		if ask "Stop, disable and purge openssh-server?" y; then
			systemctl disable --now ssh ssh.socket >>"$LOG" 2>&1
			purge_pkg openssh-server
		fi
		return
	fi
	local cfg=/etc/ssh/sshd_config bak kv
	bak=$(mktemp)
	cp -a "$cfg" "$bak"
	mkdir -p /run/sshd
	for kv in "PermitRootLogin no" "PermitEmptyPasswords no" "X11Forwarding no" \
		"MaxAuthTries $SSH_MAX_AUTH_TRIES" "LoginGraceTime 60" "IgnoreRhosts yes" \
		"HostbasedAuthentication no" "PermitUserEnvironment no" \
		"ClientAliveInterval 300" "ClientAliveCountMax 2" "LogLevel VERBOSE"; do
		set_kv "$cfg" "${kv%% *}" "${kv#* }" " " prepend
	done
	chmod 600 "$cfg"
	if sshd -t 2>>"$LOG"; then
		systemctl reload ssh >>"$LOG" 2>&1 || systemctl reload sshd >>"$LOG" 2>&1
		change "sshd_config validated and reloaded"
	else
		warn "sshd -t FAILED - restoring original sshd_config"
		cat "$bak" >"$cfg"
	fi
	rm -f "$bak"
	info "Effective settings (sshd -T):"
	sshd -T 2>/dev/null | grep -E '^(permitrootlogin|permitemptypasswords|x11forwarding|maxauthtries|loglevel|ignorerhosts|hostbasedauthentication|permituserenvironment|clientaliveinterval|clientalivecountmax|logingracetime|passwordauthentication)' | sed 's/^/     /'
	if grep -rniE 'PermitRootLogin|PermitEmptyPasswords|X11Forwarding' /etc/ssh/sshd_config.d/ 2>/dev/null; then
		review "Drop-ins above may override your settings - compare with sshd -T output"
	fi
}

# ------------------------------- 7. FIREWALL ---------------------------------
firewall_setup() {
	hdr "Firewall (ufw)"
	command -v ufw >/dev/null 2>&1 || apt_install ufw
	local ports=() p
	read -r -p "Ports to ALLOW inbound, space-separated (e.g. 22/tcp 80/tcp; blank = none): " -a ports
	ask "Reset ALL existing ufw rules and apply default-deny incoming?" y || return
	ufw --force reset >>"$LOG" 2>&1
	ufw default deny incoming >>"$LOG" 2>&1
	ufw default allow outgoing >>"$LOG" 2>&1
	for p in "${ports[@]}"; do ufw allow "$p" >>"$LOG" 2>&1 && change "ufw allow $p"; done
	ufw logging on >>"$LOG" 2>&1
	if ufw --force enable >>"$LOG" 2>&1; then change "ufw enabled"; else warn "ufw enable failed"; fi
	systemctl enable ufw >>"$LOG" 2>&1
	ufw status verbose | sed 's/^/     /'
}

# ------------------------------- 8. SERVICES ---------------------------------
services_review() {
	hdr "Services"
	local s act en pkg
	for s in "${BAD_SERVICES[@]}"; do
		unit_exists "$s" || continue
		act=$(systemctl is-active "$s" 2>/dev/null)
		en=$(systemctl is-enabled "$s" 2>/dev/null)
		[[ $act == active || $en == enabled ]] || continue
		review "$s  enabled=$en active=$act"
		if ask "   Stop + disable $s? (say n if the README requires it)" n; then
			systemctl disable --now "$s" >>"$LOG" 2>&1 && change "Disabled $s"
			pkg=$(unit_package "$s")
			if [[ -n $pkg ]] && ask "   Also purge package '$pkg'?" n; then purge_pkg "$pkg"; fi
		fi
	done
	info "All enabled services:"
	systemctl list-unit-files --state=enabled --no-pager --no-legend | awk '{print "     "$1}'
	info "Listening sockets:"
	ss -tulpn | sed 's/^/     /'
}

# ------------------------------- 9. SYSCTL -----------------------------------
sysctl_harden() {
	hdr "Kernel / network (sysctl)"
	local kv k v cur
	for kv in "${SYSCTL_SETTINGS[@]}"; do set_kv /etc/sysctl.conf "${kv%%=*}" "${kv#*=}" "=" append; done
	sysctl --system >>"$LOG" 2>&1
	for kv in "${SYSCTL_SETTINGS[@]}"; do
		k=${kv%%=*}
		v=${kv#*=}
		cur=$(sysctl -n "$k" 2>/dev/null) || continue
		[[ $cur == "$v" ]] || review "$k is $cur (wanted $v) - something in /etc/sysctl.d or /usr/lib/sysctl.d overrides it"
	done
	grep -qE '^\*[[:space:]]+hard[[:space:]]+core' /etc/security/limits.conf 2>/dev/null ||
		{
			echo '* hard core 0' >>/etc/security/limits.conf
			change "limits.conf: core dumps disabled"
		}
}

# ------------------------------- 10. PERMS & MISC ----------------------------
perms_and_misc() {
	hdr "File permissions & misc"
	chown root:root /etc/passwd /etc/group
	chmod 644 /etc/passwd /etc/group
	getent group shadow >/dev/null && chown root:shadow /etc/shadow /etc/gshadow || chown root:root /etc/shadow /etc/gshadow
	chmod 640 /etc/shadow /etc/gshadow
	[[ -f /etc/ssh/sshd_config ]] && chmod 600 /etc/ssh/sshd_config
	[[ -f /etc/crontab ]] && chmod 600 /etc/crontab
	chmod 440 /etc/sudoers
	find /etc/sudoers.d -type f -exec chmod 440 {} + 2>/dev/null
	change "Permissions set on passwd/group/shadow/gshadow/sshd_config/crontab/sudoers"

	if ask "Set home directories to 750?" y; then
		local u h
		for u in $(human_users); do
			h=$(getent passwd "$u" | cut -d: -f6)
			[[ -d $h ]] && chmod 750 "$h"
		done
		change "Home directories set to 750"
	fi

	info "/etc/hosts entries beyond the defaults:"
	grep -vE '^\s*(#|$)|localhost|ip6-|^ff0|^::1|127\.0\.1\.1' /etc/hosts | sed 's/^/     /'

	local sus f b
	mapfile -t sus < <(find / -xdev -type f -perm -4000 2>/dev/null)
	for f in "${sus[@]}"; do
		b=${f##*/}
		if [[ $b =~ $GTFO_RE ]]; then
			review "SUID bit on $f (shell-escape risk)"
			ask "   Remove SUID bit?" n && chmod u-s "$f" && change "Removed SUID from $f"
		fi
	done
}

# ------------------------------- 11. PROHIBITED SOFTWARE ---------------------
prohibited_software() {
	hdr "Prohibited software"
	local p
	for p in "${BAD_PKGS[@]}"; do
		pkg_installed "$p" || continue
		review "Installed: $p"
		if ask "   Purge $p? (say n if the README lists it as required)" y; then purge_pkg "$p"; fi
	done
	apt-mark showmanual | sort >"$REPORT_DIR/manual-packages-$TS.txt"
	{
		snap list 2>/dev/null
		flatpak list 2>/dev/null
	} >"$REPORT_DIR/snap-flatpak-$TS.txt"
	dpkg -l 2>/dev/null | grep -iE 'game|solitaire|mines|sudoku|crack|sniff|hack' | awk '{print "     "$2" - "$3}'
	info "Manually-installed packages saved to $REPORT_DIR/manual-packages-$TS.txt - skim it for anything odd"
	info "(apt autoremove --purge is NOT run automatically; review first)"
}

prohibited_files() {
	hdr "Prohibited-file search (report only, nothing deleted)"
	local out=$REPORT_DIR/files-$TS.txt dirs=() d expr=() e
	for d in /home /root /tmp /var/tmp /opt /srv /media /mnt /var/www /usr/local; do [[ -d $d ]] && dirs+=("$d"); done
	for e in "${MEDIA_EXT[@]}"; do expr+=(-o -iname "*.$e"); done
	expr=("${expr[@]:1}")
	{
		echo "## Audio/video files (owner  size  path)"
		find "${dirs[@]}" -xdev -type f \( "${expr[@]}" \) -not -path '*/.cache/*' -printf '%u\t%s\t%p\n' 2>/dev/null
		echo
		echo "## Images in /home and /root"
		find /home /root -xdev -type f \( -iname '*.jpg' -o -iname '*.jpeg' -o -iname '*.png' -o -iname '*.gif' -o -iname '*.bmp' \) -not -path '*/.cache/*' -not -path '*/.local/*' 2>/dev/null
		echo
		echo "## Interesting names (passwords, creds, captures, hashes, archives)"
		find /home /root /tmp /var/tmp /opt /srv -xdev -type f \( -iname '*pass*' -o -iname '*cred*' -o -iname '*secret*' -o -iname '*.pcap' -o -iname '*.pot' -o -iname '*hash*' -o -iname '*.zip' -o -iname '*.tar*' -o -iname '*.7z' -o -iname '*.rar' \) -not -path '*/.cache/*' -not -path '*/.mozilla/*' 2>/dev/null
		echo
		echo "## Scripts / binaries in home dirs and temp dirs"
		find /home /root /tmp /var/tmp /dev/shm /opt -xdev -type f \( -iname '*.sh' -o -iname '*.py' -o -iname '*.pl' -o -iname '*.rb' -o -perm /111 \) -not -path '*/.cache/*' -not -path '*/.mozilla/*' -not -path '*/.local/*' 2>/dev/null
	} >"$out"
	info "Report: $out"
	grep -c . "$out" | sed 's/^/     lines in report: /'
	sed -n '1,25p' "$out" | sed 's/^/     /'
	info "Open the full report with: less $out"
}

# ------------------------------- 12. SCANNERS --------------------------------
install_scan_tools() {
	hdr "Installing scanners (needs internet)"
	apt-get update >>"$LOG" 2>&1
	local t
	for t in clamav clamav-freshclam rkhunter chkrootkit lynis debsums auditd; do
		if pkg_installed "$t"; then
			info "$t already installed"
		elif apt_install "$t"; then
			change "Installed $t"
		else warn "Could not install $t (no internet?)"; fi
	done
	systemctl enable --now auditd >>"$LOG" 2>&1 && change "auditd enabled"
}

run_clamscan() {
	hdr "ClamAV (background)"
	command -v clamscan >/dev/null 2>&1 || {
		warn "clamscan not installed - run install_scan_tools first"
		return
	}
	systemctl stop clamav-freshclam >>"$LOG" 2>&1
	if freshclam >>"$LOG" 2>&1; then info "ClamAV signatures updated"; else warn "freshclam failed (no internet?) - using existing signatures"; fi
	systemctl start clamav-freshclam >>"$LOG" 2>&1
	local out=$REPORT_DIR/clamscan-$TS.log dirs=() d
	if ask "Full-system scan (slow)? n = targeted directories only" n; then
		dirs=(/)
	else for d in "${SCAN_DIRS[@]}"; do [[ -d $d ]] && dirs+=("$d"); done; fi
	nohup nice -n 19 ionice -c3 clamscan -r -i --exclude-dir='^/sys' --exclude-dir='^/proc' \
		--exclude-dir='^/dev' --exclude-dir='^/run' "${dirs[@]}" >"$out" 2>&1 &
	disown
	info "clamscan running in background (PID $!)."
	info "Check progress:  tail -f $out     Hits contain 'FOUND'"
}

run_rkhunter() {
	hdr "rkhunter"
	command -v rkhunter >/dev/null 2>&1 || {
		warn "rkhunter not installed"
		return
	}
	rkhunter --update >>"$LOG" 2>&1 || true
	# Do NOT run 'rkhunter --propupd' - it would baseline a compromised system.
	rkhunter --check --skip-keypress --report-warnings-only --logfile "$REPORT_DIR/rkhunter-$TS.log" 2>&1 |
		tee "$REPORT_DIR/rkhunter-$TS.warnings" | sed 's/^/     /'
	info "Expect some false positives. Full log: $REPORT_DIR/rkhunter-$TS.log"
}

run_chkrootkit() {
	hdr "chkrootkit"
	command -v chkrootkit >/dev/null 2>&1 || {
		warn "chkrootkit not installed"
		return
	}
	chkrootkit -q 2>&1 | tee "$REPORT_DIR/chkrootkit-$TS.txt" | sed 's/^/     /'
}

run_lynis() {
	hdr "Lynis"
	command -v lynis >/dev/null 2>&1 || {
		warn "lynis not installed"
		return
	}
	lynis audit system --quick --no-colors >"$REPORT_DIR/lynis-$TS.txt" 2>&1
	info "Warnings / suggestions (id | text):"
	grep -E '^(warning|suggestion)\[\]=' /var/log/lynis-report.dat 2>/dev/null |
		sed -E 's/^(warning|suggestion)\[\]=/\1: /' | cut -d'|' -f1-2 | sed 's/^/     /' | head -n 60
	info "Full output: $REPORT_DIR/lynis-$TS.txt"
}

run_debsums() {
	hdr "debsums (modified package files)"
	command -v debsums >/dev/null 2>&1 || {
		warn "debsums not installed"
		return
	}
	debsums -c 2>/dev/null | tee "$REPORT_DIR/debsums-$TS.txt" | sed 's/^/     /'
	[[ -s $REPORT_DIR/debsums-$TS.txt ]] || info "No modified package files found"
}

run_scanners() {
	run_clamscan
	run_rkhunter
	run_chkrootkit
	run_lynis
	run_debsums
}

# ------------------------------- 13. PERSISTENCE -----------------------------
# persistence_report [quiet]   quiet = cron mode: skips slow find/ scans, logs only NEW flags
persistence_report() {
	local quiet=${1:-} out=$REPORT_DIR/persistence-$TS.txt
	[[ $quiet == quiet ]] || hdr "Persistence / suspicious-activity report"
	local f u p pid exe ex c files sfiles suid b
	{
		echo "Persistence report  $(date)  host=$(hostname)"

		echo
		echo "######## CRON: system"
		ls -la /etc/crontab /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly 2>&1
		grep -vE '^\s*(#|$)' /etc/crontab /etc/cron.d/* 2>/dev/null
		echo
		echo "######## CRON: per-user"
		for u in $(cut -d: -f1 /etc/passwd); do
			c=$(crontab -l -u "$u" 2>/dev/null | grep -vE '^\s*(#|$)') && [[ -n $c ]] && {
				echo "--- $u ---"
				echo "$c"
			}
		done
		files=(/etc/crontab /etc/cron.d/* /etc/cron.hourly/* /etc/cron.daily/* /etc/cron.weekly/* /etc/cron.monthly/* /var/spool/cron/crontabs/*)
		grep -nE "$SUSPICIOUS_RE" "${files[@]}" 2>/dev/null | sed 's/^/[!] CRON: /'
		echo
		echo "######## AT jobs"
		atq 2>&1
		ls -la /var/spool/cron/atjobs 2>&1

		echo
		echo "######## SYSTEMD: timers"
		systemctl list-timers --all --no-pager 2>&1
		echo
		echo "######## SYSTEMD: custom unit files (/etc/systemd/system and user units)"
		find /etc/systemd/system /home/*/.config/systemd/user /root/.config/systemd/user -maxdepth 3 -type f \( -name '*.service' -o -name '*.timer' \) 2>/dev/null |
			while read -r f; do
				echo "--- $f"
				grep -E '^(ExecStart|ExecStartPre|ExecStartPost|ExecStop|User)=' "$f"
				grep -qE "$SUSPICIOUS_RE|ExecStart=[-@+!]*(/tmp|/var/tmp|/dev/shm|/home|/root)" "$f" && flag "systemd unit looks suspicious: $f"
			done
		echo
		echo "######## SYSTEMD: enabled unit files"
		systemctl list-unit-files --state=enabled --no-pager 2>&1
		echo
		echo "######## SYSTEMD: running services"
		systemctl list-units --type=service --state=running --no-pager 2>&1

		echo
		echo "######## RC / INIT"
		if [[ -f /etc/rc.local ]]; then
			cat /etc/rc.local
			grep -vqE '^\s*(#|$|exit 0)' /etc/rc.local && flag "/etc/rc.local contains commands"
		fi
		ls -la /etc/init.d

		echo
		echo "######## AUTOSTART entries"
		for f in /etc/xdg/autostart/*.desktop /home/*/.config/autostart/*.desktop /root/.config/autostart/*.desktop; do
			[[ -f $f ]] || continue
			ex=$(grep -m1 '^Exec=' "$f")
			echo "$f  ->  $ex"
			[[ $f == /etc/xdg/* ]] || flag "per-user autostart entry: $f ($ex)"
			grep -qE "$SUSPICIOUS_RE" "$f" && flag "autostart entry looks suspicious: $f"
		done

		echo
		echo "######## SHELL STARTUP FILES"
		sfiles=(/etc/profile /etc/bash.bashrc /etc/environment /etc/profile.d/* /home/*/.bashrc /home/*/.profile /home/*/.bash_profile /home/*/.bash_login /home/*/.bash_logout /root/.bashrc /root/.profile)
		for f in "${sfiles[@]}"; do [[ -f $f ]] && grep -nE "$SUSPICIOUS_RE" "$f" | sed "s|^|[!] $f: |"; done
		grep -nE '^\s*alias[[:space:]]+(sudo|su|passwd|ps|ss|netstat|ssh|login|top|kill|lsof)=' "${sfiles[@]}" 2>/dev/null | sed 's/^/[!] aliased core command: /'
		grep -nE '^\s*alias ' "${sfiles[@]}" 2>/dev/null | sed 's/^/ALIAS: /'

		echo
		echo "######## LD_PRELOAD"
		ls -la /etc/ld.so.preload 2>&1
		[[ -s /etc/ld.so.preload ]] && {
			cat /etc/ld.so.preload
			flag "/etc/ld.so.preload is non-empty"
		}
		grep -rn 'LD_PRELOAD\|LD_LIBRARY_PATH' /etc/environment /etc/profile /etc/profile.d 2>/dev/null | sed 's/^/[!] /'

		echo
		echo "######## SSH keys / rc files"
		for f in /home/*/.ssh/authorized_keys* /root/.ssh/authorized_keys*; do
			[[ -f $f ]] && {
				echo "--- $f"
				cut -c1-100 "$f"
				flag "authorized_keys present: $f"
			}
		done
		for f in /home/*/.ssh/rc /etc/ssh/sshrc; do [[ -f $f ]] && flag "ssh rc file exists: $f"; done

		echo
		echo "######## PROCESSES (tree)"
		ps auxf 2>&1
		for p in /proc/[0-9]*; do
			pid=${p#/proc/}
			[[ $pid == "$$" || $pid == "$BASHPID" ]] && continue
			exe=$(readlink "$p/exe" 2>/dev/null) || continue
			ex=$(tr '\0' ' ' <"$p/cmdline" 2>/dev/null | cut -c1-100)
			case $exe in
			/tmp/* | /var/tmp/* | /dev/shm/* | /home/* | /root/* | *"(deleted)"*)
				flag "PID $pid runs from $exe ($ex)"
				continue
				;;
			esac
			# scripts run via an interpreter (sh, python...) show the interpreter as exe,
			# so also look at the command line for temp-dir paths
			if [[ $ex =~ (^|[[:space:]])(/tmp|/var/tmp|/dev/shm)/ ]]; then
				flag "PID $pid command line references a temp dir ($ex)"
			fi
		done
		ps -eo pid,user,args --no-headers | grep -E "$SUSPICIOUS_RE" | grep -v 'grep -E' | sed 's/^/[!] PROC: /'

		echo
		echo "######## LISTENING SOCKETS"
		ss -tulpn 2>&1
		echo
		echo "######## ESTABLISHED CONNECTIONS"
		ss -tnp state established 2>&1
		ss -tulpnH 2>/dev/null | grep -E '"(nc|ncat|netcat|socat|python[0-9.]*|perl|ruby|php)"' | sed 's/^/[!] LISTENER: /'

		echo
		echo "######## TEMP DIRS"
		find /tmp /var/tmp /dev/shm -type f -perm /111 2>/dev/null | sed 's/^/[!] executable in temp dir: /'
		find /tmp /var/tmp /dev/shm -name '.*' -not -name '.' -not -name '.*-unix' -not -name '.X*' 2>/dev/null | sed 's/^/[!] hidden item in temp dir: /'

		echo
		echo "######## /etc/hosts"
		grep -vE '^\s*(#|$)' /etc/hosts
		grep -vE '^\s*(#|$)|localhost|ip6-|^ff0|^::1|127\.0\.1\.1' /etc/hosts | sed 's/^/[!] hosts entry: /'

		echo
		echo "######## ACCOUNTS"
		awk -F: '$3==0 && $1!="root"{print "[!] extra UID 0 account: "$1}' /etc/passwd
		awk -F: '$2==""{print "[!] empty password: "$1}' /etc/shadow
		awk -F: '$3<1000 && $1!="root" && $7!~/(nologin|false|sync|shutdown|halt)$/ {print "[!] system account with login shell: "$1" "$7}' /etc/passwd
		grep -rnE 'NOPASSWD|!authenticate' /etc/sudoers /etc/sudoers.d 2>/dev/null | sed 's/^/[!] sudoers: /'
		getent group nopasswdlogin | awk -F: '$4!=""{print "[!] nopasswdlogin members: "$4}'

		if [[ $quiet != quiet ]]; then
			echo
			echo "######## SUID files"
			suid=$(find / -xdev -type f -perm -4000 2>/dev/null | sort)
			echo "$suid"
			for f in $suid; do
				b=${f##*/}
				[[ $b =~ $GTFO_RE ]] && flag "SUID on $f"
			done
			echo
			echo "######## SGID files"
			find / -xdev -type f -perm -2000 2>/dev/null | sort
			echo
			echo "######## World-writable files (first 100)"
			find / -xdev -type f -perm -0002 2>/dev/null | head -n 100
			echo
			echo "######## Files with no valid owner/group (first 100)"
			find / -xdev \( -nouser -o -nogroup \) 2>/dev/null | head -n 100
			echo
			echo "######## Regular files modified in last 2 days (first 300)"
			find / -xdev -type f -mtime -2 -not -path '/var/lib/*' -not -path '/var/cache/*' -not -path '/var/log/*' -not -path '/root/cp_mint/*' 2>/dev/null | head -n 300
		fi
	} >"$out" 2>&1

	if [[ $quiet == quiet ]]; then
		local new=$DATA_DIR/flags.new old=$DATA_DIR/flags.old
		grep '^\[!\]' "$out" | sed -E 's/PID [0-9]+/PID n/; s/^\[!\] PROC: *[0-9]+/[!] PROC:/' | sort -u >"$new"
		[[ -f $old ]] || : >"$old"
		comm -13 "$old" "$new" | sed "s/^/$(date '+%F %T') NEW /" >>"$REPORT_DIR/monitor-flags.log"
		mv "$new" "$old"
	else
		local n
		n=$(grep -c '^\[!\]' "$out")
		echo
		info "Report written: $out   ($n flagged lines)"
		grep '^\[!\]' "$out" | head -n 80 | sed 's/^/   /'
		info "Read everything with: less $out"
	fi
}

trace_pid() {
	hdr "Trace a process back to whatever keeps starting it"
	local t pids pid exe name p a
	local -a args
	read -r -p "PID or process name: " t
	[[ -n $t ]] || return
	if [[ $t =~ ^[0-9]+$ ]]; then pids=$t; else pids=$(pgrep -f "$t" | grep -vx "$$"); fi
	[[ -n $pids ]] || {
		warn "no matching process"
		return
	}
	for pid in $pids; do
		[[ -d /proc/$pid ]] || continue
		exe=$(readlink "/proc/$pid/exe" 2>/dev/null)
		echo "${C_B}---- PID $pid ----${C_0}"
		echo "exe:     $exe"
		echo "cwd:     $(readlink "/proc/$pid/cwd" 2>/dev/null)"
		echo "cmdline: $(tr '\0' ' ' <"/proc/$pid/cmdline")"
		echo "user:    $(ps -o user= -p "$pid")"
		echo "parent chain:"
		p=$pid
		while [[ -n $p && $p -gt 1 ]]; do
			ps -o pid=,ppid=,user=,args= -p "$p" | sed 's/^/   /'
			p=$(ps -o ppid= -p "$p" | tr -d ' ')
		done
		echo "systemd unit:"
		systemctl status "$pid" --no-pager 2>&1 | head -n 4 | sed 's/^/   /'
		name=${exe##*/}
		[[ -n $name ]] || name=$t
		if [[ $name =~ ^(sh|dash|bash|zsh|python[0-9.]*|perl|ruby|php|node)$ ]]; then
			# interpreter: the thing worth searching for is the script it is running
			mapfile -d '' -t args <"/proc/$pid/cmdline"
			for a in "${args[@]:1}"; do
				[[ $a == -* ]] && continue
				name=${a##*/}
				break
			done
		fi
		echo "startup locations that mention '$name':"
		grep -rIl --exclude-dir=cp_mint -- "$name" /etc/cron* /var/spool/cron /etc/systemd /etc/init.d /etc/rc.local \
			/etc/xdg/autostart /etc/profile /etc/profile.d /etc/bash.bashrc /home/*/.config/autostart /home/*/.config/systemd \
			/home/*/.bashrc /home/*/.profile /home/*/.bash_profile /root/.bashrc /root/.profile 2>/dev/null | sed 's/^/   /'
		echo "kill order:  1) remove the startup entry above  2) delete/neutralise the binary  3) kill $pid"
	done
}

install_monitor_cron() {
	hdr "Log-only monitor (cron)"
	warn "Installs /etc/cron.d/cp-monitor: runs the persistence report every 30 min and logs NEW findings."
	warn "It never deletes or kills anything. Remove it when done: rm /etc/cron.d/cp-monitor"
	ask "Install it?" n || return
	cat >/etc/cron.d/cp-monitor <<EOF
SHELL=/bin/bash
PATH=/usr/sbin:/usr/bin:/sbin:/bin
*/30 * * * * root nice -n 19 $SCRIPT_PATH persistence_quiet >/dev/null 2>&1
EOF
	chmod 644 /etc/cron.d/cp-monitor
	change "Installed /etc/cron.d/cp-monitor  ->  findings appear in $REPORT_DIR/monitor-flags.log"
}

# ------------------------------- WRAP-UP -------------------------------------
manual_reminders() {
	hdr "Things this script cannot do for you"
	cat <<'EOF'
   - README: required services, authorized users, critical files. Re-read it now.
   - Firefox: updates, pop-up blocker, safe-browsing, no saved passwords, HTTPS-only.
   - Cinnamon: screensaver lock-on-idle and password-after-lock.
   - Application configs (Apache/MySQL/Samba/etc.) if the README says they stay.
   - Review the flagged output in /root/cp_mint/reports/ before deleting anything.
   - Check ClamAV results:  grep FOUND /root/cp_mint/reports/clamscan-*.log
   - Reboot if the kernel or lightdm changed, then confirm you can still log in.
EOF
}

step() { ask "Run: $1?" y && "$2"; }

run_all() {
	ask "Have you read the README AND finished the Forensics Questions?" n || {
		warn "Do those first, then re-run."
		return
	}
	step "Update packages / APT checks" do_updates
	step "Install scanners" install_scan_tools
	step "Start ClamAV scan in background" run_clamscan
	step "Users & groups audit" users_audit
	step "Password & login policy" password_policy
	step "Set passwords for authorized users" set_passwords
	step "LightDM hardening" lightdm_harden
	step "SSH" ssh_harden
	step "Firewall" firewall_setup
	step "Services review" services_review
	step "sysctl hardening" sysctl_harden
	step "Permissions & misc" perms_and_misc
	step "Prohibited software" prohibited_software
	step "Prohibited-file search" prohibited_files
	step "Persistence report" persistence_report
	step "rkhunter / chkrootkit / lynis / debsums" "run_other_scanners"
	manual_reminders
}
run_other_scanners() {
	run_rkhunter
	run_chkrootkit
	run_lynis
	run_debsums
}

menu() {
	local c
	while true; do
		cat <<EOF

${C_B}============== CyberPatriot Linux Mint helper ==============${C_0}
 1) Updates + APT checks + auto-updates      10) Permissions & misc
 2) Users & groups audit                     11) Prohibited software
 3) Password & login policy                  12) Prohibited-file search (report)
 4) Set passwords for authorized users       13) Install scanners
 5) LightDM (guest / autologin)              14) Run all scanners
 6) SSH                                      15) Persistence report
 7) Firewall (ufw)                           16) Trace a PID / process
 8) Services review                          17) Install log-only monitor cron
 9) sysctl hardening                         18) Show manual reminders
 a) Step through everything                  q) Quit
 Log: $LOG
EOF
		read -r -p "Choice: " c
		case $c in
		1) do_updates ;; 2) users_audit ;; 3) password_policy ;;
		4) set_passwords ;; 5) lightdm_harden ;; 6) ssh_harden ;;
		7) firewall_setup ;; 8) services_review ;; 9) sysctl_harden ;;
		10) perms_and_misc ;; 11) prohibited_software ;; 12) prohibited_files ;;
		13) install_scan_tools ;; 14) run_scanners ;; 15) persistence_report ;;
		16) trace_pid ;; 17) install_monitor_cron ;; 18) manual_reminders ;;
		a | A) run_all ;;
		q | Q) break ;;
		*) echo "?" ;;
		esac
	done
}

main() {
	case "${1:-menu}" in
	persistence_quiet)
		persistence_report quiet
		return
		;; # cron mode, no backup/prompts
	esac
	backup_configs
	case "${1:-menu}" in
	menu) menu ;;
	all) run_all ;;
	updates) do_updates ;;
	users) users_audit ;;
	policy) password_policy ;;
	passwords) set_passwords ;;
	lightdm) lightdm_harden ;;
	ssh) ssh_harden ;;
	firewall) firewall_setup ;;
	services) services_review ;;
	sysctl) sysctl_harden ;;
	perms) perms_and_misc ;;
	software) prohibited_software ;;
	files) prohibited_files ;;
	scan)
		install_scan_tools
		run_scanners
		;;
	persistence) persistence_report ;;
	trace) trace_pid ;;
	*) sed -n '2,14p' "$SCRIPT_PATH" ;;
	esac
}

main "$@"
