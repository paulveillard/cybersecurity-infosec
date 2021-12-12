#!/bin/bash
# CIS CentOS Linux 7 Benchmark v2.2.0 L1/L2 (Server Edition) - Updated/Modified by James Hemmings (Local Script Version V1.3).
# Copyright (c) 2015, Ross Hamilton. All rights reserved.
# Licenced under the BSD Licence See LICENCE file for details

AUDITDIR="/tmp/$(hostname -s)_audit"
TIME="$(date +%F_%T)"

# Configuration File Locations
auditd_conf='/etc/audit/auditd.conf'
sshd_config='/etc/ssh/sshd_config'
grub_cfg='/boot/grub2/grub.cfg'
pwqual='/etc/security/pwquality.conf'
pam_su='/etc/pam.d/su'
rsyslog_conf='/etc/rsyslog.conf'

# Create Audit Directory
mkdir -p $AUDITDIR

echo ""
echo ""
echo "CIS CentOS Linux 7 Benchmark v2.2.0 L1/L2 (Server Edition)."
echo "Updated/Modified by James Hemmings (Local Script Version V1.3)."
echo ""
echo ""
read -n 1 -s -r -p "Press any key to continue"
echo ""
echo ""
echo ""

# CIS 1.2.1
echo "Listing package update repo's..."
yum repolist >> $AUDITDIR/yum_repolist_$TIME.log

# CIS 1.2.2
echo "Enable YUM GPGCheck..."
sed -i 's/gpgcheck=0/gpgcheck=1/g' /etc/yum.conf

echo "Checking RPM GPG Key Status..."
rpm -q gpg-pubkey --qf '%{name}-%{version}-%{release} --> %{summary}\n' >> $AUDITDIR/rpm_gpgkeys_status_$TIME.log

# Disable mounting of unneeded filesystems CIS 1.1.1 and CIS 3.5
echo "Disabling Legacy Filesystems + Network Protocols..."
cat > /etc/modprobe.d/CIS.conf << "EOF"
install cramfs /bin/true
install freevxfs /bin/true
install jffs2 /bin/true
install hfs /bin/true
install hfsplus /bin/true
install squahfs /bin/true
install udf /bin/true
install dccp /bin/true
install sctp /bin/true
install rds /bin/true
install tipc /bin/true
install bnep /bin/true
install bluetooth /bin/true
install btusb /bin/true
install net-pf-31 /bin/true
install appletalk /bin/true
# !!Enviroment Specific!! Caution!!
#install cifs /bin/true
#install nfs /bin/true
#install nfsv3 /bin/true
#install nfsv4 /bin/true
#install gfs2 /bin/true
blacklist firewire-core
EOF

# Custom hardening configuration, none-cis.
echo "Removing GCC compiler..."
yum -y remove gcc*

# CIS 1.6.1.4, CIS 1.6.1.5, CIS 2.3.4, CIS 2.2.17, CIS 2.3.2, CIS 2.1.1, CIS 2.2.16, CIS 2.1.7, CIS 2.2.20, CIS 2.3.3, CIS 2.2.18, 1.6.1.5, 1.6.1.4
echo "Removing legacy services..."
yum -y remove rsh-server rsh ypserv ypbind tftp tftp-server talk talk-server telnet telnet-server xinetd setroubleshoot mcstrans >> $AUDITDIR/service_remove_$TIME.log

# CIS 2.2.6, 1.5.4 + Custom Configuration
echo "Removing un-neccessary services..."
yum -y remove bind vsftpd dovecot samba squid net-snmp openldap-servers openldap-clients xorg-x11* prelink httpd >> $AUDITDIR/service_remove_$TIME.log

# CIS 2.2.3, CIS 2.2.4, CIS 2.2.5, CIS 2.2.6, CIS 2.2.21, CIS 1.1.22
echo "Disabling Unnecessary Services..."
servicelist=(dhcpd avahi-daemon cups nfslock rpcgssd rpcbind rpcidmapd rpcsvcgssd slapd rsyncd autofs)
for i in ${servicelist[@]}; do
  [ $(systemctl disable $i 2> /dev/null) ] || echo "$i is Disabled"
done

# CIS 2.1.1
chkconfig chargen-dgram off >> $AUDITDIR/chargen_disable_status_$TIME.log
chkconfig chargen-stream off >> $AUDITDIR/chargen_disable_status_$TIME.log

# CIS 2.1.2
chkconfig daytime-dgram off >> $AUDITDIR/daytime_disable_status_$TIME.log
chkconfig daytime-stream off >> $AUDITDIR/daytime_disable_status_$TIME.log

# CIS 2.1.3 
chkconfig discard-dgram off >> $AUDITDIR/discard_disable_status_$TIME.log
chkconfig discard-stream off >> $AUDITDIR/discard_disable_status_$TIME.log

# CIS 2.1.5
chkconfig time-dgram off >> $AUDITDIR/time_disable_status_$TIME.log
chkconfig time-stream off >> $AUDITDIR/time_disable_status_$TIME.log

# CIS 2.2.1.1
echo "Installing NTP..."
yum -y install ntp >> $AUDITDIR/service_install_$TIME.log

# 3.6.1 
echo "Installing iptables..." 
yum -y install iptables >> $AUDITDIR/service_install_$TIME.log		

# CIS 1.3.1
echo "Installing AIDE..."
yum -y install aide >> $AUDITDIR/service_install_$TIME.log

# CIS 1.3.1
echo "Configuring AIDE..."
aide --init >> $AUDITDIR/aide_init_status_$TIME.log
mv /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz

# CIS 1.3.2
echo "0 5 * * * /usr/sbin/aide --check" >> /etc/crontab

echo "Setting GMT Timezone..."
timedatectl set-timezone Europe/London

# CIS 1.6.1.2
echo "Enabling SELinux (Targeted)..."
sed -i 's/^SELINUX=.*/SELINUX=enforcing/g' /etc/selinux/config

# CIS 1.6.1.3
sed -i 's/^SELINUXTYPE=.*/SELINUXTYPE=targeted/g' /etc/selinux/config

# CIS 5.4.4
echo "Setting Daemon Service Umask..."
cp /etc/init.d/functions $AUDITDIR/functions_$TIME.bak
echo "umask 027" >> /etc/init.d/functions

# CIS 5.3.4
echo "Upgrading password hashing algorithm to SHA512..."
authconfig --passalgo=sha512 --update

# CIS 1.5.1
echo "Setting core dump security limits..."
echo '* hard core 0' > /etc/security/limits.conf

# CIS 4.2.1.2 - 4.2.1.3  Configure /etc/rsyslog.conf - This is environment specific
echo "Generating additional rsyslog logs..."
echo 'auth,user.* /var/log/user' >> /etc/rsyslog.conf
echo 'kern.* /var/log/kern.log' >> /etc/rsyslog.conf
echo 'daemon.* /var/log/daemon.log' >> /etc/rsyslog.conf
echo 'syslog.* /var/log/syslog' >> /etc/rsyslog.conf
echo 'lpr,news,uucp,local0,local1,local2,local3,local4,local5,local6.* /var/log/unused.log' >> /etc/rsyslog.conf
touch /var/log/user /var/log/kern.log /var/log/daemon.log /var/log/syslog /var/log/unused.log
chmod og-rwx /var/log/user /var/log/kern.log /var/log/daemon.log /var/log/syslog /var/log/unused.log
chown root:root /var/log/user /var/log/kern.log /var/log/daemon.log /var/log/syslog /var/log/unused.log

# CIS 4.2.1.3 Ensure rsyslog default file permissions configured (Scored)
echo "Configuring rsyslog default file permissions..."
sed -i 's/^$FileCreateMode .*$/$FileCreateMode = 0640/' ${rsyslog_conf}

# CIS 4.2.1.4 - 4.2.1.5  Configure rsyslog to Send Log to a Remote Log Host - This is environment specific
# CIS 4.1.1.1 Configure Audit Log Storage Size
echo "Configuring Audit Log Storage Size..."
cp -a ${auditd_conf} ${auditd_conf}.bak
sed -i 's/^max_log_file .*$/max_log_file = 2048/' ${auditd_conf}

# CIS 4.1.1.2 Disable system on Audit Log Full - This is VERY environment specific (and likely controversial)
sed -i 's/^space_left_action.*$/space_left_action = SYSLOG/' ${auditd_conf}
sed -i 's/^action_mail_acct.*$/action_mail_acct = root/' ${auditd_conf}
sed -i 's/^admin_space_left_action.*$/admin_space_left_action = halt/' ${auditd_conf}

# CIS 4.1.1.3 Keep All Auditing Information
sed -i 's/^max_log_file_action.*$/max_log_file_action = keep_logs/' ${auditd_conf}

# CIS 4.1.2
echo "Enabling auditd service..."
systemctl enable auditd 

# CIS 4.1.4 - 4.1.18
echo "Setting audit rules..."
cat > /etc/audit/audit.rules << "EOF"

## Remove any existing rules
-D

## Increase kernel buffer size
-b 8192

## Failure of auditd causes a kernel panic
## Possible values: 0 (silent), 1 (printk, print a failure message), 2 (panic, halt the system)
-f 2

## Self Auditing ---------------------------------------------------------------
## Audit the audit logs
### Successful and unsuccessful attempts to read information from the audit records
-w /var/log/audit/ -k auditlog

## Auditd configuration
### Modifications to audit configuration that occur while the audit collection functions are operating
-w /etc/audit/ -p wa -k auditconfig
-w /etc/libaudit.conf -p wa -k auditconfig
-w /etc/audisp/ -p wa -k audispconfig

## Monitor for use of audit management tools
-w /sbin/auditctl -p x -k audittools
-w /sbin/auditd -p x -k audittools

# Filters ---------------------------------------------------------------------

## Ignore SELinux AVC records
-a always,exclude -F msgtype=AVC

## Ignore current working directory records
-a always,exclude -F msgtype=CWD

## Ignore EOE records (End Of Event, not needed)
-a always,exclude -F msgtype=EOE

## Cron jobs fill the logs with stuff we normally don't want (works with SELinux)
-a never,user -F subj_type=crond_t
-a exit,never -F subj_type=crond_t

## This prevents chrony from overwhelming the logs
-a never,exit -F arch=b64 -S adjtimex -F auid=unset -F uid=chrony -F subj_type=chronyd_t

## This is not very interesting and wastes a lot of space if the server is public facing
-a always,exclude -F msgtype=CRYPTO_KEY_USER

## VMWare tools
-a exit,never -F arch=b32 -S fork -F success=0 -F path=/usr/lib/vmware-tools -F subj_type=initrc_t -F exit=-2
-a exit,never -F arch=b64 -S fork -F success=0 -F path=/usr/lib/vmware-tools -F subj_type=initrc_t -F exit=-2

### High Volume Event Filter (especially on Linux Workstations)
-a exit,never -F arch=b32 -F dir=/dev/shm -k sharedmemaccess
-a exit,never -F arch=b64 -F dir=/dev/shm -k sharedmemaccess
-a exit,never -F arch=b32 -F dir=/var/lock/lvm -k locklvm
-a exit,never -F arch=b64 -F dir=/var/lock/lvm -k locklvm

# Rules -----------------------------------------------------------------------

# Kernel parameters
-w /etc/sysctl.conf -p wa -k sysctl

## Modprobe configuration
-w /etc/modprobe.conf -p wa -k modprobe

## Stunnel
-w /usr/sbin/stunnel -p x -k stunnel

## Cron configuration & scheduled jobs
-w /etc/cron.allow -p wa -k cron
-w /etc/cron.deny -p wa -k cron
-w /etc/cron.d/ -p wa -k cron
-w /etc/cron.daily/ -p wa -k cron
-w /etc/cron.hourly/ -p wa -k cron
-w /etc/cron.monthly/ -p wa -k cron
-w /etc/cron.weekly/ -p wa -k cron
-w /etc/crontab -p wa -k cron
-w /var/spool/cron/crontabs/ -k cron

## Passwd
-w /usr/bin/passwd -p x -k passwd_modification

## Tools to change group identifiers
-w /usr/sbin/groupadd -p x -k group_modification
-w /usr/sbin/groupmod -p x -k group_modification
-w /usr/sbin/addgroup -p x -k group_modification
-w /usr/sbin/useradd -p x -k user_modification
-w /usr/sbin/usermod -p x -k user_modification
-w /usr/sbin/adduser -p x -k user_modification

## System startup scripts
-w /etc/inittab -p wa -k init
-w /etc/init.d/ -p wa -k init
-w /etc/init/ -p wa -k init

## Library search paths
-w /etc/ld.so.conf -p wa -k libpath

## Pam configuration
-w /etc/pam.d/ -p wa -k pam
-w /etc/security/limits.conf -p wa  -k pam
-w /etc/security/pam_env.conf -p wa -k pam
-w /etc/security/namespace.conf -p wa -k pam
-w /etc/security/namespace.init -p wa -k pam

## SSH configuration
-w /etc/ssh/sshd_config -k sshd

# Systemd
-w /bin/systemctl -p x -k systemd 
-w /etc/systemd/ -p wa -k systemd

## Monitor usage of commands to change power state
-w /sbin/shutdown -p x -k power
-w /sbin/poweroff -p x -k power
-w /sbin/reboot -p x -k power
-w /sbin/halt -p x -k power

## Process ID change (switching accounts) applications
-w /bin/su -p x -k priv_esc
-w /usr/bin/sudo -p x -k priv_esc
-w /etc/sudoers -p rw -k priv_esc

# CIS Benchmark Rules -----------------------------------------------------------------------

# CIS 4.1.4 Ensure events that modify date and time information are collected
-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change
-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time-change
-a always,exit -F arch=b64 -S clock_settime -k time-change
-a always,exit -F arch=b32 -S clock_settime -k time-change
-w /etc/localtime -p wa -k time-change

# CIS 4.1.5 Ensure events that modify user/group information are collected
-w /etc/group -p wa -k identity
-w /etc/passwd -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/security/opasswd -p wa -k identity

# CIS 4.1.6 Ensure events that modify the system's network environment are collected
-a always,exit -F arch=b64 -S sethostname -S setdomainname -k system-locale
-a always,exit -F arch=b32 -S sethostname -S setdomainname -k system-locale
-w /etc/issue -p wa -k system-locale
-w /etc/issue.net -p wa -k system-locale
-w /etc/hosts -p wa -k system-locale
-w /etc/sysconfig/network -p wa -k system-locale
-w /etc/sysconfig/network-scripts/ -p wa -k system-locale

# CIS 4.1.7 Ensure events that modify the system's Mandatory Access Controls are collected
-w /etc/selinux/ -p wa -k MAC-policy
-w /usr/share/selinux/ -p wa -k MAC-policy

# CIS 4.1.8 Ensure login and logout events are collected
-w /var/log/faillog -p wa -k logins
-w /var/log/lastlog -p wa -k logins
-w /var/log/tallylog -p wa -k logins

# CIS 4.1.9 Ensure session initiation information is collected
-w /var/run/utmp -p wa -k session
-w /var/log/wtmp -p wa -k session
-w /var/log/btmp -p wa -k session

# CIS 4.1.10 Ensure discretionary access control permission modification events are collected
-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod

# CIS 4.1.11 Ensure unsuccessful unauthorized file access attempts are collected
-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access

# CIS 4.1.13 Ensure successful file system mounts are collected
-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts
-a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts

# CIS 4.1.14 Ensure file deletion events by users are collected
-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete
-a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete

# CIS 4.1.15 Ensure changes to system administration scope (sudoers) is collected
-w /etc/sudoers -p wa -k scope
-w /etc/sudoers.d -p wa -k scope

# CIS 4.1.16 Ensure system administrator actions (sudolog) are collected
-w /var/log/sudo.log -p wa -k actions

# CIS 4.1.17 Ensure kernel module loading and unloading is collected (Scored)
-w /sbin/insmod -p x -k modules
-w /sbin/rmmod -p x -k modules
-w /sbin/modprobe -p x -k modules
-a always,exit -F arch=b64 -S init_module -S delete_module -k modules

# 4.1.12 Ensure use of privileged commands is collected
-a always,exit -F path=/usr/bin/wall -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/write -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/chage -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/gpasswd -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/newgrp -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/mount -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/chfn -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/chsh -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/su -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/umount -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/crontab -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/pkexec -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/ssh-agent -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/passwd -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/sudo -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/sbin/pam_timestamp_check -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/sbin/unix_chkpwd -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/sbin/netreport -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/sbin/usernetctl -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/sbin/postdrop -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/sbin/postqueue -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/lib/polkit-1/polkit-agent-helper-1 -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/lib64/dbus-1/dbus-daemon-launch-helper -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/libexec/utempter/utempter -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/libexec/openssh/ssh-keysign -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged

# Special Rules ---------------------------------------------------------------

## 32bit API Exploitation
### If you are on a 64 bit platform, everything _should_ be running
### in 64 bit mode. This rule will detect any use of the 32 bit syscalls
### because this might be a sign of someone exploiting a hole in the 32
### bit API.
-a always,exit -F arch=b32 -S all -k 32bit_api

## Reconnaissance
-w /usr/bin/whoami -p x -k recon
-w /etc/issue -p r -k recon
-w /etc/hostname -p r -k recon

## Suspicious activity
-w /usr/bin/wget -p x -k susp_activity
-w /usr/bin/curl -p x -k susp_activity
-w /usr/bin/base64 -p x -k susp_activity
-w /bin/nc -p x -k susp_activity
-w /bin/netcat -p x -k susp_activity
-w /usr/bin/ncat -p x -k susp_activity
-w /usr/bin/ssh -p x -k susp_activity
-w /usr/bin/socat -p x -k susp_activity
-w /usr/bin/wireshark -p x -k susp_activity
-w /usr/bin/rawshark -p x -k susp_activity
-w /usr/bin/rdesktop -p x -k sbin_susp

## Sbin suspicious activity
-w /sbin/iptables -p x -k sbin_susp 
-w /sbin/ifconfig -p x -k sbin_susp
-w /usr/sbin/tcpdump -p x -k sbin_susp
-w /usr/sbin/traceroute -p x -k sbin_susp

## Injection 
### These rules watch for code injection by the ptrace facility.
### This could indicate someone trying to do something bad or just debugging
-a always,exit -F arch=b32 -S ptrace -k tracing
-a always,exit -F arch=b64 -S ptrace -k tracing
-a always,exit -F arch=b32 -S ptrace -F a0=0x4 -k code_injection
-a always,exit -F arch=b64 -S ptrace -F a0=0x4 -k code_injection
-a always,exit -F arch=b32 -S ptrace -F a0=0x5 -k data_injection
-a always,exit -F arch=b64 -S ptrace -F a0=0x5 -k data_injection
-a always,exit -F arch=b32 -S ptrace -F a0=0x6 -k register_injection
-a always,exit -F arch=b64 -S ptrace -F a0=0x6 -k register_injection

## Privilege Abuse
### The purpose of this rule is to detect when an admin may be abusing power by looking in user's home dir.
-a always,exit -F dir=/home -F uid=0 -F auid>=1000 -F auid!=4294967295 -C auid!=obj_uid -k power_abuse

# RPM (Redhat/CentOS)
-w /usr/bin/rpm -p x -k software_mgmt
-w /usr/bin/yum -p x -k software_mgmt

# CIS 4.1.18 Ensure the audit configuration is immutable (Scored)
-e 2
EOF

echo "Configuring boot.log log rotation..."
sed -i "1 i /var/log/boot.log" /etc/logrotate.d/syslog 			# CIS 4.3

echo "Configuring Cron and Anacron..."
yum -y install cronie-anacron >> $AUDITDIR/service_install_$TIME.log
systemctl enable crond # CIS 5.1.1
chown root:root /etc/anacrontab
chmod og-rwx /etc/anacrontab
chown root:root /etc/crontab # CIS 5.1.2
chmod og-rwx /etc/crontab  # CIS 5.1.2
chown root:root /etc/cron.hourly # CIS 5.1.3
chmod og-rwx /etc/cron.hourly # CIS 5.1.3
chown root:root /etc/cron.daily # CIS 5.1.4
chmod og-rwx /etc/cron.daily # CIS 5.1.4
chown root:root /etc/cron.weekly # CIS 5.1.5 
chmod og-rwx /etc/cron.weekly # CIS 5.1.5 
chown root:root /etc/cron.monthly # CIS 5.1.6
chmod og-rwx /etc/cron.monthly # CIS 5.1.6
chown root:root /etc/cron.d # 5.1.7
chmod og-rwx /etc/cron.d # 5.1.7
/bin/rm -f /etc/cron.deny # CIS 5.1.8
/bin/rm -f /etc/at.deny # CIS 5.1.8
touch /etc/cron.allow # CIS 5.1.8
touch /etc/at.allow # CIS 5.1.8
chmod og-rwx /etc/cron.allow # CIS 5.1.8
chmod og-rwx /etc/at.allow # CIS 5.1.8
chown root:root /etc/cron.allow # CIS 5.1.8 
chown root:root /etc/at.allow # CIS 5.1.8

echo "Creating Banner..."
sed -i "s/\#Banner none/Banner \/etc\/issue\.net/" /etc/ssh/sshd_config
cp -p /etc/issue.net $AUDITDIR/issue.net_$TIME.bak
cat > /etc/issue.net << 'EOF'
/------------------------------------------------------------------------\
|                       *** NOTICE TO USERS ***                          |
|                                                                        |
| This computer system is the private property of YOUR_COMPANY_NAME      |
| It is for authorized use only.                                         |
|                                                                        |
| Users (authorized or unauthorized) have no explicit or implicit        |
| expectation of privacy.                                                |
|                                                                        |
| Any or all uses of this system and all files on this system may be     |
| intercepted, monitored, recorded, copied, audited, inspected, and      |
| disclosed to your employer, to authorized site, government, and law    |
| enforcement personnel, as well as authorized officials of government   |
| agencies, both domestic and foreign.                                   |
|                                                                        |
| By using this system, the user consents to such interception,          |
| monitoring, recording, copying, auditing, inspection, and disclosure   |
| at the discretion of such personnel or officials.  Unauthorized or     |
| improper use of this system may result in civil and criminal penalties |
| and administrative or disciplinary action, as appropriate. By          |
| continuing to use this system you indicate your awareness of and       |
| consent to these terms and conditions of use. LOG OFF IMMEDIATELY if   |
| you do not agree to the conditions stated in this warning.             |
\------------------------------------------------------------------------/
EOF
cp -p /etc/motd /etc/motd_$TIME.bak
cat > /etc/motd << 'EOF'
YOUR_COMPANY_NAME AUTHORIZED USE ONLY
EOF

echo "Configuring SSH..."
cp /etc/ssh/sshd_config $AUDITDIR/sshd_config_$TIME.bak
chown root:root ${sshd_config}						# CIS 5.2.1
chmod 600 ${sshd_config}						# CIS 5.2.1
sed -i "s/\#Protocol/Protocol/" ${sshd_config}				# CIS 5.2.2
sed -i "s/\#LogLevel/LogLevel/" ${sshd_config}				# CIS 5.2.3
sed -i "s/X11Forwarding yes/X11Forwarding no/" ${sshd_config}		# CIS 5.2.4
sed -i "s/\#MaxAuthTries 6/MaxAuthTries 4/" ${sshd_config}		# CIS 5.2.5
sed -i "s/\#IgnoreRhosts yes/IgnoreRhosts yes/" ${sshd_config}		# CIS 5.2.6
sed -i "s/\#HostbasedAuthentication no/HostbasedAuthentication no/" ${sshd_config}	# CIS 5.2.7
sed -i "s/\#PermitRootLogin yes/PermitRootLogin no/" ${sshd_config}	# CIS 5.2.8
sed -i "s/\#PermitEmptyPasswords no/PermitEmptyPasswords no/" ${sshd_config}	# CIS 5.2.9
sed -i "s/\#PermitUserEnvironment no/PermitUserEnvironment no/" ${sshd_config}	# CIS 5.2.10

line_num=$(grep -n "^\# Ciphers and keying" ${sshd_config} | cut -d: -f1)
sed -i "${line_num} a MACs hmac-sha1-etm@openssh.com,umac-64-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-ripemd160-etm@openssh.com,hmac-sha1,umac-64@openssh.com,umac-128@openssh.com,hmac-sha2-256,hmac-sha2-512,hmac-ripemd160" ${sshd_config}  # CIS 5.2.12
sed -i "${line_num} a Ciphers aes128-ctr,aes192-ctr,aes256-ctr" ${sshd_config}  # CIS 5.2.11

sed -i "s/\#ClientAliveInterval 0/ClientAliveInterval 300/" ${sshd_config}	# CIS 5.2.13
sed -i "s/\#ClientAliveCountMax 3/ClientAliveCountMax 0/" ${sshd_config}	# CIS 5.2.13
sed -i "s/\#LoginGraceTime 2m/LoginGraceTime 60/" ${sshd_config}	# CIS 5.2.14
sed -i "s/\#Banner none/Banner \/etc\/issue\.net/" ${sshd_config}    	# CIS 5.2.16

systemctl restart sshd >> $AUDITDIR/service_restart_$TIME.log

# CIS 5.3.1
echo "Setting Password Policy..."
sed -i 's/^# minlen =.*$/minlen = 12/' ${pwqual}
sed -i 's/^# dcredit =.*$/dcredit = -1/' ${pwqual}
sed -i 's/^# ucredit =.*$/ucredit = -1/' ${pwqual}
sed -i 's/^# ocredit =.*$/ocredit = -1/' ${pwqual}
sed -i 's/^# lcredit =.*$/lcredit = -1/' ${pwqual}

# CIS 5.3.2
echo "Configuring PAM account lockout..."
content="$(egrep -v "^#|^auth" /etc/pam.d/password-auth)"
echo -e "auth required pam_env.so
auth required pam_faillock.so preauth audit silent deny=5 unlock_time=1800
auth [success=1 default=bad] pam_unix.so
auth [default=die] pam_faillock.so authfail audit deny=5 unlock_time=1800
auth sufficient pam_faillock.so authsucc audit deny=5 unlock_time=1800
auth required pam_deny.so\n$content" > /etc/pam.d/password-auth

# CIS 5.3.2
content="$(egrep -v "^#|^auth" /etc/pam.d/system-auth)"
echo -e "auth required pam_env.so
auth sufficient pam_unix.so remember=5
auth required pam_faillock.so preauth audit silent deny=5 unlock_time=1800
auth [success=1 default=bad] pam_unix.so
auth [default=die] pam_faillock.so authfail audit deny=5 unlock_time=1800
auth sufficient pam_faillock.so authsucc audit deny=5 unlock_time=1800
auth required pam_deny.so\n$content" > /etc/pam.d/system-auth

echo "Setting password expiration..."
login_defs=/etc/login.defs
sed -i 's/^PASS_MAX_DAYS.*$/PASS_MAX_DAYS 0/' ${login_defs} # CIS 5.4.1.1 - Custom per NCSC guidelines.
sed -i 's/^PASS_MIN_DAYS.*$/PASS_MIN_DAYS 7/' ${login_defs} # CIS 5.4.1.2
sed -i 's/^PASS_MIN_LEN.*$/PASS_MIN_LEN 12/' ${login_defs} # Custom per NCSC guidelines.
sed -i 's/^PASS_WARN_AGE.*$/PASS_WARN_AGE 7/' ${login_defs} # CIS 5.4.1.3

# CIS 5.3.3
echo "Preventing password re-use..."
line_num="$(grep -n "^password[[:space:]]*sufficient[[:space:]]*pam_unix.so*" /etc/pam.d/system-auth | cut -d: -f1)"
sed -n "$line_num p" system-auth | grep remember || sed "${line_num} s/$/ remember=5/" /etc/pam.d/system-auth

# CIS 5.5
echo "Securing TTY..."
cp /etc/securetty /etc/securetty.orig
#> /etc/securetty
cat << EOF > /etc/securetty
console
tty1
EOF

# CIS 5.4.4
echo "Setting default umask for users..."
line_num=$(grep -n "^[[:space:]]*umask" /etc/bashrc | head -1 | cut -d: -f1)
sed -i ${line_num}s/002/027/ /etc/bashrc
line_num=$(grep -n "^[[:space:]]*umask" /etc/profile | head -1 | cut -d: -f1)
sed -i ${line_num}s/002/027/ /etc/profile

echo "Locking inactive user accounts..."
# Locks 30 days after expiry.
useradd -D -f 30

# CIS 1.1.3, 1.1.4, 1.1.5, 1.1.8, 1.1.9, 1.1.10
echo "Securing /TMP... (/etc/fstab)..."
cat << EOF >> /etc/fstab
/tmp      /var/tmp    none    rw,nosuid,nodev,noexec,bind    0 0
none	/dev/shm	tmpfs	rw,nosuid,nodev,noexec	0 0
EOF

# CIS 4.1.3, 1.6.1.1
echo "Enabling auditd GRUB startup..."
sed -i s/'^GRUB_CMDLINE_LINUX="'/'GRUB_CMDLINE_LINUX="audit=1 selinux=1 enforcing=1 '/ /etc/default/grub 
grub2-mkconfig -o ${grub_cfg}

echo "Verifying System File Permissions..."			
chmod og-rwx /boot/grub2/grub.cfg # CIS 1.4.1
chmod 600 /etc/rsyslog.conf
chmod 644 /etc/passwd # CIS 6.1.2
chmod 000 /etc/shadow # CIS 6.1.3
chmod 000 /etc/gshadow # CIS 6.1.5
chmod 644 /etc/group  # CIS 6.1.4
chown root:root /boot/grub2/grub.cfg	# CIS 1.4.1
chown root:root /etc/passwd # CIS 6.1.2
chown root:root /etc/shadow # CIS 6.1.3
chown root:root /etc/gshadow # CIS 6.1.5
chown root:root /etc/group  # CIS 6.1.4

# CIS 1.1.21 
echo "Setting Sticky Bit on All World-Writable Directories..."
df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type d -perm -0002 2>/dev/null | xargs chmod a+t  >> $AUDITDIR/sticky_on_world_$TIME.log

echo "Searching for world writable files..."
df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type f -perm -0002 >> $AUDITDIR/world_writable_files_$TIME.log

echo "Searching for Un-owned files and directories..."
df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -nouser -ls >> $AUDITDIR/unowned_files_$TIME.log

# Find Un-grouped Files and Directories
echo "Searching for Un-grouped files and directories..."
df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -nogroup -ls >> $AUDITDIR/ungrouped_files_$TIME.log

echo "Searching for SUID System Executables..."
df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type f -perm -4000 -print >> $AUDITDIR/suid_exec_$TIME.log

echo "Searching for SGID System Executables..."
df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type f -perm -2000 -print >> $AUDITDIR/sgid_exec_$TIME.log

# CIS 6.2.1
echo "Searching for empty password fields..."
/bin/cat /etc/shadow | /bin/awk -F: '($2 == "" ) { print $1 " does not have a password "}' >> $AUDITDIR/empty_passwd_$TIME.log

# CIS 6.2.5
echo "Verifying only root is UID 0..."
/bin/cat /etc/passwd | awk -F: '($3 == 0) { print $1 }' >> $AUDITDIR/uid_0_account_$TIME.log

# CIS 6.2.2, CIS 6.2.3, CIS 6.2.4
echo "Reviewing User and Group Settings..."
echo "Reviewing User and Group Settings..." >> $AUDITDIR/reviewusrgrp_$TIME.log
/bin/grep '^+:' /etc/passwd >> $AUDITDIR/reviewusrgrp_$TIME.log
/bin/grep '^+:' /etc/shadow >> $AUDITDIR/reviewusrgrp_$TIME.log
/bin/grep '^+:' /etc/group >> $AUDITDIR/reviewusrgrp_$TIME.log
/bin/cat /etc/passwd | /bin/awk -F: '($3 == 0) { print $1 }' >> $AUDITDIR/reviewusrgrp_$TIME.log

# CIS 6.2.6
echo "Checking root PATH integrity..."
if [ "`echo $PATH | /bin/grep :: `" != "" ]; then
    echo "Empty Directory in PATH (::)" >> $AUDITDIR/root_path_$TIME.log
fi

if [ "`echo $PATH | /bin/grep :$`"  != "" ]; then
    echo "Trailing : in PATH" >> $AUDITDIR/root_path_$TIME.log
fi

# CIS 6.2.8 
p=`echo $PATH | /bin/sed -e 's/::/:/' -e 's/:$//' -e 's/:/ /g'`
set -- $p
while [ "$1" != "" ]; do
    if [ "$1" = "." ]; then
        echo "PATH contains ." >> $AUDITDIR/root_path_$TIME.log
        shift
        continue
    fi
    if [ -d $1 ]; then
        dirperm=`/bin/ls -ldH $1 | /bin/cut -f1 -d" "`
        if [ `echo $dirperm | /bin/cut -c6 ` != "-" ]; then
            echo "Group Write permission set on directory $1" >> $AUDITDIR/root_path_$TIME.log
        fi
        if [ `echo $dirperm | /bin/cut -c9 ` != "-" ]; then
            echo "Other Write permission set on directory $1" >> $AUDITDIR/root_path_$TIME.log
        fi
            dirown=`ls -ldH $1 | awk '{print $3}'`
           if [ "$dirown" != "root" ] ; then
             echo "$1 is not owned by root" >> $AUDITDIR/root_path_$TIME.log
              fi
    else
            echo "$1 is not a directory" >> $AUDITDIR/root_path_$TIME.log
      fi
    shift
done

echo "Checking Permissions on User Home Directories..."

for dir in `/bin/cat /etc/passwd  | /bin/egrep -v '(root|halt|sync|shutdown)' |\
    /bin/awk -F: '($8 == "PS" && $7 != "/sbin/nologin") { print $6 }'`; do
        dirperm=`/bin/ls -ld $dir | /bin/cut -f1 -d" "`
        if [ `echo $dirperm | /bin/cut -c6 ` != "-" ]; then
            echo "Group Write permission set on directory $dir" >> $AUDITDIR/home_permission_$TIME.log
        fi
        if [ `echo $dirperm | /bin/cut -c8 ` != "-" ]; then
            echo "Other Read permission set on directory $dir" >> $AUDITDIR/home_permission_$TIME.log

        fi

        if [ `echo $dirperm | /bin/cut -c9 ` != "-" ]; then
            echo "Other Write permission set on directory $dir" >> $AUDITDIR/home_permission_$TIME.log
        fi
        if [ `echo $dirperm | /bin/cut -c10 ` != "-" ]; then
            echo "Other Execute permission set on directory $dir" >> $AUDITDIR/home_permission_$TIME.log
        fi
done

# CIS 6.2.10
echo "Checking User Dot File Permissions..."
for dir in `/bin/cat /etc/passwd | /bin/egrep -v '(root|sync|halt|shutdown)' |
/bin/awk -F: '($7 != "/sbin/nologin") { print $6 }'`; do
    for file in $dir/.[A-Za-z0-9]*; do

        if [ ! -h "$file" -a -f "$file" ]; then
            fileperm=`/bin/ls -ld $file | /bin/cut -f1 -d" "`

            if [ `echo $fileperm | /bin/cut -c6 ` != "-" ]; then
                echo "Group Write permission set on file $file" >> $AUDITDIR/dotfile_permission_$TIME.log
            fi
            if [ `echo $fileperm | /bin/cut -c9 ` != "-" ]; then
                echo "Other Write permission set on file $file" >> $AUDITDIR/dotfile_permission_$TIME.log
            fi
        fi

    done

done

# CIS 6.2.13 
echo "Checking Permissions on User .netrc Files..."
for dir in `/bin/cat /etc/passwd | /bin/egrep -v '(root|sync|halt|shutdown)' |\
    /bin/awk -F: '($7 != "/sbin/nologin") { print $6 }'`; do
    for file in $dir/.netrc; do
        if [ ! -h "$file" -a -f "$file" ]; then
            fileperm=`/bin/ls -ld $file | /bin/cut -f1 -d" "`
            if [ `echo $fileperm | /bin/cut -c5 ` != "-" ]
            then
                echo "Group Read set on $file" >> $AUDITDIR/netrd_permission_$TIME.log
            fi
            if [ `echo $fileperm | /bin/cut -c6 ` != "-" ]
            then
                echo "Group Write set on $file" >> $AUDITDIR/netrd_permission_$TIME.log
            fi
            if [ `echo $fileperm | /bin/cut -c7 ` != "-" ]
            then
                echo "Group Execute set on $file" >> $AUDITDIR/netrd_permission_$TIME.log
            fi
            if [ `echo $fileperm | /bin/cut -c8 ` != "-" ]
            then
                echo "Other Read  set on $file" >> $AUDITDIR/netrd_permission_$TIME.log
            fi
            if [ `echo $fileperm | /bin/cut -c9 ` != "-" ]
            then
                echo "Other Write set on $file" >> $AUDITDIR/netrd_permission_$TIME.log
            fi
            if [ `echo $fileperm | /bin/cut -c10 ` != "-" ]
            then
                echo "Other Execute set on $file" >> $AUDITDIR/netrd_permission_$TIME.log
            fi
        fi
    done
done

# CIS 6.2.14
echo "Checking for Presence of User .rhosts Files..."
for dir in `/bin/cat /etc/passwd | /bin/egrep -v '(root|halt|sync|shutdown)' |\
    /bin/awk -F: '($7 != "/sbin/nologin") { print $6 }'`; do
    for file in $dir/.rhosts; do
        if [ ! -h "$file" -a -f "$file" ]; then
            echo ".rhosts file in $dir" >> $AUDITDIR/rhosts_$TIME.log
        fi    done
done

# CIS 6.2.15
echo "Checking Groups in /etc/passwd..."

for i in $(cut -s -d: -f4 /etc/passwd | sort -u ); do
  grep -q -P "^.*?:x:$i:" /etc/group
  if [ $? -ne 0 ]; then
    echo "Group $i is referenced by /etc/passwd but does not exist in /etc/group" >> $AUDITDIR/audit_$TIME.log
  fi
done

# CIS 6.2.7
echo "Checking That Users Are Assigned Home Directories..."

cat /etc/passwd | awk -F: '{ print $1 " " $3 " " $6 }' | while read user uid dir; do
  if [ $uid -ge 500 -a ! -d "$dir" -a $user != "nfsnobody" ]; then
 echo "The home directory ($dir) of user $user does not exist." >> $AUDITDIR/audit_$TIME.log
 fi
done

# CIS 6.2.9
echo "Checking That Defined Home Directories Exist..."

cat /etc/passwd | awk -F: '{ print $1 " " $3 " " $6 }' | while read user uid dir; do
 if [ $uid -ge 500 -a -d "$dir" -a $user != "nfsnobody" ]; then
 owner=$(stat -L -c "%U" "$dir")
 if [ "$owner" != "$user" ]; then
 echo "The home directory ($dir) of user $user is owned by $owner." >> $AUDITDIR/audit_$TIME.log
 fi
 fi
done

# CIS 6.2.18
echo "Checking for Duplicate UIDs..."

/bin/cat /etc/passwd | /bin/cut -f3 -d":" | /bin/sort -n | /usr/bin/uniq -c |\
    while read x ; do
    [ -z "${x}" ] && break
    set - $x
    if [ $1 -gt 1 ]; then
        users=`/bin/gawk -F: '($3 == n) { print $1 }' n=$2 \
            /etc/passwd | /usr/bin/xargs`
        echo "Duplicate UID ($2): ${users}" >> $AUDITDIR/audit_$TIME.log
    fi
done

# CIS 6.2.17 
echo "Checking for Duplicate GIDs..."

/bin/cat /etc/group | /bin/cut -f3 -d":" | /bin/sort -n | /usr/bin/uniq -c |\
    while read x ; do
    [ -z "${x}" ] && break
    set - $x
    if [ $1 -gt 1 ]; then
        grps=`/bin/gawk -F: '($3 == n) { print $1 }' n=$2 \
            /etc/group | xargs`
        echo "Duplicate GID ($2): ${grps}" >> $AUDITDIR/audit_$TIME.log
    fi
done

echo "Checking That Reserved UIDs Are Assigned to System Accounts..."
defUsers="root bin daemon adm lp sync shutdown halt mail news uucp operator games
gopher ftp nobody nscd vcsa rpc mailnull smmsp pcap ntp dbus avahi sshd rpcuser
nfsnobody haldaemon avahi-autoipd distcache apache oprofile webalizer dovecot squid
named xfs gdm sabayon usbmuxd rtkit abrt saslauth pulse postfix tcpdump"
/bin/cat /etc/passwd | /bin/awk -F: '($3 < 500) { print $1" "$3 }' |\
    while read user uid; do
        found=0
        for tUser in ${defUsers}
        do
            if [ ${user} = ${tUser} ]; then
                found=1
            fi
        done
        if [ $found -eq 0 ]; then
            echo "User $user has a reserved UID ($uid)."  >> $AUDITDIR/audit_$TIME.log
        fi
    done

# CIS 6.2.18 
echo "Checking for Duplicate User Names..."
cat /etc/passwd | cut -f1 -d":" | sort -n | /usr/bin/uniq -c |\
    while read x ; do
    [ -z "${x}" ] && break
    set - $x
    if [ $1 -gt 1 ]; then
        uids=`/bin/gawk -F: '($1 == n) { print $3 }' n=$2 \
            /etc/passwd | xargs`
        echo "Duplicate User Name ($2): ${uids}"  >> $AUDITDIR/audit_$TIME.log
    fi
done

# CIS 6.2.19
echo "Checking for Duplicate Group Names..."

cat /etc/group | cut -f1 -d":" | /bin/sort -n | /usr/bin/uniq -c |\
    while read x ; do
    [ -z "${x}" ] && break
    set - $x
    if [ $1 -gt 1 ]; then
        gids=`/bin/gawk -F: '($1 == n) { print $3 }' n=$2 \
            /etc/group | xargs`
        echo "Duplicate Group Name ($2): ${gids}"  >> $AUDITDIR/audit_$TIME.log
    fi
done

# CIS 6.2.12 
echo "Checking for Presence of User .netrc Files..."

for dir in `/bin/cat /etc/passwd |\
    /bin/awk -F: '{ print $6 }'`; do
    if [ ! -h "$dir/.netrc" -a -f "$dir/.netrc" ]; then
        echo ".netrc file $dir/.netrc exists"  >> $AUDITDIR/audit_$TIME.log
    fi
done

# CIS 6.2.11
echo "Checking for Presence of User .forward Files..."

for dir in `/bin/cat /etc/passwd |\
    /bin/awk -F: '{ print $6 }'`; do
    if [ ! -h "$dir/.forward" -a -f "$dir/.forward" ]; then
        echo ".forward file $dir/.forward exists"  >> $AUDITDIR/audit_$TIME.log
    fi
done

echo "Modifying Network Parameters..."
cp /etc/sysctl.conf $AUDITDIR/sysctl.conf_$TIME.bak
cat > /etc/sysctl.conf << 'EOF'
fs.suid_dumpable = 0					# CIS 1.5.1
kernel.randomize_va_space = 2			# CIS 1.5.3
kernel.kptr_restrict = 2				# Custom
kernel.sysrq = 0						# Custom
kernel.dmesg_restrict = 1				# Custom
net.ipv4.ip_forward = 0					# CIS 3.1.1
net.ipv4.conf.all.send_redirects = 0			# CIS 3.1.2
net.ipv4.conf.default.send_redirects = 0		# CIS 3.1.2
net.ipv4.conf.all.accept_source_route = 0		# CIS 3.2.1
net.ipv4.conf.default.accept_source_route = 0		# CIS 3.2.1
net.ipv4.conf.all.accept_redirects = 0 			# CIS 3.2.2
net.ipv4.conf.default.accept_redirects = 0 		# CIS 3.2.2
net.ipv4.conf.all.secure_redirects = 0 			# CIS 23.2.3
net.ipv4.conf.default.secure_redirects = 0 		# CIS 3.2.3
net.ipv4.conf.all.log_martians = 1 			# CIS 3.2.4
net.ipv4.conf.default.log_martians = 1 			# CIS 3.2.4
net.ipv4.icmp_echo_ignore_broadcasts = 1		# CIS 3.2.5
net.ipv4.icmp_ignore_bogus_error_responses = 1		# CIS 3.2.6
net.ipv4.conf.all.rp_filter = 1				# CIS 3.2.7
net.ipv4.conf.default.rp_filter = 1			# CIS 3.2.7
net.ipv4.tcp_syncookies = 1				# CIS 3.2.8
net.ipv6.conf.all.accept_ra = 0				# CIS 3.3.1
net.ipv6.conf.default.accept_ra = 0 			# CIS 3.3.1
net.ipv6.conf.all.accept_redirects = 0			# CIS 3.3.2
net.ipv6.conf.default.accept_redirects = 0		# CIS 3.3.2
net.ipv6.conf.all.disable_ipv6 = 1			# CIS 3.3.3
EOF

echo "Disabling IPv6..."
cp /etc/sysconfig/network $AUDITDIR/network_$TIME.bak
echo "NETWORKING_IPV6=no" >> /etc/sysconfig/network
echo "IPV6INIT=no" >> /etc/sysconfig/network
echo "options ipv6 disable=1" >> /etc/modprobe.d/ipv6.conf

echo "Restricting hosts.deny..."
echo "ALL: ALL" >> /etc/hosts.deny			# CIS 3.4.3
chown root:root /etc/hosts.deny				# CIS 3.4.5
chmod 644 /etc/hosts.deny				# CIS 3.4.5			

echo "Configuring hosts.allow..." 
/bin/rm -f /etc/hosts.allow
echo "ALL: 127.0.0.1" > /etc/hosts.allow
echo "sshd: ALL" >> /etc/hosts.allow

echo "Configuring systemd run level 3... (Disable GUIs)"
systemctl set-default multi-user.target

echo "Preventing CTRL+ALT+DEL Console Reboot..."
systemctl mask ctrl-alt-del.target

# CIS 1.4.3
echo "Verify single user mode authentication..."
grep /sbin/sulogin /usr/lib/systemd/system/rescue.service  >> $AUDITDIR/single_user_mode_$TIME.log
grep /sbin/sulogin /usr/lib/systemd/system/emergency.service >> $AUDITDIR/single_user_mode_$TIME.log

# CIS 5.6
echo "Restricting Access to the su Command..."
cp /etc/pam.d/su $AUDITDIR/su_$TIME.bak
line_num="$(grep -n "^\#auth[[:space:]]*required[[:space:]]*pam_wheel.so[[:space:]]*use_uid" ${pam_su} | cut -d: -f1)"
sed -i "${line_num} a auth		required	pam_wheel.so use_uid" ${pam_su}
usermod -G wheel root

# Set bootloader password - User Interaction Required.
# CIS 1.5.3
echo "Please enter GRUB2 Bootloader Configuration Password..."
echo "** NOTE **: Do NOT Lose this or you cannot modify GRUB configuration."
grub2-setpassword
grub2-mkconfig -o /boot/grub2/grub.cfg
# Moved further down script, as file is not created until setpassword.
chmod og-rwx /boot/grub2/user.cfg # CIS 1.4.1
chown root:root /boot/grub2/user.cfg	# CIS 1.4.1

echo ""
echo "Successfully Completed"
echo "Please check $AUDITDIR"
