import io
import json
import os
import sys
import tempfile
import time
import unittest
import urllib.request
from contextlib import redirect_stderr, redirect_stdout
from datetime import datetime, timezone
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from centinela import cli, digest, heartbeat, migrate, modules, notify, safety  # noqa: E402
from centinela import setup  # noqa: E402
from centinela.checks import apt, certbot, cve, disk, docker, expect, firewall, load, memory, nginx, ports, restart, services, units  # noqa: E402
from centinela.core import CRIT, WARN, Blocked, Config, Ctx, Finding, HttpError, Skip, child_env  # noqa: E402


class FakeCtx(Ctx):
    """run() matches the longest command-prefix in `cmds`; http_get matches URL substrings in `urls`."""

    def __init__(self, conf="", cmds=None, urls=None):
        super().__init__(Config.from_string(conf))
        self.cmds, self.urls = cmds or {}, urls or {}

    def run(self, argv, timeout=60, unsafe=False):
        self.guard(argv, unsafe)
        line = " ".join(argv)
        for prefix in sorted(self.cmds, key=len, reverse=True):
            if line.startswith(prefix):
                rc, out, *err = self.cmds[prefix]
                return rc, out, err[0] if err else ""
        return 127, "", "not faked: " + line

    def http_get(self, url, timeout=20):
        for part, body in self.urls.items():
            if part in url:
                if isinstance(body, Exception):
                    raise body
                return body
        raise HttpError(url, 404)


ADVISORIES = """<ul class="mobilemenu"><li>english<br></li></ul><ul>
<li><p>Memory corruption in HTTP/2<br>Severity: <b>major</b><br><a href="x">Advisory</a><br>
<a href="y">CVE-2099-0001</a><br>Not vulnerable: 1.31.9+, 1.30.7+<br>Vulnerable: 1.9.5-1.31.8</p></li>
<li><p>Resolver issue<br>Severity: medium<br><a href="y">CVE-2099-0002</a><br>Not vulnerable: 1.31.9+, 1.30.7+<br>Vulnerable: 0.6.18-1.31.8</p></li>
<li><p>Old windows thing<br>Severity: minor<br>Not vulnerable: 1.2.5+<br>Vulnerable: 0.7.52-1.2.4 (Windows)</p></li>
<li><p>Single version<br>Severity: low<br>Not vulnerable: 1.30.7+<br>Vulnerable: 1.26.2</p></li></ul>"""
DOWNLOADS = ("<h4>Mainline version</h4><a href='/download/nginx-1.31.9.tar.gz'>x</a>"
             "<h4>Stable version</h4><a href='/download/nginx-1.30.7.tar.gz'>x</a>"
             "<h4>Legacy versions</h4><a href='/download/nginx-1.28.3.tar.gz'>x</a>")


class NginxTests(unittest.TestCase):
    def test_parse_and_affects(self):
        advs = nginx.parse_advisories(ADVISORIES)
        self.assertEqual(len(advs), 3)  # the Windows-only one is dropped
        self.assertEqual(advs[0]["cves"], ["CVE-2099-0001"])
        self.assertEqual(advs[0]["severity"], "major")
        self.assertTrue(nginx.affects("1.26.2", advs[0]))
        self.assertFalse(nginx.affects("1.30.7", advs[0]))  # fixed on its own branch
        self.assertFalse(nginx.affects("1.30.9", advs[0]))  # even though numerically < 1.31.8
        self.assertTrue(nginx.affects("1.30.6", advs[0]))
        self.assertFalse(nginx.affects("1.32.0", advs[0]))
        self.assertTrue(nginx.affects("1.26.2", advs[2]))
        self.assertFalse(nginx.affects("1.26.3", advs[2]))
        self.assertEqual(nginx.fixed_in("1.26.2", advs[0]), "1.30.7")

    def test_downloads(self):
        self.assertEqual(nginx.parse_downloads(DOWNLOADS), {"mainline": "1.31.9", "stable": "1.30.7"})

    def run_check(self, version, advisories=ADVISORIES):
        ctx = FakeCtx(cmds={"nginx -v": (0, "")}, urls={"security_advisories": advisories, "download": DOWNLOADS})
        ctx.run = lambda argv, timeout=60: (0, "", "nginx version: nginx/%s\n" % version)
        return nginx.run(ctx)

    def test_vulnerable_is_critical_and_suppresses_behind(self):
        fs = self.run_check("1.26.2")
        self.assertEqual({f.level for f in fs}, {CRIT, WARN})
        self.assertFalse(any(f.id.startswith("behind") for f in fs))
        self.assertIn("apt-get install --only-upgrade nginx", fs[0].cmd)

    def test_behind_only(self):
        fs = self.run_check("1.28.0", advisories="<ul></ul>")
        self.assertEqual([f.id for f in fs], ["behind-1.30.7"])

    def test_current_is_silent(self):
        self.assertEqual(self.run_check("1.30.7"), [])

    def test_offline_skips(self):
        ctx = FakeCtx(urls={"nginx.org": Skip("offline")})
        ctx.run = lambda argv, timeout=60: (0, "", "nginx version: nginx/1.28.0")
        with redirect_stderr(io.StringIO()), self.assertRaises(Skip):
            nginx.run(ctx)


class AptTests(unittest.TestCase):
    OUT = """Listing...
openssl/stable-security 3.0.15-1~deb12u1 amd64 [upgradable from: 3.0.14-1~deb12u2]
nginx/bookworm 1.30.7-1~bookworm amd64 [upgradable from: 1.28.0-1~bookworm]
htop/stable 3.2.2-2 amd64 [upgradable from: 3.2.1-1]
"""

    def test_findings(self):
        with tempfile.TemporaryDirectory() as d:
            flag = os.path.join(d, "reboot-required")
            open(flag, "w").close()
            open(flag + ".pkgs", "w").write("linux-image-6.1.0-28-amd64\n")
            ctx = FakeCtx('[apt]\nreboot_flag="%s"\nstamp_file="%s/none"\n' % (flag, d), {"apt list": (0, self.OUT)})
            fs = {f.id.split("-")[0]: f for f in apt.run(ctx)}
        self.assertEqual(fs["security"].level, CRIT)
        self.assertIn("only-upgrade openssl", fs["security"].cmd)
        self.assertIn("nginx", fs["watched"].text)
        self.assertEqual(fs["other"].text, "1 other upgradable package(s)")
        self.assertIn("linux-image-6.1.0-28-amd64", fs["reboot"].text)

    def test_quiet_when_current(self):
        ctx = FakeCtx('[apt]\nreboot_flag="/nonexistent"\nstamp_file="/nonexistent"\n', {"apt list": (0, "Listing...\n")})
        self.assertEqual(apt.run(ctx), [])


class RestartTests(unittest.TestCase):
    NEEDRESTART = ("NEEDRESTART-VER: 3.6\nNEEDRESTART-KCUR: 6.1.0-27-amd64\nNEEDRESTART-KEXP: 6.1.0-28-amd64\n"
                   "NEEDRESTART-KSTA: 3\nNEEDRESTART-SVC: nginx.service\nNEEDRESTART-SVC: user@1000.service\n")

    def test_parse_needrestart(self):
        svcs, kcur, kexp, ksta = restart.parse_needrestart(self.NEEDRESTART)
        self.assertEqual((svcs, kcur, kexp, ksta), (["nginx.service", "user@1000.service"], "6.1.0-27-amd64", "6.1.0-28-amd64", 3))
        self.assertIsNone(restart.parse_needrestart("garbage"))

    def test_needrestart_run_ignores_and_reports_kernel(self):
        ctx = FakeCtx('[apt]\nreboot_flag="/nonexistent"\n', {"needrestart -b": (0, self.NEEDRESTART)})
        with mock.patch("shutil.which", return_value="/usr/sbin/needrestart"):
            ids = {f.id: f for f in restart.run(ctx)}
        self.assertEqual(set(ids), {"nginx.service", "kernel"})
        self.assertEqual(ids["nginx.service"].cmd, "sudo systemctl restart nginx.service")

    def test_proc_fallback(self):
        with tempfile.TemporaryDirectory() as proc:
            for pid, exe, cg in (("10", "/usr/sbin/nginx (deleted)", "0::/system.slice/nginx.service\n"),
                                 ("11", "/usr/sbin/sshd", "0::/system.slice/ssh.service\n"),
                                 ("12", "/usr/bin/other (deleted)", "0::/x\n")):
                os.makedirs(os.path.join(proc, pid))
                os.symlink(exe, os.path.join(proc, pid, "exe"))
                with open(os.path.join(proc, pid, "cgroup"), "w") as fh:
                    fh.write(cg)
            found = restart.scan_proc(["nginx", "sshd"], proc)
        self.assertEqual(found, {"nginx.service": "nginx"})


class DockerTests(unittest.TestCase):
    PS = ("redis\tredis:7.4\trunning\tUp 2 days\t/srv/app\tredis\n"
          "app\tcentinela:latest\texited\tExited (1) 3 hours ago\t/srv/app\tapp\n"
          "web\tnginx:1.27\trunning\tUp 1 hour (unhealthy)\t\t\n")

    def test_parse_ref(self):
        self.assertEqual(docker.parse_ref("redis:7.4"), docker.Ref(None, "library/redis", "7.4"))
        self.assertEqual(docker.parse_ref("bitnami/redis:7.4@sha256:abc"), docker.Ref(None, "bitnami/redis", "7.4"))
        self.assertEqual(docker.parse_ref("ghcr.io/o/r:1.2").registry, "ghcr.io")
        self.assertEqual(docker.parse_ref("localhost:5000/x").tag, "latest")

    def test_newest_same_major(self):
        tags = ["7.4", "7.2", "7.4.1", "7.6", "8.0", "7.6-alpine", "latest", "7.8.1"]
        self.assertEqual(docker.newest_same_major("7.4", tags), "7.6")
        self.assertEqual(docker.newest_same_major("7.4-alpine", tags), "7.6-alpine")
        self.assertEqual(docker.newest_same_major("7.4.1", tags), "7.8.1")
        self.assertIsNone(docker.newest_same_major("7.6", tags))
        self.assertIsNone(docker.newest_same_major("7", tags))
        self.assertIsNone(docker.newest_same_major("latest", tags))
        self.assertEqual(docker.newest_same_major("3.12-slim", ["3.13-slim", "3.12-slim"], "minor"), None)

    def test_containers(self):
        fs = docker.check_containers(FakeCtx(), docker.parse_ps(self.PS))
        self.assertEqual({f.id for f in fs}, {"down-app", "unhealthy-web"})
        self.assertTrue(all(f.level == CRIT for f in fs))
        self.assertEqual(fs[0].cmd, "docker logs --tail 50 app")

    def test_run_images_and_down(self):
        tags = json.dumps({"results": [{"name": n} for n in ("7.4", "7.6", "8.0")], "next": None})
        ctx = FakeCtx('[docker]\nignore_images = ["centinela:*", "nginx:*"]\n', {
            "docker info": (0, "27.0"), "docker ps": (0, self.PS)}, {"library/redis/tags?": tags})
        ids = {f.id: f for f in docker.run(ctx)}
        self.assertIn("newer-redis:7.4-7.6", ids)
        self.assertEqual(ids["newer-redis:7.4-7.6"].cmd, "docker pull redis:7.6")
        self.assertIn("down-app", ids)

    def test_rebuilt_same_tag_uses_compose_command(self):
        ctx = FakeCtx("", {"docker image inspect": (0, '["redis@sha256:old"]')},
                      {"tags?page_size": '{"results": []}', "/tags/7": json.dumps({"digest": "sha256:newnewnewnew"})})
        c = docker.parse_ps(self.PS)[0]
        fs = docker._check_image(ctx, "redis:7", docker.parse_ref("redis:7"), c)
        self.assertEqual(len(fs), 1)
        self.assertEqual(fs[0].cmd, "cd /srv/app && docker compose pull redis && docker compose up -d redis")

    def test_track_minor_from_toml_table(self):
        ctx = FakeCtx('[docker.track]\npython = "minor"\n', {"docker image inspect": (1, "")},
                      {"tags?page_size": json.dumps({"results": [{"name": "3.13-slim"}]})})
        self.assertEqual(docker._check_image(ctx, "python:3.12-slim", docker.parse_ref("python:3.12-slim"), None), [])
        ctx.cfg = Config.from_string("")
        fs = docker._check_image(ctx, "python:3.12-slim", docker.parse_ref("python:3.12-slim"), None)
        self.assertEqual(fs[0].id, "newer-python:3.12-slim-3.13-slim")

    def test_find_base_by_layers_and_label(self):
        recs = [
            {"RepoTags": ["python:3.12-slim", "python:3.12.4-slim"], "RootFS": {"Layers": ["a", "b"]}},
            {"RepoTags": ["python:3.12.4"], "RootFS": {"Layers": ["a", "b"]}},  # same layers, same length
            {"RepoTags": ["myapp:old"], "RootFS": {"Layers": ["a", "b", "c"]}},   # older build of the app itself
            {"RepoTags": ["myapp:new"], "RootFS": {"Layers": ["a", "b", "c", "d"]}},
            {"RepoTags": ["nginx:1.27"], "RootFS": {"Layers": ["x", "y"]}},
            {"RepoTags": ["ghcr.io/o/base:1"], "RootFS": {"Layers": ["a"]}},
            {"RepoTags": ["labelled:1"], "Config": {"Labels": {"org.opencontainers.image.base.name": "node:20-alpine"}},
             "RootFS": {"Layers": ["q", "r"]}},
        ]
        self.assertEqual(docker.find_base("myapp:new", recs), "python:3.12-slim")  # least precise tag wins
        self.assertEqual(docker.find_base("labelled:1", recs), "node:20-alpine")
        self.assertIsNone(docker.find_base("nginx:1.27", recs))
        self.assertIsNone(docker.find_base("unknown:1", recs))

    def test_base_image_finding_has_rebuild_command(self):
        recs = [{"RepoTags": ["python:3.12-slim"], "RootFS": {"Layers": ["a"]}, "RepoDigests": []},
                {"RepoTags": ["centinela:latest"], "RootFS": {"Layers": ["a", "b"]}}]
        ps = "app\tcentinela:latest\trunning\tUp 1 hour\t/srv/app\tapp\n"
        tags = json.dumps({"results": [{"name": n} for n in ("3.12-slim", "3.13-slim")], "next": None})
        ctx = FakeCtx("", {"docker image ls": (0, "id1\nid2\n"), "docker image inspect": (0, json.dumps(recs)),
                       "docker image inspect --format": (0, "[]")},
                      {"tags?page_size": tags})
        fs = docker.check_images(ctx, docker.parse_ps(ps))
        self.assertEqual(len(fs), 1)
        self.assertIn("base image python:3.12-slim (of centinela:latest) is behind python:3.13-slim", fs[0].text)
        off = FakeCtx('[docker]\ndetect_base = false\n', {"docker image ls": (0, "id1\n")}, {"tags?page_size": tags})
        self.assertEqual(docker.check_images(off, docker.parse_ps(ps)), [])
        c = docker.parse_ps(ps)[0]
        self.assertEqual(docker._update_cmd("python:3.12-slim", c, "centinela:latest"),
                         "cd /srv/app && docker compose build --pull app && docker compose up -d app")

    def test_watch_images_globs_keep_newest_local_tag(self):
        ls = "\n".join(["python:3.12-slim", "python:3.12.1-slim", "python:3.12.4-slim", "python:3.12-alpine",
                        "python:latest", "python:3.9", "node:22-slim", "myapp:20261118-ab", "<none>:<none>"])
        ctx = FakeCtx(cmds={"docker image ls": (0, ls)})
        got = docker.watched_images(ctx, ["python:3.12*", "python:latest", "myapp:*"])
        self.assertEqual(got, ["myapp:20261118-ab", "python:3.12-alpine", "python:3.12.4-slim", "python:latest"])
        self.assertEqual(docker.watched_images(ctx, []), [])
        self.assertEqual(docker.watched_images(FakeCtx(cmds={"docker image ls": (1, "")}), ["*"]), [])

    def test_watch_images_are_checked_and_ignore_globs_apply(self):
        tags = json.dumps({"results": [{"name": n} for n in ("3.12.4-slim", "3.12.9-slim")], "next": None})
        conf = '[docker]\nwatch_images = ["python:3.12*", "myapp:*"]\nignore_images = ["myapp:*"]\ndetect_base = false\n'
        ctx = FakeCtx(conf, {"docker image ls": (0, "python:3.12.4-slim\npython:3.12.1-slim\nmyapp:20261118-ab\n"),
                             "docker image inspect": (1, "")}, {"tags?page_size": tags})
        fs = docker.check_images(ctx, [])
        self.assertEqual([f.id for f in fs], ["newer-python:3.12.4-slim-3.12.9-slim"])

    def test_trusted_images(self):
        ps = ("redis\tredis:7.4\trunning\tUp 2 days\t\t\n"
              "web\tdocker.io/library/nginx:1.27\trunning\tUp 1 hour\t\t\n"
              "app\tghcr.io/me/app:20261118-ab\trunning\tUp 5 minutes\t\t\n"
              "miner1\tevil/xmrig:latest\trunning\tUp 3 minutes\t\t\n"
              "miner2\tevil/xmrig:latest\trestarting\tRestarting (1) 5 seconds ago\t\t\n"
              "pinned\tredis@sha256:abc\trunning\tUp 1 hour\t\t\n"
              "moved\t3a1b2c4d5e6f\trunning\tUp 1 hour\t\t\n"
              "old\tevil/other:1\texited\tExited (0) 3 days ago\t\t\n")
        conf = '[docker]\ntrusted_images = ["redis", "redis:7.*", "nginx:*", "ghcr.io/me/app:*"]\nignore_containers = ["miner1"]\n'
        fs = docker.check_trusted(FakeCtx(conf), docker.parse_ps(ps))
        self.assertEqual([f.id for f in fs], ["untrusted-3a1b2c4d5e6f", "untrusted-evil/xmrig:latest"])
        self.assertTrue(all(f.level == CRIT for f in fs))
        xmrig = fs[1]
        self.assertIn("miner1, miner2", xmrig.text)
        self.assertEqual(xmrig.cmd, "docker inspect miner1")  # ignore_containers does not exempt it
        self.assertIn("image id", fs[0].text)
        self.assertEqual(docker.check_trusted(FakeCtx(), docker.parse_ps(ps)), [])  # no list = check off
        self.assertEqual(docker.check_trusted(FakeCtx('[docker]\ntrusted_images = ["*"]\n'), docker.parse_ps(ps)), [])

    DENIED = "permission denied while trying to connect to the Docker daemon socket at unix:///var/run/docker.sock"

    def write_container(self, root, cid, name="web", **state):
        folder = os.path.join(root, "containers", cid)
        os.makedirs(folder)
        conf = {"ID": cid, "Name": "/" + name, "State": dict({"Running": True, "Pid": 4242, "StartedAt": "2026-11-06T06:39:53Z",
                "FinishedAt": "0001-01-01T00:00:00Z", "ExitCode": 0}, **state),
                "Config": {"Image": "redis:7.4", "Labels": {"com.docker.compose.service": "cache",
                                                           "com.docker.compose.project.working_dir": "/srv/app"}}}
        with open(os.path.join(folder, "config.v2.json"), "w") as fh:
            json.dump(conf, fh)

    def test_container_files_give_the_same_rows_as_docker_ps(self):
        alive = lambda pid, cid: pid == 4242
        base = {"ID": "a" * 64, "Name": "/web", "Config": {"Image": "redis:7.4", "Labels": {
            "com.docker.compose.service": "cache", "com.docker.compose.project.working_dir": "/srv/app"}}}
        up = docker.container_from_config(dict(base, State={"Running": True, "Pid": 4242, "StartedAt": "2026-11-06T06:39:53Z"}), alive)
        self.assertEqual((up.name, up.image, up.state, up.service, up.workdir), ("web", "redis:7.4", "running", "cache", "/srv/app"))
        sick = docker.container_from_config(dict(base, State={"Running": True, "Pid": 4242, "StartedAt": "x", "Health": {"Status": "unhealthy"}}), alive)
        self.assertIn("(unhealthy)", sick.status)
        stale = docker.container_from_config(dict(base, State={"Running": True, "Pid": 99, "StartedAt": "x", "FinishedAt": "y", "ExitCode": 137}), alive)
        self.assertEqual((stale.state, stale.status), ("exited", "Exited (137) at y"))  # Running in the file, process gone
        self.assertEqual(docker.container_from_config(dict(base, State={"Restarting": True, "ExitCode": 1}), alive).state, "restarting")
        self.assertEqual(docker.container_from_config(dict(base, State={"StartedAt": "0001-01-01T00:00:00Z"}), alive).state, "created")

    def test_without_the_socket_it_reads_the_container_files(self):
        with tempfile.TemporaryDirectory() as root:
            self.write_container(root, "a" * 64, Running=False, Pid=0, FinishedAt="2026-11-20T01:00:00Z", ExitCode=1)
            self.write_container(root, "b" * 64, "db", Running=False, Pid=0, FinishedAt="2026-11-20T01:00:00Z", ExitCode=0)
            os.makedirs(os.path.join(root, "containers", "broken"))  # no config file
            with open(os.path.join(root, "containers", "broken", "config.v2.json"), "w") as fh:
                fh.write("{not json")
            ctx = FakeCtx('[docker]\ndata_root = "%s"\n' % root, {"docker info": (1, "", self.DENIED)})
            fs = docker.run(ctx)
            self.assertEqual(sorted(f.id for f in fs), ["down-db", "down-web"])
            self.assertEqual(len(docker.read_containers(root)), 2)  # the broken one is skipped, not fatal

    def test_trusted_images_work_from_the_container_files(self):
        with tempfile.TemporaryDirectory() as root:
            self.write_container(root, "a" * 64)
            ctx = FakeCtx('[docker]\ndata_root = "%s"\ntrusted_images = ["nginx:*"]\n' % root,
                          {"docker info": (1, "", self.DENIED)})
            with mock.patch.object(docker, "pid_alive", lambda pid, cid: True):
                self.assertIn("untrusted-redis:7.4", [f.id for f in docker.run(ctx)])

    def test_permission_denied_is_a_skip_not_a_down_daemon(self):
        denied = self.DENIED
        nowhere = '[docker]\ndata_root = "/nonexistent/docker"\n'
        with self.assertRaises(Skip):  # no socket and no readable files
            docker.run(FakeCtx(nowhere, {"docker info": (1, "", denied)}))
        down = "Cannot connect to the Docker daemon at unix:///var/run/docker.sock. Is the docker daemon running?"
        self.assertEqual(docker.run(FakeCtx(cmds={"docker info": (1, "", down)}))[0].id, "daemon")

    def test_daemon_down(self):
        fs = docker.run(FakeCtx(cmds={"docker info": (1, "")}))
        self.assertEqual((fs[0].id, fs[0].level), ("daemon", CRIT))

    def test_dockerfile_images(self):
        with tempfile.NamedTemporaryFile("w", suffix=".Dockerfile", delete=False) as fh:
            fh.write("FROM python:3.12-slim AS build\nFROM --platform=linux/amd64 node:20\nFROM scratch\nFROM $BASE\n")
        self.assertEqual(docker.dockerfile_images(fh.name), ["python:3.12-slim", "node:20"])
        os.unlink(fh.name)


class CertbotTests(unittest.TestCase):
    def test_expiry(self):
        with tempfile.TemporaryDirectory() as live:
            for name in ("soon.example.com", "later.example.com", "gone.example.com"):
                os.makedirs(os.path.join(live, name))
            ends = {"soon.example.com": "Dec  1 12:00:00 2026 GMT", "later.example.com": "Mar  1 12:00:00 2027 GMT",
                    "gone.example.com": "Nov  1 12:00:00 2026 GMT"}
            ctx = FakeCtx('[certbot]\nlive_dir="%s"\n' % live)
            ctx.run = lambda argv, timeout=60: (0, "notAfter=%s\n" % ends[argv[-1].split("/")[-2]], "")
            with mock.patch("shutil.which", return_value="/usr/bin/openssl"):
                fs = {f.id: f for f in certbot.run(ctx, now=datetime(2026, 11, 18, tzinfo=timezone.utc))}
        self.assertEqual(set(fs), {"soon.example.com", "gone.example.com"})
        self.assertEqual(fs["soon.example.com"].level, WARN)  # 13 days
        self.assertEqual(fs["gone.example.com"].level, CRIT)
        self.assertIn("EXPIRED", fs["gone.example.com"].text)
        self.assertEqual(fs["soon.example.com"].cmd, "sudo certbot renew --cert-name soon.example.com")


class SystemTests(unittest.TestCase):
    DF = ("Filesystem 1024-blocks Used Available Capacity Mounted on\n"
          "/dev/sda1 100 85 15 85% /\n/dev/sda1 100 85 15 85% /var/lib/docker/x\n"
          "/dev/sdb1 100 95 5 95% /data disk\n/dev/sdc1 100 10 90 10% /boot\n")

    def test_disk(self):
        ctx = FakeCtx(cmds={"df -Pi": (0, "Filesystem Inodes IUsed IFree IUse% Mounted on\n/dev/sda1 1 1 0 - /\n"),
                            "df -P": (0, self.DF)})
        fs = {f.id: f for f in disk.run(ctx)}
        self.assertEqual(set(fs), {"disk-/", "disk-/data disk"})
        self.assertEqual(fs["disk-/data disk"].level, CRIT)
        self.assertIn("'/data disk'", fs["disk-/data disk"].cmd)

    GB = 1024 * 1024  # df 1K-blocks per GB

    def df_for(self, rows):
        return "Filesystem 1024-blocks Used Available Capacity Mounted on\n" + "".join(
            "%s %d %d %d %d%% %s\n" % (dev, total * self.GB, used * self.GB, (total - used) * self.GB, 100 * used // total, mount)
            for dev, total, used, mount in rows)

    def disk_ids(self, rows, conf=""):
        ctx = FakeCtx(conf, {"df -Pi": (0, ""), "df -P": (0, self.df_for(rows))})
        with mock.patch("sys.platform", "linux"):
            return {f.id: f.level for f in disk.run(ctx)}

    def test_the_same_percentage_means_different_things_on_different_sizes(self):
        self.assertEqual(self.disk_ids([("a", 20, 18, "/small")]), {"disk-/small": CRIT})     # 90%, 2 GB left
        self.assertEqual(self.disk_ids([("a", 4096, 3700, "/big")]), {})                      # 90%, 410 GB left
        self.assertEqual(self.disk_ids([("a", 1000, 960, "/mid")]), {})                       # 96%, 40 GB left
        self.assertEqual(self.disk_ids([("a", 1000, 985, "/mid")]), {"disk-/mid": WARN})      # 98.5%, 15 GB left
        self.assertEqual(self.disk_ids([("a", 1000, 995, "/mid")]), {"disk-/mid": CRIT})      # 99.5%, 5 GB left
        self.assertEqual(self.disk_ids([("a", 100, 70, "/ok")]), {})                          # below 80%

    def test_free_space_floors_are_configurable_and_zero_means_percent_only(self):
        big = [("a", 4096, 3700, "/big")]
        self.assertEqual(self.disk_ids(big, "[disk]\nwarn_free_gb = 0\ncrit_free_gb = 0\n"), {"disk-/big": CRIT})
        self.assertEqual(self.disk_ids(big, "[disk]\ncrit_free_gb = 500\n"), {"disk-/big": CRIT})
        self.assertEqual(self.disk_ids([("a", 100, 85, "/x")], "[disk]\nwarn_percent = 90\n"), {})

    def test_the_message_says_how_much_is_left(self):
        ctx = FakeCtx(cmds={"df -Pi": (0, ""), "df -P": (0, self.df_for([("a", 20, 18, "/small")]))})
        with mock.patch("sys.platform", "linux"):
            (f,) = disk.run(ctx)
        self.assertEqual(f.text, "disk /small is 90% full (2.0 GB free of 20.0 GB)")

    MACDF = ("Filesystem     1024-blocks      Used Available Capacity  Mounted on\n"
             "/dev/disk1s4s1   976797816  16211120  56899636    23%    /\n"
             "/dev/disk1s1     976797816 876813088  56899636    94%    /System/Volumes/Data\n"
             "/dev/disk1s6     976797816  19923976  56899636    26%    /System/Volumes/VM\n"
             "/dev/disk4s1      17004544  16482556    477828    98%    /Library/Developer/CoreSimulator/Volumes/iOS_21C62\n")

    def test_macos_checks_space_only_and_skips_system_and_simulator_volumes(self):
        calls = []
        ctx = FakeCtx(cmds={"df -Pk -l": (0, self.MACDF)})
        run = ctx.run
        ctx.run = lambda argv, timeout=60, unsafe=False: (calls.append(argv), run(argv, timeout, unsafe))[1]
        with mock.patch("sys.platform", "darwin"):
            self.assertEqual(disk.run(ctx), [])                      # 94% but 54 GB free: fine
            fs = disk.run(FakeCtx("[disk]\nwarn_free_gb = 100\n", {"df -Pk -l": (0, self.MACDF)}))
            self.assertEqual([f.id for f in fs], ["disk-/System/Volumes/Data"])   # the simulator image stays ignored
            self.assertTrue(disk.applicable(Config()))
        self.assertEqual(calls, [["df", "-Pk", "-l"]])               # no inode pass, no GNU -x flags

    def test_inodes_are_still_judged_by_percentage(self):
        inodes = "Filesystem Inodes IUsed IFree IUse% Mounted on\n/dev/sda1 100 95 5 95% /\n"
        ctx = FakeCtx(cmds={"df -Pi": (0, inodes), "df -P": (0, self.df_for([("a", 100, 10, "/")]))})
        with mock.patch("sys.platform", "linux"):
            self.assertEqual([(f.id, f.level) for f in disk.run(ctx)], [("inodes-/", CRIT)])

    def test_failed_units(self):
        ctx = FakeCtx('[units]\nignore = ["ignored.*"]\n', {"systemctl --failed": (0, "foo.service loaded failed failed Foo\n● ignored.timer loaded failed failed X\n")})
        self.assertEqual([f.id for f in units.run(ctx)], ["foo.service"])

    def test_services(self):
        shows = {"systemctl show -p LoadState -p ActiveState fail2ban.service": (0, "LoadState=loaded\nActiveState=inactive\n"),
                 "systemctl show -p LoadState -p ActiveState nginx.service": (0, "LoadState=not-found\nActiveState=inactive\n"),
                 "systemctl show -p LoadState -p ActiveState docker.service": (0, "LoadState=loaded\nActiveState=failed\n"),
                 "systemctl show -p LoadState -p ActiveState ssh.service": (0, "LoadState=loaded\nActiveState=active\n")}
        conf = '[services]\nrequired = ["fail2ban"]\nwatch = ["nginx", "docker", "ssh"]\n'
        fs = {f.id: f for f in services.run(FakeCtx(conf, shows))}
        self.assertEqual(set(fs), {"fail2ban.service", "docker.service"})  # nginx absent = skipped, not a finding
        self.assertEqual(fs["fail2ban.service"].cmd, "sudo systemctl start fail2ban.service")

        fs = services.run(FakeCtx('[services]\nrequired = ["ghost"]\nwatch = []\n', {"systemctl show": (0, "LoadState=not-found\n")}))
        self.assertEqual(fs[0].id, "ghost.service-missing")

    def test_services_are_off_until_configured(self):
        shows = {"systemctl show": (0, "LoadState=not-found\nActiveState=inactive\n")}
        with mock.patch("shutil.which", return_value="/bin/systemctl"):
            self.assertFalse(services.applicable(Config()))
            self.assertFalse(services.applicable(Config.from_string("[services]\nknown = [\"cron.service\"]\n")))
            for conf in ('required = ["fail2ban"]', 'watch = ["nginx"]', "freeze = true"):
                self.assertTrue(services.applicable(Config.from_string("[services]\n%s\n" % conf)), conf)
        self.assertEqual(services.run(FakeCtx("", shows)), [])  # nothing named, nothing required

    def test_ufw(self):
        self.assertEqual(firewall.run(FakeCtx(cmds={"ufw status": (0, "Status: active\n\nTo Action\n")})), [])
        fs = firewall.run(FakeCtx(cmds={"ufw status": (0, "Status: inactive\n")}))
        self.assertEqual(fs[0].level, CRIT)
        with mock.patch.object(firewall, "UFW_CONF", "/nonexistent/ufw.conf"):
            with self.assertRaises(Skip):
                firewall.run(FakeCtx(cmds={"ufw status": (1, "ERROR: You need to be root")}))

    def test_ufw_without_root_reads_its_config(self):
        denied = FakeCtx(cmds={"ufw status": (1, "ERROR: You need to be root to run this script")})
        for text, expected in (("# c\nENABLED=yes\nLOGLEVEL=low\n", 0), ("ENABLED=no\n", 1)):
            with tempfile.NamedTemporaryFile("w", suffix=".conf", delete=False) as fh:
                fh.write(text)
            with mock.patch.object(firewall, "UFW_CONF", fh.name):
                fs = firewall.run(denied)
            os.unlink(fh.name)
            self.assertEqual(len(fs), expected)
            if fs:
                self.assertEqual((fs[0].id, fs[0].level), ("ufw-inactive", CRIT))

    def test_cve(self):
        out = ("CVE-2099-1 libssl3 (remotely exploitable, high urgency)\nCVE-2099-2 libssl3 (high urgency)\n"
               "CVE-2099-3 curl (low urgency)\nCVE-2099-4 bash (high urgency)\nnoise line\n")
        ctx = FakeCtx('[cve]\nsuite = "bookworm"\n', {"debsecan --suite bookworm --format summary --only-fixed": (0, out)})
        fs = {f.id: f for f in cve.run(ctx)}
        self.assertEqual(set(fs), {"libssl3", "bash"})
        self.assertEqual(fs["libssl3"].level, CRIT)
        self.assertEqual(fs["bash"].level, WARN)
        self.assertIn("CVE-2099-1, CVE-2099-2", fs["libssl3"].text)


class DigestTests(unittest.TestCase):
    def f(self, i, level=WARN, module="m"):
        return Finding(module, i, level, "text " + i, "cmd " + i)

    def test_dedupe_window_and_tolerance(self):
        a, b = self.f("a"), self.f("b")
        now = 1_000_000_000
        sent = {a.key: now - 6 * 86400, b.key: now - (7 * 86400 - 3600)}  # b sent 6d23h ago
        to_send, supp = digest.select([a, b], sent, now, 7)
        self.assertEqual(([f.id for f in to_send], [f.id for f in supp]), (["b"], ["a"]))  # 6d23h counts as a week
        self.assertEqual(digest.select([a], {}, now, 7)[0], [a])

    def test_prune_scopes(self):
        w, c, other = self.f("w", WARN), self.f("c", CRIT), self.f("x", WARN, "other")
        sent = {w.key: 1e9, c.key: 1e9, other.key: 1e9}
        kept = digest.prune(sent, set(), {"m"}, {CRIT}, 1e9 + 10)  # critical-only run
        self.assertEqual(set(kept), {w.key, other.key})  # WARN entry and unevaluated module kept
        kept = digest.prune(sent, {w.key}, {"m"}, {CRIT, WARN}, 1e9 + 10)
        self.assertEqual(set(kept), {w.key, other.key})

    def test_cap_and_format(self):
        fs = [self.f("x-%d" % i) for i in range(12)]
        capped = digest.cap_module(fs, 8)
        self.assertEqual(len(capped), 8)
        self.assertIn("+5 more", capped[-1].text)
        # a noisy kind must not bury another kind of finding from the same module
        noisy = [Finding("docker", "down-c%d" % i, CRIT, "down", "") for i in range(150)]
        important = [Finding("docker", "untrusted-evil:%d" % i, CRIT, "untrusted", "") for i in range(3)]
        out = digest.cap_module(noisy + important, 8)
        self.assertEqual([f.id for f in out if f.id.startswith("untrusted")], ["untrusted-evil:0", "untrusted-evil:1", "untrusted-evil:2"])
        self.assertEqual(sum(1 for f in out if f.id.startswith("down") or f.id.startswith("more-down")), 8)
        msg = digest.format_messages("vps", [self.f("a", CRIT), self.f("b")])[0]
        self.assertEqual(msg.splitlines()[0], "vps: 2 need action (1 critical)")
        self.assertEqual(msg.splitlines()[1], "[CRIT] text a | run: cmd a")

    def test_chunking(self):
        fs = [Finding("m", str(i), WARN, "x" * 300, "c") for i in range(30)]
        msgs = digest.format_messages("h", fs, limit=1000)
        self.assertTrue(len(msgs) > 1 and all(len(m) <= 1000 for m in msgs))
        self.assertEqual(sum(m.count("[WARN]") for m in msgs), 30)


class CliTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.state = os.path.join(self.tmp.name, "s", "state.json")
        self.conf = os.path.join(self.tmp.name, "h.toml")
        open(self.conf, "w").write('[general]\nenable = ["demo"]\nextra_dir = "%s"\n' % self.tmp.name)
        open(os.path.join(self.tmp.name, "demo.py"), "w").write(
            "from centinela.core import *\nNAME='demo'\nDESC='d'\nRESULT=[]\n"
            "def run(ctx):\n    return [Finding('demo','w',WARN,'warn me','fix w'), Finding('demo','c',CRIT,'crit me','fix c')]\n")
        os.chmod(self.tmp.name, 0o755)
        self.base = ["--config", self.conf, "--state", self.state, "--env-file", os.path.join(self.tmp.name, "none.env")]

    def tearDown(self):
        self.tmp.cleanup()

    def invoke(self, *args, env=None):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err), mock.patch.dict(os.environ, env or {}, clear=False):
            code = cli.main(self.base + list(args))
        return code, out.getvalue(), err.getvalue()

    def test_dry_run_prints_and_writes_no_state(self):
        code, out, _ = self.invoke("--dry-run")
        self.assertEqual(code, 0)
        self.assertIn("[CRIT] crit me | run: fix c", out)
        self.assertFalse(os.path.exists(self.state))

    def test_daily_is_critical_only(self):
        _, out, _ = self.invoke("--dry-run", "--mode", "daily")
        self.assertIn("crit me", out)
        self.assertNotIn("warn me", out)

    def test_send_dedupe_and_silence(self):
        env = {"TELEGRAM_BOT_TOKEN": "TOKEN123", "TELEGRAM_CHAT_ID": "42"}
        with mock.patch("centinela.notify.send") as send:
            self.assertEqual(self.invoke(env=env)[0], 0)
            self.assertEqual(send.call_count, 1)
            self.assertIn("warn me", send.call_args[0][2])
            self.assertEqual(self.invoke(env=env)[0], 0)  # second run: everything deduped
            self.assertEqual(send.call_count, 1)
        self.assertEqual(oct(os.stat(self.state).st_mode & 0o777), "0o600")
        # --no-dedupe still dry-run prints everything again
        self.assertIn("warn me", self.invoke("--dry-run", "--no-dedupe")[1])

    def test_failed_delivery_is_not_recorded(self):
        env = {"TELEGRAM_BOT_TOKEN": "t", "TELEGRAM_CHAT_ID": "1"}
        with mock.patch("centinela.notify.send", side_effect=notify.NotifyError("boom")):
            code, _, err = self.invoke(env=env)
        self.assertEqual(code, 1)
        self.assertIn("delivery failed: telegram: boom", err)
        self.assertFalse(os.path.exists(self.state))

    ENV = {"TELEGRAM_BOT_TOKEN": "t", "TELEGRAM_CHAT_ID": "1"}

    def test_failure_notice_is_sent_once_and_names_the_command(self):
        with mock.patch("centinela.notify.send") as send:
            self.assertEqual(self.invoke("--failed", "daily", env=self.ENV)[0], 0)
            self.assertEqual(self.invoke("--failed", "daily", env=self.ENV)[0], 0)  # same failure again: deduped
            self.assertEqual(send.call_count, 1)
            text = send.call_args[0][2]
            self.assertIn("scheduled daily run of centinela failed", text)
            self.assertIn("journalctl -u centinela@daily", text)
            self.assertEqual(self.invoke("--failed", "weekly", env=self.ENV)[0], 0)  # another unit: its own notice
            self.assertEqual(send.call_count, 2)

    def test_a_good_run_lets_the_next_failure_through(self):
        with mock.patch("centinela.notify.send") as send:
            self.invoke("--failed", "daily", env=self.ENV)
            self.invoke(env=self.ENV)  # a normal run that completes clears the failure from the dedupe state
            self.invoke("--failed", "daily", env=self.ENV)
            self.assertEqual([c for c in (a[0][2] for a in send.call_args_list)].count(send.call_args_list[0][0][2]), 2)

    def test_failure_notice_survives_a_broken_state_file(self):
        os.makedirs(os.path.dirname(self.state))
        with open(self.state, "w") as fh:
            fh.write("{not json")
        with mock.patch("centinela.notify.send") as send:
            self.assertEqual(self.invoke("--failed", "weekly", env=self.ENV)[0], 0)
        self.assertEqual(send.call_count, 1)

    def test_failure_notice_reports_a_dead_channel_and_cleans_the_mode(self):
        with mock.patch("centinela.notify.send", side_effect=notify.NotifyError("boom")):
            code, _, err = self.invoke("--failed", "daily", env=self.ENV)
        self.assertEqual(code, 1)  # nothing else to do: the failed unit and the journal are the record
        self.assertIn("delivery failed", err)
        self.assertEqual(cli.failure_findings("daily; rm -rf /")[0].id, "failed-unknown")
        self.assertEqual(self.invoke("--failed", "x", "--test")[0], 2)

    def test_service_units_point_at_the_failure_unit(self):
        data = os.path.join(os.path.dirname(cli.__file__), "data")
        service = open(os.path.join(data, "centinela@.service")).read()
        self.assertIn("OnFailure=centinela-failure@%i.service", service)
        failure = open(os.path.join(data, "centinela-failure@.service")).read()
        self.assertIn("--failed %i", failure)
        self.assertNotIn("\nOnFailure=", failure)  # a failing notice must not trigger itself

    def test_missing_credentials(self):
        with mock.patch.dict(os.environ, clear=True):
            code, _, err = self.invoke()
        self.assertEqual(code, 1)
        self.assertIn("TELEGRAM_BOT_TOKEN", err)

    def test_list_modules_and_disable(self):
        open(self.conf, "a").write('disable = ["demo"]\n')
        self.assertIn("disabled", self.invoke("--list-modules")[1])
        code, out, _ = self.invoke("--dry-run")
        self.assertEqual(out, "")

    def test_unsafe_extra_dir_refused(self):
        os.chmod(os.path.join(self.tmp.name, "demo.py"), 0o666)
        _, _, err = self.invoke("--list-modules")
        self.assertIn("refusing extra checks", err)

    def test_says_so_when_no_check_ran(self):
        with open(self.conf, "w") as fh:
            fh.write('[general]\nenable = []\nextra_dir = "%s"\n' % self.tmp.name)
        code, out, err = self.invoke("--dry-run")
        self.assertEqual((code, out), (0, ""))
        self.assertIn("no check ran on this machine", err)

    def test_test_flag_dry(self):
        self.assertIn("demo critical", self.invoke("--test", "--dry-run")[1])

    def test_notify_env_file_and_redaction(self):
        path = os.path.join(self.tmp.name, "n.env")
        open(path, "w").write("# c\nexport TELEGRAM_BOT_TOKEN='abc'\nTELEGRAM_CHAT_ID=99\n")
        with mock.patch.dict(os.environ, clear=True):
            notify.load_env_file(path)
            self.assertEqual(notify.credentials(), ("abc", "99"))
        import urllib.error
        with mock.patch("urllib.request.urlopen", side_effect=urllib.error.HTTPError("https://api.telegram.org/botSECRET/x", 401, "no", {}, None)):
            with self.assertRaises(notify.NotifyError) as cm:
                notify.send("SECRET", "1", "hi")
        self.assertNotIn("SECRET", str(cm.exception))
        body = io.BytesIO(b'{"ok":false,"error_code":403,"description":"Forbidden: bot can\'t send messages to bots"}')
        err = urllib.error.HTTPError("https://api.telegram.org/botSECRET/x", 403, "Forbidden", {}, body)
        with mock.patch("urllib.request.urlopen", side_effect=err):
            with self.assertRaises(notify.NotifyError) as cm:
                notify.send("SECRET", "1", "hi")
        self.assertEqual(str(cm.exception), "telegram HTTP 403: Forbidden: bot can't send messages to bots")


class IdentityTests(unittest.TestCase):
    def test_describe(self):
        from centinela import identity
        cfg = Config.from_string('[general]\nhost_name = "my-vps"\n[notify]\nshow = ["host", "ip", "public_ip"]\n')
        with mock.patch.object(identity, "local_ip", return_value="10.0.0.5"):
            self.assertEqual(identity.describe(cfg, lambda url, t: "203.0.113.9\n"), "my-vps (10.0.0.5, 203.0.113.9)")
            self.assertEqual(identity.describe(cfg, lambda url, t: "<html>nope</html>"), "my-vps (10.0.0.5)")
            def offline(url, t):
                raise Skip("offline")
            with redirect_stderr(io.StringIO()):
                self.assertEqual(identity.describe(cfg, offline), "my-vps (10.0.0.5)")
        self.assertEqual(identity.describe(Config.from_string('[general]\nhost_name = "x"\n')), "x")

    def test_header_in_message(self):
        with tempfile.TemporaryDirectory() as d:
            conf = os.path.join(d, "h.toml")
            with open(conf, "w") as fh:
                fh.write('[general]\nhost_name = "pi"\nenable = []\n[notify]\nshow = ["host", "os"]\n')
            out = io.StringIO()
            with redirect_stdout(out), mock.patch("centinela.identity.os_name", return_value="Debian GNU/Linux 12"):
                cli.main(["--config", conf, "--test", "--dry-run"])
        self.assertTrue(out.getvalue().startswith("pi (Debian GNU/Linux 12): 2 need action"))


class SecretsTests(unittest.TestCase):
    def test_loose_permissions_warn_and_skip_when_env_set(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "n.env")
            with open(path, "w") as fh:
                fh.write("TELEGRAM_BOT_TOKEN=t\nTELEGRAM_CHAT_ID=1\n")
            os.chmod(path, 0o644)
            err = io.StringIO()
            with mock.patch.dict(os.environ, clear=True), redirect_stderr(err):
                notify.load_env_file(path)
                self.assertEqual(notify.credentials(), ("t", "1"))
            self.assertIn("accessible by others", err.getvalue())
            os.chmod(path, 0o600)
            err = io.StringIO()
            with mock.patch.dict(os.environ, {"TELEGRAM_BOT_TOKEN": "x", "TELEGRAM_CHAT_ID": "2"}, clear=True), redirect_stderr(err):
                notify.load_env_file(path)  # already in the environment (systemd): file untouched
                self.assertEqual(notify.credentials(), ("x", "2"))
            self.assertEqual(err.getvalue(), "")

    def load_warnings(self, path):
        err = io.StringIO()
        with mock.patch.dict(os.environ, clear=True), redirect_stderr(err):
            notify.load_env_file(path)
        return err.getvalue()

    def test_a_clean_secrets_file_gives_no_warning(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "n.env")
            open(path, "w").write("TELEGRAM_BOT_TOKEN=t\nTELEGRAM_CHAT_ID=1\n")
            os.chmod(path, 0o600)
            self.assertEqual(self.load_warnings(path), "")

    def test_warns_when_owned_by_someone_else(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "n.env")
            open(path, "w").write("TELEGRAM_BOT_TOKEN=t\n")
            os.chmod(path, 0o600)
            with mock.patch("os.geteuid", return_value=424242):
                if os.stat(path).st_uid == 0:
                    self.skipTest("test runs as root")
                self.assertIn("owned by uid", self.load_warnings(path))

    def test_warns_when_inside_a_git_repository(self):
        with tempfile.TemporaryDirectory() as d:
            os.mkdir(os.path.join(d, ".git"))
            os.mkdir(os.path.join(d, "conf"))
            path = os.path.join(d, "conf", "n.env")
            open(path, "w").write("TELEGRAM_BOT_TOKEN=t\n")
            os.chmod(path, 0o600)
            out = self.load_warnings(path)
            self.assertIn("git repository", out)
            self.assertNotIn("TELEGRAM_BOT_TOKEN", out)

    def test_env_file_path_comes_from_config(self):
        with tempfile.TemporaryDirectory() as d:
            env = os.path.join(d, "custom.env")
            with open(env, "w") as fh:
                fh.write("TELEGRAM_BOT_TOKEN=cfgtoken\nTELEGRAM_CHAT_ID=7\n")
            os.chmod(env, 0o600)
            conf = os.path.join(d, "h.toml")
            with open(conf, "w") as fh:
                fh.write('[general]\nenable = []\n[notify]\nenv_file = "%s"\n' % env)
            with mock.patch.dict(os.environ, clear=True), mock.patch("centinela.notify.send") as send, \
                    redirect_stderr(io.StringIO()):
                self.assertEqual(cli.main(["--config", conf, "--test"]), 0)
            self.assertEqual(send.call_args[0][:2], ("cfgtoken", "7"))


BUILD = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "build.py")


def sh(*argv):
    import subprocess
    return subprocess.run(argv, capture_output=True, text=True)


class BuildTests(unittest.TestCase):
    """The single-file zipapp is what gets distributed, so run the real artifact."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.out = os.path.join(cls.tmp.name, "dist")
        cls.exe = os.path.join(cls.out, "centinela")
        cls.proc = sh(sys.executable, BUILD, "--out", cls.out)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_builds_and_is_reproducible(self):
        self.assertEqual(self.proc.returncode, 0, self.proc.stderr)
        sums = os.path.join(self.out, "SHA256SUMS")
        first = open(sums).read()
        self.assertEqual(sh(sys.executable, BUILD, "--out", self.out).returncode, 0)
        self.assertEqual(open(sums).read(), first)
        self.assertEqual(sorted(l.split()[1] for l in first.splitlines()), ["centinela", "centinela_1.0.1_all.deb"])
        self.assertTrue(os.access(self.exe, os.X_OK))

    def test_deb_structure(self):
        import io
        import tarfile
        raw = open(os.path.join(self.out, "centinela_1.0.1_all.deb"), "rb").read()
        self.assertTrue(raw.startswith(b"!<arch>\ndebian-binary   "))
        members, pos = {}, 8
        while pos < len(raw):
            name, size = raw[pos:pos + 16].decode().strip(), int(raw[pos + 48:pos + 58])
            members[name] = raw[pos + 60:pos + 60 + size]
            pos += 60 + size + size % 2
        self.assertEqual(list(members), ["debian-binary", "control.tar.gz", "data.tar.gz"])
        self.assertEqual(members["debian-binary"], b"2.0\n")
        ctl = tarfile.open(fileobj=io.BytesIO(members["control.tar.gz"]))
        control = ctl.extractfile("./control").read().decode()
        for field in ("Package: centinela", "Architecture: all", "Depends: python3 (>= 3.11)", "Conflicts: centinel\n"):
            self.assertIn(field, control)
        self.assertEqual(ctl.extractfile("./conffiles").read(), b"/etc/centinela/centinela.toml\n")
        for script in ("postinst", "prerm", "postrm"):
            self.assertEqual(ctl.getmember("./" + script).mode, 0o755)
        data = tarfile.open(fileobj=io.BytesIO(members["data.tar.gz"]))
        unit = data.extractfile("./lib/systemd/system/centinela@.service").read().decode()
        self.assertIn("ExecStart=/usr/bin/centinela --mode %i", unit)
        self.assertNotIn("/usr/local/bin", unit)
        self.assertEqual(data.getmember("./usr/bin/centinela").mode, 0o755)
        self.assertTrue(all(m.uid == 0 and m.gid == 0 for m in data.getmembers()))
        self.assertIn("./etc/centinela/checks.d", [m.name.rstrip("/") for m in data.getmembers()])
        self.assertEqual(data.extractfile("./usr/bin/centinela").read(), open(self.exe, "rb").read())
        copyright = data.extractfile("./usr/share/doc/centinela/copyright").read().decode()
        self.assertIn("License: MIT", copyright)
        self.assertIn("Permission is hereby granted", copyright)

    def test_artifact_runs_with_bundled_modules_and_data(self):
        out = sh(self.exe, "--list-modules", "--config", "/dev/null").stdout
        self.assertIn("nginx", out)
        self.assertIn("firewall", out)
        self.assertIn("[Service]", sh(self.exe, "--print", "service").stdout)
        self.assertIn("[general]", sh(self.exe, "--print", "config").stdout)
        self.assertIn("CAP_DAC_READ_SEARCH", sh(self.exe, "--print", "restricted").stdout)
        self.assertIn("(deny file-write*)", sh(self.exe, "--print", "restricted-macos").stdout)
        self.assertTrue(sh(self.exe, "--print", "restricted-user").stdout.startswith("# systemd-sysusers"))
        self.assertIn("centinela 1.0.1", sh(self.exe, "--version").stdout)
        self.assertIn("demo critical", sh(self.exe, "--test", "--dry-run", "--config", "/dev/null").stdout)


SS = """tcp   LISTEN 0 128  0.0.0.0:22       0.0.0.0:*  users:(("sshd",pid=1,fd=3))
tcp   LISTEN 0 128     [::]:22          [::]:*  users:(("sshd",pid=1,fd=4))
tcp   LISTEN 0 4096 127.0.0.1:6379     0.0.0.0:*  users:(("redis-server",pid=2,fd=6))
tcp   LISTEN 0 511    0.0.0.0:443      0.0.0.0:*  users:(("nginx",pid=3,fd=7))
udp   UNCONN 0 0   127.0.0.53%lo:53    0.0.0.0:*
tcp   LISTEN 0 5       [::1]:631          [::]:*
"""


class PortsTests(unittest.TestCase):
    def run_check(self, conf, out=SS):
        return ports.run(FakeCtx(conf, {"ss -H -lntup": (0, out)}))

    def test_parse_merges_ipv4_ipv6_and_scopes(self):
        got = {ports.entry(l): l.process for l in ports.parse_ss(SS)}
        self.assertEqual(got, {"tcp/22": "sshd", "tcp/6379@local": "redis-server", "tcp/443": "nginx",
                               "udp/53@local": "", "tcp/631@local": ""})

    def test_not_applicable_until_configured(self):
        with mock.patch("shutil.which", return_value="/usr/bin/ss"), mock.patch("sys.platform", "linux"):
            self.assertFalse(ports.applicable(Config()))
            self.assertTrue(ports.applicable(Config.from_string('[ports]\nknown = ["udp/68"]\n')))

    def test_expected_missing_exposed_and_frozen_unexpected(self):
        conf = ('[ports]\nexpected = ["tcp/22", "tcp/6379@local", "tcp/443", "tcp/8080"]\n'
                'known = ["udp/53@local", "tcp/631@local"]\nfreeze = true\n')
        out = (SS.replace("127.0.0.1:6379", "0.0.0.0:6379")                    # redis now open to the world
               + 'tcp LISTEN 0 1 0.0.0.0:4444 0.0.0.0:* users:(("nc",pid=9,fd=3))\n'
               + "tcp LISTEN 0 1 127.0.0.1:9000 0.0.0.0:*\n")
        got = sorted((f.id, f.level) for f in self.run_check(conf, out))
        self.assertEqual(got, sorted([("exposed-tcp/6379", CRIT), ("missing-tcp/8080", CRIT),
                                      ("unexpected-tcp/4444-any", CRIT), ("unexpected-tcp/9000@local-local", WARN)]))

    def test_everything_as_approved_is_silent_and_unfrozen_ignores_new(self):
        conf = ('[ports]\nexpected = ["tcp/22", "tcp/6379@local", "tcp/443"]\nknown = ["udp/53@local", "tcp/631@local"]\nfreeze = true\n')
        self.assertEqual(self.run_check(conf), [])
        extra = SS + "tcp LISTEN 0 1 0.0.0.0:4444 0.0.0.0:*\n"
        self.assertEqual(self.run_check(conf.replace("freeze = true", "freeze = false"), extra), [])
        self.assertEqual(len(self.run_check(conf, extra)), 1)

    def test_falls_back_without_process_names(self):
        ctx = FakeCtx('[ports]\nexpected = ["tcp/22"]\n', {"ss -H -lntup": (1, ""), "ss -H -lntu": (0, SS)})
        self.assertEqual(ports.run(ctx), [])


class FreezeTests(unittest.TestCase):
    def test_services_freeze(self):
        shows = {"systemctl show": (0, "LoadState=loaded\nActiveState=active\n"),
                 "systemctl list-units": (0, "ssh.service loaded active running SSH\ncron.service loaded active running Cron\n"
                                             "getty@tty1.service loaded active running Getty\nmalware.service loaded active running X\n")}
        conf = '[services]\nrequired = []\nwatch = ["ssh"]\nknown = ["cron.service", "getty@*.service"]\nfreeze = true\n'
        fs = services.run(FakeCtx(conf, shows))
        self.assertEqual([f.id for f in fs], ["unexpected-malware.service"])
        self.assertEqual(services.run(FakeCtx(conf.replace("freeze = true", "freeze = false"), shows)), [])

    def test_docker_ignore_images_are_allowed_and_freeze_can_be_off(self):
        ps = docker.parse_ps("a\tredis:7.4\trunning\tUp\t\t\nb\tbusybox:1\trunning\tUp\t\t\nc\tevil:1\trunning\tUp\t\t\n")
        conf = '[docker]\ntrusted_images = ["redis:7.*"]\nignore_images = ["busybox:*"]\n'
        self.assertEqual([f.id for f in docker.check_trusted(FakeCtx(conf), ps)], ["untrusted-evil:1"])
        self.assertEqual(docker.check_trusted(FakeCtx(conf + "freeze_images = false\n"), ps), [])

    def test_generalize(self):
        g = docker.generalize
        self.assertEqual(g("redis:7.4"), "redis:7.*")
        self.assertEqual(g("redis:7.4.1-alpine"), "redis:7.*-alpine")
        self.assertEqual(g("redis:7"), "redis:7")
        self.assertEqual(g("myapp:20261118-ab12"), "myapp:*")
        self.assertEqual(g("ghcr.io/me/app:v1.2.3"), "ghcr.io/me/app:v1.*")
        self.assertEqual(g("ghcr.io/me/app:sha-3f9c2ab"), "ghcr.io/me/app:*")
        self.assertEqual(g("nginx:latest"), "nginx:latest")
        self.assertEqual(g("redis@sha256:abc"), "redis")


class ImageRuleTests(unittest.TestCase):
    PS = ("a\tredis:7.4\trunning\tUp\t\t\nb\tredis:7.2\trunning\tUp\t\t\nc\tdocker.io/library/redis:7.4\trunning\tUp\t\t\n"
          "d\tmyapp:1.3\trunning\tUp\t\t\ne\tmyapp:2.0\trunning\tUp\t\t\nf\tworker:b9\trunning\tUp\t\t\n"
          "g\tworker:c\trunning\tUp\t\t\nh\tghcr.io/me/app:xyz\trunning\tUp\t\t\ni\tredis\trunning\tUp\t\t\n")
    CONF = ('[docker.images]\nredis = "7.4"\nmyApp = "1.*"\nworker = ["a", "b*"]\n"ghcr.io/Me/App" = "*"\n')

    def test_fixed_ranges_lists_case_and_untagged(self):
        fs = docker.check_trusted(FakeCtx(self.CONF), docker.parse_ps(self.PS))
        # redis:7.4 (also as docker.io/library/redis:7.4) is fixed; 7.2 and the untagged "latest" are not;
        # MyApp matches myapp in any case; a list allows several; "*" allows any tag
        self.assertEqual([f.id for f in fs], ["untrusted-myapp:2.0", "untrusted-redis", "untrusted-redis:7.2", "untrusted-worker:c"])
        self.assertTrue(all(f.level == CRIT for f in fs))

    def test_freeze_defaults_on_with_rules_and_can_be_switched_off(self):
        ps = docker.parse_ps(self.PS)
        self.assertTrue(docker.check_trusted(FakeCtx(self.CONF), ps))
        self.assertEqual(docker.check_trusted(FakeCtx('[docker]\nfreeze_images = false\n' + self.CONF), ps), [])
        self.assertEqual(docker.check_trusted(FakeCtx(), ps), [])   # nothing listed: off

    def test_helpers(self):
        self.assertEqual(docker.split_image("Docker.io/library/Redis:7.4@sha256:abc"), ("redis", "7.4"))
        self.assertEqual(docker.split_image("ghcr.io/Me/App"), ("ghcr.io/me/app", "latest"))
        self.assertEqual(docker.split_image("localhost:5000/x"), ("localhost:5000/x", "latest"))
        self.assertTrue(docker.is_exact("7.4"))
        self.assertFalse(docker.is_exact("7.*"))
        self.assertIsNone(docker.matching_rule("redis:7.2", {"redis": ["7.4"]}))

    def test_fixed_tag_means_no_newer_version_warnings_but_ranges_still_get_them(self):
        tags = json.dumps({"results": [{"name": n} for n in ("7.4", "7.6")], "next": None})
        def check(conf):
            ctx = FakeCtx(conf, {"docker image inspect": (1, "")}, {"tags?page_size": tags})
            return docker._check_image(ctx, "redis:7.4", docker.parse_ref("redis:7.4"), None)
        self.assertEqual(check('[docker.images]\nredis = "7.4"\n'), [])                      # fixed to 7.4: leave it alone
        self.assertEqual(check('[docker.images]\nredis = "7.*"\n')[0].id, "newer-redis:7.4-7.6")  # a range still tracks the major
        self.assertEqual(check("")[0].id, "newer-redis:7.4-7.6")                              # no rule: as before


class DropInTests(unittest.TestCase):
    def test_merge_order_and_sources(self):
        with tempfile.TemporaryDirectory() as d:
            os.makedirs(os.path.join(d, "centinela.d"))
            for name, text in (("centinela.toml", '[docker]\nignore_images = ["a"]\nx = 1\n[disk]\nwarn_percent = 70\n'),
                               ("centinela.d/10-wizard.toml", '[docker]\nignore_images = ["b"]\n'),
                               ("centinela.d/20-local.toml", '[disk]\nwarn_percent = 60\n')):
                with open(os.path.join(d, name), "w") as fh:
                    fh.write(text)
            cfg = Config.load(os.path.join(d, "centinela.toml"))
            self.assertEqual(cfg.list("docker", "ignore_images"), ["b"])  # lists replace
            self.assertEqual(cfg.int("docker", "x", 0), 1)  # other keys survive
            self.assertEqual(cfg.int("disk", "warn_percent", 80), 60)  # later file wins
            self.assertEqual(len(cfg.sources), 3)
            self.assertEqual(Config.load(os.path.join(d, "nope.toml")).sources[0].endswith("10-wizard.toml"), True)
            with open(os.path.join(d, "centinela.d", "30-bad.toml"), "w") as fh:
                fh.write("[oops")
            with self.assertRaises(ValueError) as cm:
                Config.load(os.path.join(d, "centinela.toml"))
            self.assertIn("30-bad.toml", str(cm.exception))

    def test_dump_subtables_and_quoted_keys_roundtrip(self):
        import tomllib
        data = {"docker": {"freeze_images": True, "ignore_images": [],
                           "images": {"ghcr.io/me/app": ["a", "b"], "redis": "7.4"}}}
        text = setup.dump_toml(data)
        self.assertIn('[docker.images]\n"ghcr.io/me/app" = [', text)
        self.assertLess(text.index("freeze_images"), text.index("[docker.images]"))       # flat keys first, as TOML requires
        self.assertEqual(tomllib.loads(text), data)

    def test_dump_roundtrip(self):
        data = {"docker": {"trusted_images": ["redis:7.*", 'we"ird'], "ignore_images": [], "freeze_images": True},
                "general": {"host_name": "my-vps", "n": 3}}
        import tomllib
        self.assertEqual(tomllib.loads(setup.dump_toml(data)), data)


PS = ("redis\tredis:7.4\trunning\tUp 2 days\t/srv/app\tredis\n"
      "web\tnginx:1.27\trunning\tUp 2 days\t\t\n"
      "app\tghcr.io/me/app:20261118-ab\trunning\tUp 1 day\t\t\n"
      "app2\tghcr.io/me/app:20261117-cd\trunning\tUp 1 day\t\t\n")
UNITS = ("ssh.service loaded active running SSH\ncron.service loaded active running Cron\n"
         "getty@tty1.service loaded active running Getty\n")
FAKE_PLAN = {"apt": (type("M", (), {"DESC": "apt stuff"}), "run"), "nginx": (type("M", (), {"DESC": "nginx"}), "n/a"),
             "cve": (type("M", (), {"DESC": "cves"}), "run")}


def scripted(answers):
    """ask() that answers by prompt keyword, in order; EOF when a keyword runs out."""
    queues = {k: list(v) for k, v in answers.items()}

    def ask(prompt):
        for key, queue in queues.items():
            if key in prompt:
                if queue:
                    return queue.pop(0)
                raise EOFError
        raise EOFError
    return ask


class BannerTests(unittest.TestCase):
    def test_figure_banner(self):
        lines = setup.banner_text(False, 80).split("\n")
        self.assertEqual(len(lines), 26)
        self.assertEqual([l.strip() for l in lines[-3:] if l.strip()], ["CENTINELA", "MONITORING TOOL"])
        self.assertTrue(any(0x2800 <= ord(ch) <= 0x28FF for l in lines for ch in l))        # braille art
        self.assertTrue(all(l.rstrip() == l for l in lines))                                 # no trailing blanks
        self.assertFalse(any(ch == "\u2800" for l in lines for ch in l))                     # blanks are plain spaces
        self.assertTrue(setup.banner_text(True, 80).startswith("\033[32m") and setup.banner_text(True, 80).endswith("\033[0m"))
        self.assertEqual(setup.banner_text(False, 10), "")                                   # too narrow: skipped, not wrapped

    def test_ascii_fallback_is_pure_ascii(self):
        text = setup.banner_text(False, 80, utf8=False)
        text.encode("ascii")                                                                 # raises if anything is not ASCII
        self.assertIn("MONITORING TOOL", text)
        self.assertEqual(len(text.split("\n")), 7)
        self.assertEqual(setup.banner_text(False, 40, utf8=False), "")                       # the title needs 63 columns

    def test_wizard_prints_banner_only_when_given(self):
        said = []
        w = setup.Wizard(FakeCtx(), scripted({}), said.append, True, setup.banner_text(False, 80))
        with mock.patch("centinela.setup.modules.plan", return_value={}), mock.patch("centinela.setup.modules.discover", return_value={}):
            w.run()
        self.assertIn("CENTINELA", said[0])
        said2 = []
        w2 = setup.Wizard(FakeCtx(), scripted({}), said2.append, True)
        with mock.patch("centinela.setup.modules.plan", return_value={}), mock.patch("centinela.setup.modules.discover", return_value={}):
            w2.run()
        self.assertNotIn("CENTINELA", said2[0])

    def run_main(self, *args, tty=True, env=None, encoding_name="utf-8"):
        class Tty(io.StringIO):
            encoding = encoding_name

            def isatty(self):
                return tty
        out = Tty()
        with mock.patch("centinela.setup.Ctx", return_value=FakeCtx()), \
                mock.patch("centinela.setup.modules.plan", return_value={}), \
                mock.patch("centinela.setup.modules.discover", return_value={}), \
                mock.patch.dict(os.environ, env or {}, clear=False), redirect_stdout(out):
            code = setup.main(["--dry-run", "--config", "/nonexistent/c.toml"] + list(args), ask=scripted({}), say=print)
        return code, out.getvalue()

    def test_main_shows_banner_on_a_terminal_only(self):
        code, out = self.run_main(env={"TERM": "xterm", "NO_COLOR": ""})   # an empty NO_COLOR does not disable colour
        self.assertEqual(code, 0)
        self.assertLess(out.index("MONITORING TOOL"), out.index("centinela setup"))  # banner comes before the intro
        self.assertTrue(any(0x2800 <= ord(ch) <= 0x28FF for ch in out))                # braille figure on a UTF-8 terminal
        ascii_out = self.run_main(encoding_name="ascii")[1]
        self.assertIn("MONITORING TOOL", ascii_out)
        self.assertFalse(any(ord(ch) > 127 for ch in ascii_out.split("centinela setup")[0]))  # fallback never emits braille
        self.assertIn("\033[32m", out)
        no_color = self.run_main(env={"TERM": "xterm", "NO_COLOR": "1"})[1]
        self.assertIn("MONITORING TOOL", no_color)
        self.assertNotIn("\033[", no_color)
        self.assertNotIn("\033[", self.run_main(env={"TERM": "dumb", "NO_COLOR": ""})[1])
        for quiet in (self.run_main("--no-banner")[1], self.run_main("--yes")[1], self.run_main(tty=False)[1]):
            self.assertNotIn("MONITORING TOOL", quiet)                     # flag, --yes and piped output stay clean

    def test_flag_exists(self):
        self.assertIn("--no-banner", sh(sys.executable, "-m", "centinela", "setup", "--help").stdout)


class WizardTests(unittest.TestCase):
    def wizard(self, conf="", answers=None, assume_yes=False):
        ctx = FakeCtx(conf, {"docker ps": (0, PS), "systemctl list-units": (0, UNITS), "ss -H -lntup": (0, SS)})
        said = []
        return setup.Wizard(ctx, scripted(answers or {}), said.append, assume_yes), said

    def run_wizard(self, *a, **kw):
        import tomllib
        w, said = self.wizard(*a, **kw)
        with mock.patch("centinela.setup.modules.plan", return_value=FAKE_PLAN), \
                mock.patch("centinela.setup.modules.discover", return_value={}), \
                mock.patch("centinela.setup.identity.local_ip", return_value="10.0.0.5"), \
                mock.patch("centinela.setup.identity.os_name", return_value="Debian 12"), \
                mock.patch("socket.gethostname", return_value="vps"):
            text = w.run()
        return tomllib.loads(text.split("\n\n", 1)[1]), text, "\n".join(said)

    def test_defaults_monitor_everything_found(self):
        out, text, said = self.run_wizard(assume_yes=True)
        self.assertEqual(out["general"]["disable"], [])
        self.assertEqual(out["notify"]["show"], ["host"])
        self.assertEqual(out["docker"]["images"], {"ghcr.io/me/app": "*", "nginx": "1.*", "redis": "7.*"})  # rotating tags collapse
        self.assertEqual(out["docker"]["trusted_images"], [])
        self.assertTrue(out["docker"]["freeze_images"])
        self.assertEqual(out["services"]["watch"], ["cron.service", "ssh.service"])
        self.assertEqual(out["services"]["known"], ["getty@*.service"])
        self.assertFalse(out["services"]["freeze"])
        self.assertEqual(out["ports"]["expected"], ["tcp/22", "tcp/443", "tcp/631@local", "tcp/6379@local", "udp/53@local"])
        self.assertTrue(out["ports"]["freeze"])
        self.assertIn("never ask for or write secrets", said)

    def test_user_picks_ignores_and_freezes(self):
        # each pick asks again until an empty Enter: modules, identity, docker, services, ports
        answers = {"Toggle": ["1", "", "1", "", "", "2", "", "1-2", ""], "Name for": ["my-vps"], "Use *": ["n"],
                   "Freeze": ["n", "y", "n"]}
        out, _, said = self.run_wizard(answers=answers)
        self.assertEqual(out["general"], {"disable": ["apt"], "host_name": "my-vps"})
        self.assertEqual(out["notify"]["show"], ["host", "ip"])
        self.assertEqual(out["docker"]["images"], {"ghcr.io/me/app": ["20261117-cd", "20261118-ab"],
                                                   "nginx": "1.27", "redis": "7.4"})  # no wildcard: exact tags
        self.assertFalse(out["docker"]["freeze_images"])
        self.assertEqual(out["services"]["watch"], ["cron.service"])      # ssh unticked
        self.assertEqual(out["services"]["known"], ["getty@*.service", "ssh.service"])
        self.assertTrue(out["services"]["freeze"])
        self.assertNotIn("tcp/22", out["ports"]["expected"])
        self.assertEqual(out["ports"]["known"][:2], ["tcp/22", "tcp/443"])
        self.assertFalse(out["ports"]["freeze"])
        self.assertIn("(10.0.0.5)", said)

    def test_rule_prompt_fixed_ranges_suffix_names_and_mistakes(self):
        answers = {"Change a rule": ["redis=fixed app=1.* nginx=1.27,1.26 nope=3 redis="]}
        out, _, said = self.run_wizard(answers=answers)
        self.assertEqual(out["docker"]["images"],
                         {"ghcr.io/me/app": "1.*", "nginx": ["1.27", "1.26"], "redis": "7.4"})   # fixed = what runs now
        self.assertIn("ignoring 'nope=3'", said)
        self.assertIn("ignoring 'redis='", said)
        self.assertIn("FIXED", said)

    def test_rerun_flags_new_items_and_keeps_hand_written_patterns(self):
        conf = ('[docker]\ntrusted_images = ["redis:*"]\nignore_images = ["nginx:*"]\nfreeze_images = true\n'
                '[services]\nwatch = ["ssh"]\nknown = ["cron.service", "gone.service"]\nfreeze = true\n'
                '[ports]\nexpected = ["tcp/22", "tcp/9999"]\nknown = ["tcp/443"]\nfreeze = true\n')
        out, _, said = self.run_wizard(conf)  # all prompts EOF -> accept proposals
        self.assertEqual(out["docker"]["images"]["redis"], "*")           # hand-written pattern reused for redis:7.4
        self.assertIn("nginx:*", out["docker"]["ignore_images"])         # still ignored, not monitored
        self.assertEqual(out["docker"]["images"]["ghcr.io/me/app"], "*")  # new -> proposed ticked
        self.assertIn("<- NEW", said)
        self.assertIn("(not present now)", said)                          # tcp/9999 no longer listens
        self.assertIn("gone.service", out["services"]["known"])           # old ignored entries are carried over
        self.assertIn("tcp/443", out["ports"]["known"])
        self.assertTrue(out["services"]["freeze"])                        # previous answers are the defaults

    def test_setup_command_writes_only_the_dropin_after_confirmation(self):
        import contextlib
        with tempfile.TemporaryDirectory() as d:
            conf = os.path.join(d, "centinela.toml")
            with open(conf, "w") as fh:
                fh.write("[disk]\nwarn_percent = 70\n")
            fake = FakeCtx("", {"docker ps": (0, PS), "systemctl list-units": (0, UNITS), "ss -H -lntup": (0, SS)})
            target = os.path.join(d, "centinela.d", "10-wizard.toml")
            common = ["--config", conf]
            with mock.patch("centinela.setup.Ctx", return_value=fake), mock.patch("centinela.setup.modules.plan", return_value=FAKE_PLAN), \
                    mock.patch("centinela.setup.modules.discover", return_value={}):
                out = io.StringIO()
                with contextlib.redirect_stdout(out):
                    self.assertEqual(setup.main(common + ["--dry-run"], ask=scripted({}), say=print), 0)
                self.assertFalse(os.path.exists(target))               # dry run writes nothing
                self.assertEqual(setup.main(common, ask=scripted({"Write this": ["n"]}), say=lambda m: None), 0)
                self.assertFalse(os.path.exists(target))               # declined
                self.assertEqual(setup.main(common + ["--yes"], ask=scripted({}), say=lambda m: None), 0)
            self.assertTrue(os.path.exists(target))
            self.assertEqual(open(conf).read(), "[disk]\nwarn_percent = 70\n")   # main file untouched
            self.assertEqual(oct(os.stat(target).st_mode & 0o777), "0o644")
            cfg = Config.load(conf)
            self.assertEqual(cfg.int("disk", "warn_percent", 0), 70)
            self.assertEqual(cfg.table("docker", "images")["redis"], "7.*")    # the file we wrote is read back


class ExampleCheckTests(unittest.TestCase):
    def load(self):
        import importlib.util
        path = os.path.join(os.path.dirname(__file__), "..", "centinela", "data", "tcp_port.py")
        spec = importlib.util.spec_from_file_location("tcp_port_example", path)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod

    def test_reports_closed_ports_only(self):
        import socket
        mod = self.load()
        with socket.socket() as srv:
            srv.bind(("127.0.0.1", 0))
            srv.listen(1)
            up = "127.0.0.1:%d" % srv.getsockname()[1]
            with socket.socket() as tmp:
                tmp.bind(("127.0.0.1", 0))
                down = "127.0.0.1:%d" % tmp.getsockname()[1]   # bound then closed again: nothing listens
            ctx = FakeCtx('[tcp_port]\ntargets = ["%s", "%s"]\n' % (up, down))
            fs = mod.run(ctx)
        self.assertEqual([f.id for f in fs], [down])
        self.assertTrue(fs[0].cmd.startswith("nc -vz -w 3 127.0.0.1 "))
        self.assertFalse(mod.applicable(Config()))


class MemoryTests(unittest.TestCase):
    MEMINFO = ("MemTotal:        2048000 kB\nMemFree:          100000 kB\nMemAvailable:     204800 kB\n"
               "SwapTotal:       2097152 kB\nSwapFree:         204800 kB\n")

    def levels(self, total_mb, used_pct, conf=""):
        cfg = Config.from_string(conf)
        findings = memory.evaluate(cfg, total_mb, int(total_mb * (100 - used_pct) / 100))
        return [f.level for f in findings]

    def test_the_same_percentage_means_different_things_on_different_sizes(self):
        # 90% of 2 GB leaves ~200 MB: warn. 95% of 2 GB leaves ~100 MB: critical.
        self.assertEqual(self.levels(2048, 90), [WARN])
        self.assertEqual(self.levels(2048, 95), [CRIT])
        self.assertEqual(self.levels(8192, 90), [WARN])      # ~800 MB left
        self.assertEqual(self.levels(8192, 95), [CRIT])      # ~400 MB left
        self.assertEqual(self.levels(16384, 90), [])         # ~1.6 GB left: plenty
        self.assertEqual(self.levels(16384, 95), [WARN])     # ~800 MB left
        self.assertEqual(self.levels(65536, 95), [])         # ~3.2 GB left
        self.assertEqual(self.levels(2048, 80), [])

    def test_thresholds_are_configurable_and_zero_floor_means_percent_only(self):
        self.assertEqual(self.levels(65536, 95, "[memory]\nwarn_free_mb = 0\n"), [WARN])
        self.assertEqual(self.levels(2048, 90, "[memory]\nwarn_percent = 95\n"), [])
        self.assertEqual(self.levels(2048, 90, "[memory]\nwarn_percent = 0\ncrit_percent = 0\n"), [])

    def test_linux_reads_available_memory_not_free(self):
        total, available, swap, swap_used = memory.read_linux(self.MEMINFO)
        self.assertEqual((total, available, swap, swap_used), (2000, 200, 2048, 1848))
        fs = memory.evaluate(Config(), total, available, swap, swap_used)
        self.assertEqual([(f.id, f.level) for f in fs], [("memory", WARN), ("swap", WARN)])
        self.assertIn("90% used: 200 MB available of 2.0 GB", fs[0].text)

    def test_old_kernels_without_memavailable(self):
        old = "MemTotal: 2048000 kB\nMemFree: 100000 kB\nBuffers: 50000 kB\nCached: 50000 kB\n"
        self.assertEqual(memory.read_linux(old)[:2], (2000, 195))

    def test_swap_needs_to_be_heavy_in_percent_and_size(self):
        self.assertEqual(memory.evaluate(Config(), 8192, 8000, 100, 90), [])        # 90% of a tiny swap
        self.assertEqual(memory.evaluate(Config(), 8192, 8000, 4096, 1024), [])     # 25% of 4 GB
        self.assertEqual(len(memory.evaluate(Config(), 8192, 8000, 4096, 3800)), 1)

    def test_macos_uses_the_free_percentage_the_system_reports(self):
        ctx = FakeCtx("", {"sysctl -n hw.memsize": (0, "2147483648\n"),
                           "memory_pressure": (0, "The system has 2147483648 (524288 pages)\n\nSystem-wide memory free percentage: 8%\n")})
        total, available, _, _ = memory.read_macos(ctx)
        self.assertEqual((total, available), (2048, 163))
        with self.assertRaises(Skip):
            memory.read_macos(FakeCtx("", {"sysctl -n hw.memsize": (0, "2147483648"), "memory_pressure": (0, "nothing useful")}))

    def test_run_on_linux_reads_the_proc_file(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "meminfo")
            open(path, "w").write(self.MEMINFO)
            with mock.patch.object(memory, "MEMINFO", path), mock.patch("sys.platform", "linux"):
                self.assertEqual([f.id for f in memory.run(FakeCtx())], ["memory", "swap"])
            with mock.patch.object(memory, "MEMINFO", os.path.join(d, "missing")), mock.patch("sys.platform", "linux"):
                with self.assertRaises(Skip):
                    memory.run(FakeCtx())


class LoadTests(unittest.TestCase):
    def test_the_load_is_judged_per_cpu(self):
        self.assertEqual(load.evaluate(Config(), 3.9, 4), [])                       # 0.98 per CPU
        (warn,) = load.evaluate(Config(), 4.0, 4)
        (crit,) = load.evaluate(Config(), 8.0, 4)
        self.assertEqual((warn.level, crit.level), (WARN, CRIT))
        self.assertIn("1.00 per CPU", warn.text)
        self.assertEqual(load.evaluate(Config(), 8.0, 16), [])                      # the same load is fine on 16 CPUs

    def test_thresholds_window_and_off_switch(self):
        self.assertEqual(load.evaluate(Config.from_string("[load]\nwarn_per_cpu = 2.5\ncrit_per_cpu = 5\n"), 12.0, 4)[0].level, WARN)
        self.assertEqual(load.evaluate(Config.from_string("[load]\nwarn_per_cpu = 0\ncrit_per_cpu = 0\n"), 80.0, 4), [])
        with mock.patch("os.getloadavg", return_value=(9.0, 5.0, 1.0)), mock.patch("os.cpu_count", return_value=4):
            self.assertEqual(load.run(FakeCtx()), [])                                # default window: 15 min
            (f,) = load.run(FakeCtx("[load]\nwindow = 1\n"))
            self.assertEqual(f.level, CRIT)
            self.assertIn("over 1 min", f.text)

    def test_a_bad_value_falls_back_to_the_default(self):
        self.assertEqual(len(load.evaluate(Config.from_string('[load]\nwarn_per_cpu = "lots"\n'), 4.0, 4)), 1)


class SafetyTests(unittest.TestCase):
    def refused(self, line):
        with self.assertRaises(safety.Unsafe, msg=line):
            safety.verify(line.split())

    def test_the_commands_the_checks_run_are_allowed(self):
        for line in ("ss -H -lntup", "ufw status", "df -P -x tmpfs", "docker ps -a --format x", "docker image ls --format y",
                     "docker image inspect a b", "docker info --format x", "systemctl show -p LoadState x",
                     "systemctl --failed --no-legend", "systemctl list-units --type=service", "apt list --upgradable",
                     "openssl x509 -noout -enddate -in /x", "needrestart -b", "nginx -v", "pgrep -f x",
                     "sysctl -n net.ipv4.ip_forward", "find /var/log -name x", "curl -sS https://x", "tar -tf x.tar"):
            safety.verify(line.split())

    def test_commands_that_change_things_are_refused(self):
        for line in ("rm -rf /", "mkfs.ext4 /dev/x", "reboot", "docker rm x", "docker image rm x", "docker system prune",
                     "systemctl restart x", "apt install x", "apt-get install x", "dpkg -i x", "needrestart",
                     "sed -i s/a/b/ f", "curl -sSo f http://x", "wget http://x", "tar xf a", "sysctl -w a=1",
                     "sysctl a=1", "ip addr add 1.2.3.4 dev lo", "iptables -A INPUT -j DROP", "nginx -s reload",
                     "journalctl --vacuum-size=1M"):
            self.refused(line)

    def test_find_is_refused_only_when_it_acts(self):
        self.refused("find / -name x -delete")
        self.refused("find . -exec ls {} ;")
        safety.verify(["find", "/var", "-name", "x", "-mtime", "+1"])

    def test_wrappers_are_looked_through(self):
        for line in ("sudo -u root rm x", "env A=1 nice -n 5 mv a b", "timeout 5 xargs rm", "nohup rm x"):
            self.refused(line)
        safety.verify("timeout 5 df -P".split())

    def test_inline_code_cannot_be_inspected(self):
        for line in ("bash -c ls", "sh -c true", "python3 -c 1", "perl -e 1", "bash -lc ls", "awk {print} f"):
            self.refused(line)

    def test_a_script_is_read_before_it_runs(self):
        with tempfile.TemporaryDirectory() as d:
            def script(name, body, mode=0o755):
                path = os.path.join(d, name)
                open(path, "w").write(body)
                os.chmod(path, mode)
                return path
            good = script("good.sh", "#!/bin/sh\n# rm would be bad\ndf -P | head -3\n")
            bad = script("bad.sh", "#!/bin/sh\ndf -P\nrm -rf /tmp/x\n")
            loose = script("loose.sh", "#!/bin/sh\ndf\n", 0o777)
            py = script("c.py", "import shutil\nshutil.rmtree('/x')\n")
            safety.verify([good])
            safety.verify(["sh", good])
            for argv in ([bad], ["bash", bad], [loose], ["python3", py]):
                with self.assertRaises(safety.Unsafe, msg=argv):
                    safety.verify(argv)
            with self.assertRaises(safety.Unsafe) as cm:
                safety.verify([bad])
            self.assertIn("line 3", str(cm.exception))

    def test_ctx_run_refuses_unless_allowed(self):
        with self.assertRaises(Blocked):
            Ctx(Config()).run(["rm", "-rf", "/nonexistent-centinela"])
        self.assertEqual(Ctx(Config()).run(["rm", "/nonexistent-centinela-x"], unsafe=True)[0], 1)
        allowed = Ctx(Config.from_string("[general]\nallow_dangerous_commands = true\n"))
        self.assertEqual(allowed.run(["rm", "/nonexistent-centinela-x"])[0], 1)


class ExpectTests(unittest.TestCase):
    def test_a_dangerous_rule_is_refused_with_a_finding_unless_allowed(self):
        conf = '[expect.clean]\nrun = "rm /tmp/x"\n'
        (f,) = expect.run(FakeCtx(conf, {"rm": (0, "")}))
        self.assertEqual(f.level, WARN)
        self.assertIn("refused: rm can change or delete data", f.text)
        self.assertIn("allow_dangerous = true", f.text)
        self.assertEqual(expect.run(FakeCtx(conf + "allow_dangerous = true\n", {"rm": (0, "")})), [])

    SSHD = "permitrootlogin no\npasswordauthentication no\nport 22\n"

    def run_rules(self, conf, cmds):
        ctx = FakeCtx(conf, cmds)
        self.assertTrue(expect.applicable(ctx.cfg))
        return expect.run(ctx)

    def test_not_applicable_without_rules(self):
        self.assertFalse(expect.applicable(Config()))
        self.assertFalse(expect.applicable(Config.from_string("[expect]\n")))

    def test_line_must_be_present_as_a_whole_line(self):
        conf = '[expect.ssh_root]\nrun = "sshd -T"\nline = "permitrootlogin no"\ntext = "SSH root login"\n'
        self.assertEqual(self.run_rules(conf, {"sshd -T": (0, self.SSHD)}), [])
        fs = self.run_rules(conf, {"sshd -T": (0, "permitrootlogin yes\nxpermitrootlogin no\n")})
        self.assertEqual([(f.id, f.level, f.cmd) for f in fs], [("ssh_root", WARN, "sshd -T")])
        self.assertEqual(fs[0].text, "SSH root login: output does not have the line 'permitrootlogin no'")

    def test_equals_contains_not_contains_regex(self):
        conf = ('[expect.fwd]\nrun = "sysctl -n net.ipv4.ip_forward"\nequals = "0"\nlevel = "crit"\n'
                '[expect.has]\nrun = "cat f"\ncontains = "ok"\nnot_contains = "bad"\nregex = "^v\\\\d+$"\n')
        good = {"sysctl -n": (0, "0\n"), "cat f": (0, "ok\nv12\n")}
        self.assertEqual(self.run_rules(conf, good), [])
        fs = self.run_rules(conf, {"sysctl -n": (0, "1\n"), "cat f": (0, "ok bad\nv12\n")})
        self.assertEqual([(f.id, f.level) for f in fs], [("fwd", CRIT), ("has", WARN)])
        self.assertIn("contains 'bad'", fs[1].text)

    def test_exit_code_is_the_default_expectation(self):
        conf = '[expect.up]\nrun = "systemctl is-active x"\n[expect.off]\nrun = "systemctl is-active y"\nexit = 3\n'
        cmds = {"systemctl is-active x": (0, "active"), "systemctl is-active y": (3, "inactive")}
        self.assertEqual(self.run_rules(conf, cmds), [])
        fs = self.run_rules(conf, {"systemctl is-active x": (3, ""), "systemctl is-active y": (0, "")})
        self.assertEqual([f.text for f in fs], ["off: exit code is 0, expected 3", "up: exit code is 3, expected 0"])

    def test_missing_command_and_timeout_are_reported(self):
        conf = '[expect.a]\nrun = "nosuch -x"\n[expect.b]\nrun = "slow"\n'

        class Slow(FakeCtx):
            def run(self, argv, timeout=60, unsafe=False):
                if argv[0] == "slow":
                    raise Skip("timed out")
                return super().run(argv, timeout)

        fs = expect.run(Slow(conf))
        self.assertIn("cannot run nosuch", fs[0].text)
        self.assertIn("did not finish in time", fs[1].text)

    def test_fix_replaces_the_suggested_command(self):
        conf = '[expect.a]\nrun = "sshd -T"\nline = "x"\nfix = "sudoedit /etc/ssh/sshd_config"\n'
        (f,) = self.run_rules(conf, {"sshd -T": (0, "y")})
        self.assertEqual(f.cmd, "sudoedit /etc/ssh/sshd_config")

    def test_the_output_is_never_in_the_message(self):
        conf = '[expect.a]\nrun = "cat secret"\nequals = "fine"\n'
        (f,) = self.run_rules(conf, {"cat secret": (0, "hunter2-the-password")})
        self.assertNotIn("hunter2", f.text)

    def test_bad_rules_are_findings_not_crashes(self):
        conf = ('[expect.noun]\nline = "x"\n[expect.typo]\nrun = "true"\nlines = "x"\n'
                '[expect.re]\nrun = "true"\nregex = "("\n[expect.ex]\nrun = "true"\nexit = "x"\n')
        fs = self.run_rules(conf, {"true": (0, "")})
        self.assertEqual(len(fs), 4)
        self.assertTrue(all(f.level == WARN for f in fs))
        self.assertEqual([f.id for f in fs], ["ex", "noun", "re", "typo"])
        self.assertIn("needs a 'run'", fs[1].text)
        self.assertIn("not valid", fs[2].text)
        self.assertIn("unknown setting 'lines'", fs[3].text)


class HeartbeatTests(unittest.TestCase):
    ENV = {"TELEGRAM_BOT_TOKEN": "t", "TELEGRAM_CHAT_ID": "1", "HEARTBEAT_URL": "https://hc.example.org/ping/SECRETTOKEN"}

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.state = os.path.join(self.tmp.name, "s", "state.json")
        self.conf = os.path.join(self.tmp.name, "h.toml")
        os.chmod(self.tmp.name, 0o755)
        open(os.path.join(self.tmp.name, "quiet.py"), "w").write(
            "NAME='quiet'\nDESC='d'\ndef applicable(cfg): return True\ndef run(ctx): return []\n")
        self.write_conf("")
        self.base = ["--state", self.state, "--env-file", os.path.join(self.tmp.name, "none.env")]

    def tearDown(self):
        self.tmp.cleanup()

    def write_conf(self, extra, enable='["quiet"]'):
        with open(self.conf, "w") as fh:
            fh.write('[general]\nenable = %s\nextra_dir = "%s"\n%s' % (enable, self.tmp.name, extra))

    def invoke(self, *args, env=None):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err), mock.patch.dict(os.environ, env or self.ENV, clear=False):
            code = cli.main(["--config", self.conf] + self.base + list(args))
        return code, out.getvalue(), err.getvalue()

    def write_runs(self, **ages_hours):
        os.makedirs(os.path.dirname(self.state), exist_ok=True)
        runs = {mode: time.time() - hours * 3600 for mode, hours in ages_hours.items()}
        with open(self.state, "w") as fh:
            json.dump({"sent": {}, "runs": runs}, fh)

    def test_a_completed_run_is_recorded_and_shown_by_status(self):
        with mock.patch("centinela.notify._open"):
            self.assertEqual(self.invoke("--mode", "daily")[0], 0)
        code, out, _ = self.invoke("--status")
        self.assertEqual(code, 0)
        self.assertIn("daily   last completed", out)
        self.assertIn("weekly  never completed", out)

    def test_status_exits_1_when_a_run_is_overdue(self):
        self.write_runs(daily=100, weekly=1)
        code, out, _ = self.invoke("--status")
        self.assertEqual(code, 1)
        self.assertIn("OVERDUE", out)
        self.write_runs(daily=47, weekly=9 * 24)
        self.assertEqual(self.invoke("--status")[0], 0)

    def test_each_schedule_notices_the_other_one_stopping(self):
        self.write_runs(daily=1, weekly=12 * 24)
        with mock.patch("centinela.notify.send") as send, mock.patch("centinela.notify._open"):
            self.invoke("--mode", "daily")
        self.assertIn("the weekly run of centinela last completed 12 days ago", send.call_args[0][2])
        self.write_runs(daily=100, weekly=1)
        _, out, _ = self.invoke("--mode", "weekly", "--dry-run")
        self.assertIn("the daily run of centinela last completed 4 days ago", out)
        self.write_runs(daily=1)  # the other one never ran here: not late, just not used
        self.assertEqual(self.invoke("--mode", "daily", "--dry-run")[1], "")
        self.write_conf('[heartbeat]\nwatch = ["daily"]\n')
        self.write_runs(daily=1, weekly=500)
        self.assertEqual(self.invoke("--mode", "daily", "--dry-run")[1], "")  # told not to watch weekly

    def test_the_failure_clears_when_the_timer_comes_back(self):
        self.write_runs(daily=1, weekly=12 * 24)
        with mock.patch("centinela.notify.send") as send, mock.patch("centinela.notify._open"):
            self.invoke("--mode", "daily")
            self.invoke("--mode", "daily")  # same problem: deduped
            self.assertEqual(send.call_count, 1)
            self.invoke("--mode", "weekly")  # the weekly run completes again
            self.write_runs(daily=1, weekly=12 * 24)  # ...and later stops again
            self.invoke("--mode", "daily")
        self.assertEqual(send.call_count, 2)

    def test_ping_after_a_completed_run_only(self):
        with mock.patch("centinela.notify._open") as opened:
            self.assertEqual(self.invoke("--dry-run")[0], 0)
            opened.assert_not_called()  # a dry run proves nothing
            self.assertEqual(self.invoke()[0], 0)
            self.assertEqual(opened.call_count, 1)
            req = opened.call_args[0][0]
            self.assertEqual(req.full_url, "https://hc.example.org/ping/SECRETTOKEN")
        self.write_conf("", enable="[]")  # nothing could be checked: no proof of life
        with mock.patch("centinela.notify._open") as opened:
            self.assertEqual(self.invoke()[0], 0)
            opened.assert_not_called()
        self.write_conf("")
        with mock.patch("centinela.notify._open") as opened, mock.patch("centinela.notify.send", side_effect=notify.NotifyError("boom")):
            self.write_runs(daily=1, weekly=500)  # a finding to send, and the channel is down
            self.assertEqual(self.invoke("--mode", "daily")[0], 1)
            opened.assert_not_called()  # failed run: no ping, so the outside service raises the alarm

    def test_ping_problems_never_fail_the_run_or_leak_the_url(self):
        bad = dict(self.ENV, HEARTBEAT_URL="http://hc.example.org/ping/SECRETTOKEN")
        code, _, err = self.invoke(env=bad)
        self.assertEqual(code, 0)
        self.assertIn("heartbeat: the URL must be https://", err)
        self.assertNotIn("SECRETTOKEN", err)
        with mock.patch("centinela.notify._open", side_effect=OSError("down")):
            code, _, err = self.invoke(env=self.ENV)
        self.assertEqual(code, 0)
        self.assertNotIn("SECRETTOKEN", err)
        with mock.patch.dict(os.environ, self.ENV):
            self.assertNotIn("HEARTBEAT_URL", child_env())

    def test_still_alive_message(self):
        self.write_conf('[heartbeat]\nmessage = "weekly"\n')
        with mock.patch("centinela.notify.send") as send, mock.patch("centinela.notify._open"):
            self.invoke("--mode", "daily")
            self.assertEqual(send.call_count, 0)  # weekly only
            self.invoke("--mode", "weekly")
            self.assertEqual(send.call_count, 1)
            self.assertIn("centinela is alive (weekly run completed, 1 check(s) ran", send.call_args[0][2])
        self.assertIn("is alive", self.invoke("--mode", "weekly", "--dry-run")[1])
        self.write_conf("")  # default: silent when healthy
        with mock.patch("centinela.notify.send") as send, mock.patch("centinela.notify._open"):
            self.invoke("--mode", "weekly")
        self.assertEqual(send.call_count, 0)


class MigrateTests(unittest.TestCase):
    def test_old_service_defaults_are_found_per_key(self):
        old = migrate.old_service_defaults_in_use
        self.assertEqual(set(old(Config())), {"required", "watch"})
        self.assertEqual(old(Config.from_string('[services]\nwatch = ["nginx"]\n')), {"required": ["fail2ban"]})
        self.assertEqual(old(Config.from_string('[services]\nrequired = []\nwatch = []\n')), {})
        self.assertEqual(old(Config.from_string('[general]\ndisable = ["services"]\n')), {})
        self.assertEqual(old(Config.from_string('[general]\nenable = ["disk"]\n')), {})

    def run_migrate(self, conf_text, *args):
        d = tempfile.mkdtemp()
        self.addCleanup(__import__("shutil").rmtree, d, True)
        conf = os.path.join(d, "centinela.toml")
        open(conf, "w").write(conf_text + '\n[general]\nextra_dir = "%s"\n' % os.path.join(d, "checks.d"))
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = migrate.main(["--config", conf, *args])
        return code, out.getvalue(), err.getvalue(), d, conf

    def test_report_changes_nothing(self):
        code, out, _, d, conf = self.run_migrate("")
        self.assertEqual(code, 0)
        self.assertIn('required = ["fail2ban"]', out)
        self.assertIn("centinela migrate --write", out)
        self.assertIn("warn_free_gb = 0", out)
        self.assertFalse(os.path.exists(os.path.join(d, "centinela.d")))

    def test_write_adds_one_dropin_that_restores_the_old_behaviour(self):
        code, out, _, d, conf = self.run_migrate("", "--write")
        self.assertEqual(code, 0)
        before = open(conf).read()
        cfg = Config.load(conf)
        self.assertEqual((cfg.list("services", "required"), cfg.list("services", "watch")),
                         (["fail2ban"], ["nginx", "docker", "ssh"]))
        with mock.patch("shutil.which", return_value="/bin/systemctl"):
            self.assertTrue(services.applicable(cfg))
        self.assertEqual(open(conf).read(), before)  # the main config is never edited
        again = io.StringIO()
        with redirect_stdout(again), redirect_stderr(io.StringIO()):
            self.assertEqual(migrate.main(["--config", conf, "--write"]), 0)  # the drop-in now pins everything
        self.assertIn("Nothing to write", again.getvalue())

    def test_an_existing_dropin_is_never_overwritten(self):
        code, _, _, d, conf = self.run_migrate("")
        os.makedirs(os.path.join(d, "centinela.d"))
        target = os.path.join(d, "centinela.d", migrate.DROPIN)
        open(target, "w").write("# mine\n")
        err = io.StringIO()
        with redirect_stdout(io.StringIO()), redirect_stderr(err):
            self.assertEqual(migrate.main(["--config", conf, "--write"]), 2)
        self.assertEqual(open(target).read(), "# mine\n")
        self.assertIn("not overwriting", err.getvalue())

    def test_checks_that_would_now_be_refused_are_listed(self):
        with tempfile.TemporaryDirectory() as d:
            open(os.path.join(d, "mine.py"), "w").write(
                "def run(ctx):\n"
                "    ctx.run(['df', '-P'])\n"
                "    ctx.run(['rm', '-rf', '/var/cache/x'])\n"
                "    ctx.run(['docker', 'image', 'inspect'] + ids)\n"
                "    ctx.run(['docker', 'rm', name])\n"
                "    ctx.run(command)\n")
            refused, unchecked = migrate.scan_checks(d)
        self.assertEqual([(line, cmd) for _, line, cmd, _ in refused], [(3, "rm -rf /var/cache/x"), (5, "docker rm")])
        self.assertEqual(unchecked, 1)

    def test_a_refused_command_in_a_check_is_a_warning_not_a_silent_skip(self):
        class Mod:
            @staticmethod
            def run(ctx):
                raise Blocked("refused: rm can change or delete data")
        err = io.StringIO()
        with redirect_stderr(err):
            findings, evaluated = cli.run_modules({"mine": (Mod, "run")}, Ctx(Config()))
        self.assertEqual([(f.module, f.id, f.level) for f in findings], [("mine", "blocked", WARN)])
        self.assertIn("allow_dangerous_commands", findings[0].text)
        self.assertEqual(evaluated, set())  # not evaluated, so its old findings are not wiped from the state


class ChannelTests(unittest.TestCase):
    ENV = {"NTFY_URL": "https://ntfy.example/secret-topic", "NTFY_TOKEN": "tk_SECRET",
           "WEBHOOK_URL": "https://hooks.example/T0/SECRETPATH", "WEBHOOK_TOKEN": "wh_SECRET"}

    def sent(self, names, cfg=None, env=None):
        reqs = []
        with mock.patch.dict(os.environ, self.ENV if env is None else env, clear=True), \
                mock.patch("centinela.notify._open", side_effect=lambda r: reqs.append(r)):
            notify.deliver(names, ["hello"], cfg)
        return reqs

    def test_ntfy_sends_text_with_the_token_in_a_header_not_the_url(self):
        (req,) = self.sent(["ntfy"])
        self.assertEqual((req.full_url, req.data), ("https://ntfy.example/secret-topic", b"hello"))
        self.assertEqual(req.get_header("Authorization"), "Bearer tk_SECRET")
        self.assertNotIn("tk_SECRET", req.full_url)

    def test_webhook_field_is_configurable(self):
        (req,) = self.sent(["webhook"])
        self.assertEqual(json.loads(req.data), {"text": "hello"})
        (req,) = self.sent(["webhook"], Config.from_string('[notify.webhook]\nfield = "content"\n'))
        self.assertEqual(json.loads(req.data), {"content": "hello"})

    def test_plain_http_is_refused_except_on_loopback(self):
        env = dict(self.ENV, NTFY_URL="http://ntfy.example/t")
        with self.assertRaises(notify.NotifyError) as cm:
            self.sent(["ntfy"], env=env)
        self.assertIn("https", str(cm.exception))
        self.assertNotIn("tk_SECRET", str(cm.exception))
        self.sent(["ntfy"], env=dict(self.ENV, NTFY_URL="http://127.0.0.1:2586/t"))

    def test_errors_never_contain_urls_or_secrets(self):
        import urllib.error
        for exc in (urllib.error.HTTPError(self.ENV["NTFY_URL"], 401, "no", {}, None),
                    urllib.error.URLError("dns failure for " + self.ENV["NTFY_URL"])):
            with mock.patch.dict(os.environ, self.ENV, clear=True), \
                    mock.patch("centinela.notify._open", side_effect=exc), mock.patch("time.sleep"):
                with self.assertRaises(notify.NotifyError) as cm:
                    notify.deliver(["ntfy"], ["hi"])
            for secret in ("secret-topic", "tk_SECRET"):
                self.assertNotIn(secret, str(cm.exception))

    def test_redirects_are_not_followed(self):
        handler = notify._NoRedirect()
        req = urllib.request.Request("https://a.example/x", headers={"Authorization": "Bearer x"})
        self.assertIsNone(handler.redirect_request(req, None, 302, "Found", {}, "https://evil.example/"))

    def test_one_failing_channel_does_not_stop_the_other(self):
        env = {"NTFY_URL": self.ENV["NTFY_URL"]}  # telegram has no credentials at all
        err = io.StringIO()
        with redirect_stderr(err):
            reqs = self.sent(["telegram", "ntfy"], env=env)
        self.assertEqual(len(reqs), 1)
        self.assertIn("TELEGRAM_BOT_TOKEN", err.getvalue())

    def test_all_channels_failing_is_an_error(self):
        with self.assertRaises(notify.NotifyError) as cm:
            self.sent(["telegram", "ntfy"], env={})
        self.assertIn("telegram", str(cm.exception))
        self.assertIn("NTFY_URL", str(cm.exception))

    def test_unknown_channel_is_a_config_error(self):
        with tempfile.TemporaryDirectory() as d:
            conf = os.path.join(d, "c.toml")
            open(conf, "w").write('[general]\nenable = []\n[notify]\nchannels = ["pigeon"]\n')
            err = io.StringIO()
            with redirect_stderr(err):
                self.assertEqual(cli.main(["--config", conf, "--dry-run"]), 2)
        self.assertIn("pigeon", err.getvalue())

    def test_commands_do_not_inherit_any_channel_secret(self):
        with mock.patch.dict(os.environ, dict(self.ENV, PATH="/usr/bin"), clear=True):
            code, out, _ = Ctx(Config()).run([sys.executable, "-c", "import os; print(sorted(os.environ))"], unsafe=True)
        self.assertEqual(code, 0)
        for name in ("NTFY", "WEBHOOK", "TELEGRAM"):
            self.assertNotIn(name, out)


class ChildEnvTests(unittest.TestCase):
    def test_commands_do_not_inherit_the_notification_credentials(self):
        env = {"TELEGRAM_BOT_TOKEN": "secret", "TELEGRAM_CHAT_ID": "1", "PATH": "/usr/bin"}
        with mock.patch.dict(os.environ, env, clear=True):
            code, out, _ = Ctx(Config()).run([sys.executable, "-c", "import os; print(sorted(os.environ))"], unsafe=True)
        self.assertEqual(code, 0)
        self.assertNotIn("TELEGRAM", out)
        self.assertIn("PATH", out)


class ModulePlanTests(unittest.TestCase):
    def test_builtins_have_contract(self):
        mods = modules.discover(Config.from_string('[general]\nextra_dir = "/nonexistent"\n'))
        self.assertEqual(set(mods), {"apt", "restart", "nginx", "docker", "certbot", "disk", "units", "services", "firewall", "cve", "ports", "expect", "memory", "load"})
        for m in mods.values():
            self.assertTrue(callable(m.run) and m.DESC)


if __name__ == "__main__":
    unittest.main()
