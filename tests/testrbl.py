import os
import select
import subprocess
import sys
import tempfile
import time
import unittest

BASE_CONFIG = """
port=5301
no-daemon
log-queries

no-resolv
no-hosts

server=127.0.0.1#5302
rbl-suffix=blocklist.com
"""

UPSTREAM_CONFIG = """
port=5302
no-daemon
log-queries

no-resolv
no-hosts

address=/goodsite.com/1.1.1.1
address=/goodsite2.com/2.2.2.2
address=/badsite.com/3.3.3.3
address=/badsite.com/4.4.4.4
address=/badpart.goodsite.com/5.5.5.5

txt-record=one.domain.com.blocklist.com,category1
txt-record=two.domain.com.blocklist.com,category1 category2 category3
txt-record=three.domain.com.blocklist.com,  white     space
"""


class RblTest(unittest.TestCase):
  def setUp(self):
    self.server_processes = []
    self.logs = ""

  def tearDown(self):
    for process in self.server_processes:
      process.terminate()
      process.wait()

  def start(self, config):
    self.config_file = tempfile.NamedTemporaryFile()
    self.config_file.write(BASE_CONFIG + config)
    self.config_file.flush()

    self.upstream_config_file = tempfile.NamedTemporaryFile()
    self.upstream_config_file.write(UPSTREAM_CONFIG)
    self.upstream_config_file.flush()

    self.start_server(self.upstream_config_file.name)
    self.process = self.start_server(self.config_file.name)

  def start_server(self, config_file):
    dnsmasq_path = os.path.join(os.path.dirname(__file__), "../src/dnsmasq")
    handle = subprocess.Popen([dnsmasq_path, "-C", config_file],
        stderr=subprocess.PIPE)
    self.server_processes.append(handle)
    return handle

  def read_logs(self):
    time.sleep(0.1)
    poll = select.poll()
    poll.register(self.process.stderr.fileno())

    self.logs = ""
    while True:
      ret = poll.poll(0)
      if not ret:
        break

      if ret[0][1] & select.POLLIN:
        self.logs += os.read(self.process.stderr.fileno(), 4096)

      if ret[0][1] & select.POLLHUP:
        break

  def assert_log_contains(self, expected, read=True):
    if read:
      self.read_logs()

    if expected in self.logs:
      return

    self.fail("Expected string '%s' not found in log.  Complete log:\n%s" % (
      expected, self.logs))

  def assert_lookup(self, name, expected, type="A"):
    handle = subprocess.Popen([
      "dig", "+short", "@127.0.0.1", "-p5301", name, type],
      stdout=subprocess.PIPE)
    stdout = handle.communicate()[0]

    self.assertEqual(expected, stdout.splitlines())

  def test_whitelist(self):
    self.start("""
        rbl-blocked-target=1.2.3.4
        rbl-whitelist=goodsite.com
        rbl-blacklist=badsite.com
        rbl-blacklist=badpart.goodsite.com
    """)

    self.assert_lookup("goodsite.com", ["1.1.1.1"])
    self.assert_log_contains("name goodsite.com is whitelisted by rbl")

    self.assert_lookup("badsite.com", ["1.2.3.4"])
    self.assert_log_contains("name badsite.com is blacklisted by rbl")

    # Allowed because whitelists are done first
    self.assert_lookup("badpart.goodsite.com", ["5.5.5.5"])
    self.assert_log_contains("name badpart.goodsite.com is whitelisted by rbl")


if __name__ == "__main__":
  unittest.main()