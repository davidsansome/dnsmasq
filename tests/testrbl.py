import os
import select
import signal
import socket
import subprocess
import sys
import tempfile
import threading
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
txt-record=three.domain.com.blocklist.com,  white     space category3

txt-record=four.domain.com.blocklist.com,category1
txt-record=four.domain.com.blocklist.com,category2

address=/one.domain.com/1.1.1.1
address=/one.domain.com/fe80::1
address=/two.domain.com/2.2.2.2
address=/three.domain.com/3.3.3.3
address=/three.domain.com/fe80::3
address=/four.domain.com/4.4.4.4

mx-host=badsite.com,mail.badsite.com
mx-host=one.domain.com,mail.domain.com
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

    if sorted(expected) != sorted(stdout.splitlines()):
      self.read_logs()
      print self.logs

    self.assertEqual(sorted(expected), sorted(stdout.splitlines()))

  def clear_cache(self):
    for process in self.server_processes:
      os.kill(process.pid, signal.SIGHUP)

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

  def test_whitelist_v6(self):
    self.start("""
        rbl-blocked-target=1.2.3.4
        rbl-blocked-target=1.2.3.5
        rbl-blocked-target=fe80::1
        rbl-blocked-target=fe80::2
        rbl-blacklist=badsite.com
    """)

    self.assert_lookup("badsite.com", ["1.2.3.4", "1.2.3.5"])
    self.assert_lookup("badsite.com", ["fe80::1", "fe80::2"], type="AAAA")

  def test_category1(self):
    self.start("""
        rbl-blocked-target=1.2.3.4
        rbl-deny-category=category1
    """)

    self.assert_lookup("one.domain.com", ["1.2.3.4"])
    self.assert_log_contains("name one.domain.com is in a denied rbl category")
    self.assert_lookup("two.domain.com", ["1.2.3.4"])
    self.assert_log_contains("name two.domain.com is in a denied rbl category")
    self.assert_lookup("three.domain.com", ["3.3.3.3"])

  def test_category2(self):
    self.start("""
        rbl-blocked-target=1.2.3.4
        rbl-deny-category=category2
    """)

    self.assert_lookup("one.domain.com", ["1.1.1.1"])
    self.assert_lookup("two.domain.com", ["1.2.3.4"])
    self.assert_log_contains("name two.domain.com is in a denied rbl category")
    self.assert_lookup("three.domain.com", ["3.3.3.3"])

  def test_category3(self):
    self.start("""
        rbl-blocked-target=1.2.3.4
        rbl-deny-category=category3
    """)

    self.assert_lookup("one.domain.com", ["1.1.1.1"])
    self.assert_lookup("two.domain.com", ["1.2.3.4"])
    self.assert_log_contains("name two.domain.com is in a denied rbl category")
    self.assert_lookup("three.domain.com", ["1.2.3.4"])
    self.assert_log_contains("name three.domain.com is in a denied rbl category")

  def test_multiple_txt_records_1(self):
    self.start("""
        rbl-blocked-target=1.2.3.4
        rbl-deny-category=category1
    """)

    # Do 100 lookups because the order of returned TXT records might change
    for _ in xrange(100):
      self.assert_lookup("four.domain.com", ["1.2.3.4"])
      self.clear_cache()

  def test_multiple_txt_records_2(self):
    self.start("""
        rbl-blocked-target=1.2.3.4
        rbl-deny-category=category2
    """)

    # Do 100 lookups because the order of returned TXT records might change
    for _ in xrange(100):
      self.assert_lookup("four.domain.com", ["1.2.3.4"])
      self.clear_cache()

  def test_aaaa_1(self):
    self.start("""
        rbl-blocked-target=fe80::ffff
        rbl-deny-category=category1
    """)

    self.assert_lookup("one.domain.com", [], type="A")
    self.assert_lookup("one.domain.com", ["fe80::ffff"], type="AAAA")
    self.assert_lookup("three.domain.com", ["fe80::3"], type="AAAA")

  def test_aaaa_3(self):
    self.start("""
        rbl-blocked-target=fe80::ffff
        rbl-deny-category=category3
    """)

    self.assert_lookup("one.domain.com", ["fe80::1"], type="AAAA")
    self.assert_lookup("two.domain.com", ["fe80::ffff"], type="AAAA")
    self.assert_lookup("three.domain.com", ["fe80::ffff"], type="AAAA")

  def test_mx(self):
    self.start("""
        rbl-blocked-target=1.2.3.4
        rbl-blacklist=badsite.com
        rbl-deny-category=category1
    """)

    # MX lookups shouldn't be blocked
    self.assert_lookup("badsite.com", ["1 mail.badsite.com."], type="MX")
    self.assert_lookup("one.domain.com", ["1 mail.domain.com."], type="MX")

    # And we shouldn't even try to query the blocklist
    self.read_logs()
    self.assertFalse("blocklist.com" in self.logs)

  def test_default(self):
    self.start("""
        rbl-blocked-target=1.2.3.4
        rbl-default-action=deny
    """)

    # Hostnames that aren't categorised should be blocked
    self.assert_lookup("othersite.com", ["1.2.3.4"])
    self.assert_log_contains("name othersite.com is uncategorised")

    # Hostnames that are categorised, but don't match any rules should not be
    # blocked
    self.assert_lookup("one.domain.com", ["1.1.1.1"])

  def test_whitelisted_blocked(self):
    self.start("""
        rbl-blocked-target=1.2.3.4
        rbl-whitelist=one.domain.com
        rbl-deny-category=category1
    """)

    # Whitelist should override deny categories
    self.assert_lookup("one.domain.com", ["1.1.1.1"])
    self.assert_lookup("two.domain.com", ["1.2.3.4"])

  def test_whitelisted_blacklist(self):
    self.start("""
        rbl-blocked-target=1.2.3.4
        rbl-whitelist=one.domain.com
        rbl-blacklist=one.domain.com
    """)

    # Whitelist should override blacklist
    self.assert_lookup("one.domain.com", ["1.1.1.1"])

  def test_target_self(self):
    self.start("""
        rbl-blocked-target=self
        rbl-blacklist=badsite.com
    """)

    self.assert_lookup("badsite.com", ["127.0.0.1"])

  def test_txt_nxdomain_caching(self):
    self.start("""
        rbl-blocked-target=1.2.3.4
        server=/blocklist.com/127.0.0.1#5303
    """)

    # dnsmasq won't return authoritive NXDOMAINs for entries we set with
    # --address, so start another DNS server written in python.
    stop = False
    def thread_main():
      sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
      sock.bind(("127.0.0.1", 5303))
      sock.settimeout(0.1)
      while not stop:
        try:
          (query, address) = sock.recvfrom(4096)
        except socket.timeout:
          pass
        else:
          if query:
            # Same ID and questions section as the query but with nxdomain flags
            response = query[0:2] + "\x81\x83" + query[4:]
            sock.sendto(response, address)

    thread = threading.Thread(target=thread_main)
    thread.start()

    try:
      self.assert_lookup("one.domain.com", ["1.1.1.1"])
      self.assert_log_contains("forwarded one.domain.com.blocklist.com to ")
      self.assert_log_contains("reply one.domain.com.blocklist.com is NXDOMAIN", read=False)

      self.assert_lookup("one.domain.com", ["1.1.1.1"])
      self.assert_log_contains("cached one.domain.com.blocklist.com is NXDOMAIN")
    finally:
      stop = True
      thread.join()


if __name__ == "__main__":
  sys.argv.append("-v")
  unittest.main()