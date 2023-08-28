#!/usr/bin/env python
# -*- coding: utf-8 -*-

from configparser import ConfigParser
import os
import signal
import syslog
import imaplib
import sys
import ssl
import logging

from logging.handlers import SysLogHandler
from argparse import ArgumentParser
from imapclient import IMAPClient
from subprocess import Popen
from datetime import datetime, timedelta
from time import sleep
from threading import Thread

logger = None

def main():
  parser = ArgumentParser()
  parser.add_argument("--config")
  parser.add_argument("--debug", action="store_true")

  args = parser.parse_args();

  level = logging.INFO if args.debug else logging.WARNING

  logger = GetmailLogger(level)
  getmail = Getmail(args.config)

  try:
    getmail.start()
  except KeyboardInterrupt:
    getmail.exit()

class GetmailLogger(object):
  """Wrapper for the logger service."""

  def __init__(self, level):
    self._pid = os.getpid()
    self._logger = self._build_logger(level)

  def error(self, msg):
    """Log an error message."""
    self._logger.error(self._format(msg))

  def info(self, msg):
    """Log an info message."""
    self._logger.info(self._format(msg))

  def debug(self, msg):
    """Log an debug message."""
    self._logger.debug(self._format(msg))

  def _build_logger(self, level):
    """Return a logger with the syslog handler."""

    handler = SysLogHandler(
      facility=SysLogHandler.LOG_DAEMON,
      address="/dev/log"
    )

    logger = logging.getLogger("getmail")
    logger.setLevel(level)
    logger.addHandler(handler)

    return logger

  def _format(self, msg):
    return "getmail[%d] %s" % (self._pid, msg)

class GetmailAccount(object):
  """Connects to an IMAP server and idles a mailbox to query the number of unseen messages."""

  def __init__(self, name, user, config_path, limit):
    self.name = name
    self._user = user
    self._limit = limit
    self._server = None
    self._username = None
    self._password = None
    self._command = None
    self._connection = None

    self._load_config(config_path)

  def disconnect(self):
    """Disconnect from the IMAP server"""

    logger.debug("Disconnecting %s" % self.name)

    if self._connection:
      try:
        self._connection.logout()
      except imaplib.IMAP4.error as err:
        logger.error("Logout threw error {0}".format(err))

      self._connection = None

  def idle(self, timeout):
    """Idle the mailbox"""

    logger.debug("Idling %s" % self.name)

    connection = self._get_connection()
    connection.idle()
    connection.idle_check(timeout=timeout)
    connection.idle_done()

  def get_count(self):
    """Return the number of unseen emails"""

    logger.debug("Getting count for %s" % self.name)

    connection = self._get_connection()
    status = connection.folder_status("INBOX", 'UNSEEN')

    return status[b'UNSEEN']

  def fetch(self):
    """Fetch the emails for the account"""
    logger.debug("Fetching emails for %s" % self.name)

    end = datetime.now() + timedelta(minutes=self._limit)
    p = Popen(self._command)

    while True:
      if p.poll() is not None:
        return

      if datetime.now() > end:
        os.killpg(p.pid, signal.SIGTERM)
        self._log_kill(p.pid)
        return

      sleep(1)

  def _connect(self):
    """Connect to the IMAP server"""
    logger.debug("Connecting %s" % self.name)

    context = ssl._create_unverified_context()

    self._connection = IMAPClient(host=self._server, ssl_context=context)
    self._connection.login(self._username, self._password)
    self._connection.select_folder("INBOX", readonly=True)

    return self._connection

  def _get_connection(self):
    """Return a connection to the IMAP server, creating it if needed"""

    return self._connection if self._connection else self._connect()

  def _log_kill(self, pid):
    """Logs that a process was killed"""

    message = "Killed process %d after %d minutes (%s)" % (pid, self._limit, " ".join(self._command))
    syslog.syslog(syslog.LOG_ERR, message)

  def _load_config(self, config_path):
    """Load in the IMAP configuration from the given path."""

    logger.debug("Loading IMAP configuration for %s" % self.name)

    config_dir = os.path.dirname(config_path)
    config_name = os.path.basename(config_path)
    lock_path = "%s.lock" % os.path.splitext(config_path)[0]

    parser = ConfigParser()
    parser.read(config_path)

    self._server = parser['retriever']['server']
    self._username = parser['retriever']['username']
    self._password = parser['retriever']['password']
    self._command = [
      "/usr/bin/sudo",
      "-u",
      self._user,
      "-H",
      "/usr/bin/setlock",
      "-n",
      lock_path,
      "/usr/bin/getmail",
      "--getmaildir",
      config_dir,
      "--rcfile",
      config_name
    ]

class Getmail(object):
  """Connects to multiple IMAP mailboxes to immediately fetch new emails when they arrive."""

  def __init__(self, config = None):
    self._config_path = config if config else "/etc/getmail-daemon.conf"
    self._running = False
    self._threads = []
    self._timeout = 30
    self._accounts = {}
    self._max_delay = 60

    self._setup_signal_handlers()
    self._load_config()

  def start(self):
    """Starts the class, returning when all of the threads have stopped"""

    self._running = True

    for thread in self._threads:
      thread.start()

    while self._running == True:
      sleep(1)

    for thread in self._threads:
      thread.join()

  def exit(self):
    """Stops the class"""

    logger.debug("Exiting...")
    self._running = False

  def _load_config(self):
    """Loads in the configuration"""

    logger.debug("Loading configuration from %s" % self._config_path)

    parser = ConfigParser()
    files = parser.read(self._config_path)


    for section in parser.sections():
      logger.debug("Loaded section %s" % section)

      try:
        user = parser.get(section, "user")
        config = parser.get(section, "config")
        limit = parser.getint(section, "limit")
      except:
        err = sys.exc_info()[0]
        logger.error("Error when setting up account", err)
        continue

      logger.debug("Creating account %s" % section)
      account = GetmailAccount(section, user, config, limit)
      logger.debug("Created account %s" % section)

      thread = Thread(target=self._idle_wrapper, args=(account,))
      self._threads.append(thread)

  def _setup_signal_handlers(self):
    """Sets up the signal handlers"""

    signal.signal(signal.SIGINT, self._signal_handler)
    signal.signal(signal.SIGTERM, self._signal_handler)

  def _signal_handler(self, signum, frame):
    """Handles signals sent to this process"""

    logger.debug("signal handler called")
    self.exit()

  def _idle_wrapper(self, account):
    """Wrapper for the idle method"""
    logger.debug("_idle_wrapper %s" % account.name)

    delay = 2

    while self._running:
      try:
        self._idle(account)
        delay = 2
      except (ConnectionResetError, TimeoutError, imaplib.IMAP4.abort) as err:
        logger.error("Caught {0}".format(err))
        account.disconnect()
        delay = min(delay * 2, self._max_delay)
        logger.info("Caught IMAP error, sleeping for %d" % delay)
        sleep(delay)
      except Exception as err:
        logger.error(err)
        logger.error("Caught exception {0}".format(err))
        self.exit()
      except:
        err = sys.exc_info()[0]
        logger.error("Caught something else {0}".format(err))
        self.exit()

    logger.debug("%s idle wrapper closing" % account.name)

  def _idle(self, account):
    """Idles the mailbox, updating the count on change"""
    logger.debug("_idle %s" % account.name)
    self._update_count(account)

    while self._running:
      logger.debug("Idling %s..." % account.name)
      account.idle(self._timeout)

      self._update_count(account)

    account.disconnect()

  def _update_count(self, account):
    """Update the message count"""
    logger.debug("Updating count for %s" % account.name)
    count = account.get_count()
    logger.debug("Count is %d" % count)

    if count > 0 and self._running:
      logger.debug("Have new messages, fetching")
      account.fetch()

if __name__ == "__main__":
  main()
