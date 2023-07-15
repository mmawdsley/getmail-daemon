#!/usr/bin/env python
# -*- coding: utf-8 -*-

import ConfigParser
import os
import signal
import syslog

from subprocess import Popen
from datetime import datetime, timedelta
from time import sleep
from threading import Thread

class Getmail ():

  def __init__ (self):

    self._config_path = "/etc/getmail-daemon.conf"
    self._running = False
    self._threads = []

    self._setup_signal_handlers ()
    self._load_config ()


  def start (self):
    """Starts the class, returning when all of the threads have stopped"""

    self._running = True

    for thread in self._threads:
      thread.start ()

    while self._running == True:
      sleep (1)

    for thread in self._threads:
      thread.join ()


  def exit (self):
    """Stops the class"""

    self._running = False


  def _load_config (self):
    """Loads in the configuration"""

    parser = ConfigParser.ConfigParser ()
    parser.read (self._config_path)

    for section in parser.sections ():

      try:

        user = parser.get (section, "user")
        config = parser.get (section, "config")
        interval = parser.getint (section, "interval")
        limit = parser.getint (section, "limit")

        self._setup_account (user, config, interval, limit)

      except:

        pass


  def _setup_signal_handlers (self):
    """Sets up the signal handlers"""

    signal.signal (signal.SIGINT, self._signal_handler)
    signal.signal (signal.SIGTERM, self._signal_handler)


  def _signal_handler (self, signum, frame):
    """Handles signals sent to this process"""

    self.exit ()


  def _setup_account (self, user, config, interval, limit):
    """Creates the thread for an account"""

    config_dir = os.path.dirname (config)
    config_name = os.path.basename (config)
    lock_path = "%s.lock" % os.path.splitext (config)[0]

    command = [
      "/usr/bin/sudo", "-u", user, "-H", "/usr/bin/setlock", "-n", lock_path,
      "/usr/bin/getmail", "--getmaildir", config_dir, "--rcfile", config_name
    ]

    t = Thread (None, self._account_handler, None, [command, interval, limit])

    self._threads.append (t)


  def _account_handler (self, command, interval, limit):
    """Fetches email for this account at the given interval"""

    delta = timedelta (minutes=interval)

    while self._running == True:

      self._run_command (command, limit)
      end = datetime.now () + delta

      while datetime.now () < end:

        if self._running == False:
          return

        sleep (1)


  def _run_command (self, command, limit):
    """Runs the command killing it if it exceeds the limit"""

    end = datetime.now () + timedelta (minutes=limit)
    p = Popen (command, preexec_fn=os.setsid)

    while True:

      if p.poll () is not None:
        return

      if datetime.now () > end:
        os.killpg (p.pid, signal.SIGTERM)
        self._log_kill (p.pid, command, limit)
        return

      sleep (1)


  def _log_kill (self, pid, command, limit):
    """Logs that a process was killed"""

    message = "Killed process %d after %d minutes (%s)" % (pid, limit, " ".join (command))
    syslog.syslog (syslog.LOG_ERR, message)


if __name__ == "__main__":

  getmail = Getmail ()

  try:
    getmail.start ()
  except KeyboardInterrupt:
    getmail.exit ()
