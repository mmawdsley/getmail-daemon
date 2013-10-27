#!/usr/bin/env python
# -*- coding: utf-8 -*-

import signal

from subprocess import Popen
from datetime import datetime, timedelta
from time import sleep
from threading import Thread

class Getmail ():

  def __init__ (self):

    self._config_dir = "/home/mmawdsley/.getmail"
    self._running = False
    self._threads = {}
    self._accounts = {
      "blueyonder" : { "interval" : 2, "limit" : 10 },
      "hallnet" : { "interval" : 1, "limit" : 10 },
      "gmail" : { "interval" : 5, "limit" : 10 }
    }

    self._setup_signal_handlers ()

    for account in self._accounts:
      self._setup_account_thread (account)


  def start (self):
    """Starts the class, returning when all of the threads have stopped"""

    self._running = True

    for thread in self._threads:
      self._threads[thread].start ()

    while self._running == True:
      sleep (1)

    for thread in self._threads:
      self._threads[thread].join ()


  def exit (self):
    """Stops the class"""

    self._running = False


  def _setup_signal_handlers (self):
    """Sets up the signal handlers"""

    signal.signal (signal.SIGINT, self._signal_handler)
    signal.signal (signal.SIGTERM, self._signal_handler)


  def _signal_handler (self, signum, frame):
    """Handles signals sent to this process"""

    self.exit ()


  def _setup_account_thread (self, account):
    """Sets up the thread for an account"""

    settings = self._accounts[account]

    lock_path = "%s/%s.lock" % (self._config_dir, account)
    config_file = "%s.rc" % account

    command = ["/usr/bin/setlock", "-n", lock_path, "/usr/bin/getmail", "--getmaildir", self._config_dir, "--rcfile", config_file]

    self._threads[account] = Thread (None, self._account_handler, None, [command, settings["interval"], settings["limit"]])


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
    p = Popen (command)

    while True:

      if p.poll () is not None:
        return

      if self._running == False or datetime.now () > end:
        p.kill ()
        return

      sleep (1)


if __name__ == "__main__":

  getmail = Getmail ()

  try:
    getmail.start ()
  except KeyboardInterrupt:
    getmail.exit ()
