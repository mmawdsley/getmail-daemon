getmail-daemon
==============

Wrapper for the getmail utility which periodically runs multiple configurations, killing processes if they hang for too long.

* http://pyropus.ca/software/getmail/

Setup
-----

* Copy the init.d/getmail-daemon script into /etc/init.d
* Copy getmail.py to /usr/sbin/getmail-daemon
* Copy config.example to /etc/getmail-daemon.conf and add your configuration
* Run "service getmail-wrapper start" to start
