getmail-daemon
==============

Wrapper for the getmail utility which uses the idle feature to be
notified of new messages as they arrive, fetching them with getmail:

* http://pyropus.ca/software/getmail/

Setup
-----

Python venv is used for the required packages so there's a small
amount of setup needed, along with a wrapper shell script to source
them.

```
cp init.d/getmail-daemon /etc/init.d/
cp getmail.sh /usr/sbin/getmail-daemon-venv
cp getmail.py /usr/sbin/getmail-daemon
cp config.example /etc/getmail-daemon.conf
cp requirements.txt to /root
cd /root
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
service getmail-daemon start
```
