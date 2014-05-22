## Kippo
_Kippo is a medium interaction SSH honeypot designed to log brute force attacks and, most importantly, the entire shell interaction performed by the attacker._

Original Homepage: <https://code.google.com/p/kippo/>.


## Fork
This is a **personal public fork** of Kippo, which includes additional features as well as modifications to decrease the chances of fingerprinting the honeypot.

This is based on "Kippo Honeypot v0.8 ([svn r248 - 2014-05-19](https://code.google.com/p/kippo/source/browse/trunk?r=248))".


-----


## (Required) Quick Setup
Tested on Debian 7 stable.

```bash
apt-get update
apt-get -y install openssl  python python-dev python-openssl python-pyasn1 python-twisted  git
git clone git://github.com/g0tmi1k/kippo.git /opt/kippo/
cp -n /opt/kippo/kippo.cfg{.dist,}
chown -R nobody\:nogroup /opt/kippo/
su nobody -c '/bin/bash /opt/kippo/start.sh'
```


## (Recommend) Port 22
It is possibly to use "iptables" and redirect the traffic to port TCP 2222 (Kippo's default port) or... use "authbind" to allow non-privileged the non-user (nobody) to use the privileged port TCP 22 (default SSH port).

```bash
apt-get -y install authbind
touch /etc/authbind/byport/22
chown nobody\:nogroup /etc/authbind/byport/22
chmod 0777 /etc/authbind/byport/22
sed -i 's/^twistd /authbind --deep twistd /' /opt/kippo/start.sh
sed -i 's/^ssh_port = .*/ssh_port = 22/' /opt/kippo/kippo.cfg
[ -e /opt/kippo/kippo.pid ] && kill $(cat /opt/kippo/kippo.pid) && sleep 2
su nobody -c '/bin/bash /opt/kippo/start.sh'
```
_...Don't forget about altering the "real" ssh port before hand!._

```bash
sed -i 's/^Port .*/Port 222/' /etc/ssh/sshd_config
service ssh restart
```


## (Optional) Unique Customization
Some suggestions on how to extend the customization, making the instant unique _(therefore less chance of detection)_.

### Hostname

```
...
hostname = uniquehostname
...
```
_File: `./kippo.cfg`_

-----

```
uniquehostname
```
_File: `./honeyfs/etc/hostname`_

-----

```
...
127.0.0.1    uniquehostname
....
```
_File: `./honeyfs/etc/hosts`_

### SSH Version

```bash
...
ssh_version_string = SSH-2.0-OpenSSH_6.0p1 Debian-4
...
```
_File: `./kippo.cfg`_

### SSH Banner

```
*************************************************************
*        All connections are monitored and recorded.        *
* Disconnect IMMEDIATELY if you are not an authorized user! *
*************************************************************
```
_File: `./honeyfs/etc/issue.net`_

### Add Addiontal Honeypot Credentials
This will add "`Password1`" to the accepted password list.

 _Note: Adding "*" will accept any password submitted._

```bash
cd /opt/kippo/ && python utils/passdb.py data/pass.db add Password1
```

### Adding fake "loot"
The following command will generate a "fake" file in `/root/accounts.zip.enc` _(which is 7mb)_.

```bash
dd if=/dev/urandom of=honeyfs/root/accounts.zip.enc bs=1M count=7
```

### Other
These are only some suggestions - feel free to alter the honeypot however you wish!


-----


## "Tell-tale signs" Of The Honeypot
Kippo is a "simulated environment". The attackers are placed in a "controlled jail", which will only response to commands/files that have been pre-defined (aka whitelisted). As a result, this can let it down, for example:

+ Missing core commands - Kippo simulates various "common" commands, however, if the attacker uses a "uncommon" command or ask for a unregistered response _(when it should be there by default)_, it will report "command not found" or give an incorrect response.
+ Timestamp on log files - some of the log files are "static" and will not update with the date or the actions of the attacker.
+ ...Various other issues.

Kippo is far from "perfect" and can be easily identified by an experienced attacker. However, this could confuse or even trick an amateur attacker into believing it real. As a result Kippo **will indicate if someone is somewhere they shouldn't be** (aka an early warning system) - _plus it is fun to watch the replays back ;)._


-----


## Warnings & Legal
Do not use if you do not accept the risks. The author(s) cannot be held responsible for the use of this program, including for any possible data loss and/or damages.

This code has been designed and created to invite unauthorized users into the system and the network in which it is been executed on. As a result, they may perform malicious actions on your device(s).

The code itself _(e.g. the wget command)_ can be used to connect to services that may or may not be public exposed. Also there are various "DoS" vulnerabilities due to there being no limitations when accessing resources. The code itself also has not been through a security audit.

If you are going to use it, it is highly recommend that you run this on a secure, up-to-date, insolated machine that does not contain any sensitive information as well as being separated from the rest of the network (e.g. DMZ zone).
