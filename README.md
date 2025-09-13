# Blue-Team
Bash Scripts and Python Files used for blue teaming

-------------------
# service_harden.sh
Kill undesired services and processes. Modify via indicators.txt keep.txt and hashes.txt to tailor to needs.
-------------------

-----
Sample indicators.txt:
nc
ncat
bash -i
sh -i
perl -e
python -c
ruby -e
socat
wget
curl
pwncat
reversecat
pspy64
pspy32
weevely
meterpreter
/tmp/
/var/tmp/
/dev/shm/
/etc/rc.local
cron
systemd
-----

-------------------
# initial_hardening.sh
-------------------
Tailored to debian and fedora individually. Harden your service immediately by killing low-hanging fruits.

REMEMBER TO SPECIFY USER AND OTHER VARS BEFORE RUNNING. 

