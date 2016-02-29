# NT LAN Manager (NTLM)

http://davenport.sourceforge.net/ntlm.html#whatIsNtlm

NTLM is a suite of authentication and session security protocols used in various Microsoft network protocol implementations.
NTLM has been largely supplanted by Kerberos as the authentication protocol of choice for domain-based scenarios.

The NTLM Security Support Provider provides these core operations:
- Auth https://msdn.microsoft.com/en-us/library/windows/desktop/aa378749(v=vs.85).aspx
- Signing (integrity)
- Sealing(encryption)

# KERBEROS

https://msdn.microsoft.com/en-us/library/windows/desktop/aa378747(v=vs.85).aspx

The Kerberos protocol makes use of:
- Key authentication
- Authenticator messages
- Key distribution
- Session tickets
- Ticket-granting tickets

http://www.tldp.org/HOWTO/html_single/Kerberos-Infrastructure-HOWTO/

In Fedora Core based GNU/Linux, the packages required to provide Kerberos service are:
krb5-server, krb5-libs


https://technet.microsoft.com/en-us/library/cc780469(v=ws.10).aspx

Active Directory is required for default NTLM and Kerberos implementations.
The Kerberos V5 protocol became the default authentication package with Windows 2000.
The Kerberos V5 protocol is more secure, more flexible, and more efficient than NTLM:
- Delegated authentication
- Interoperability
- More efficient authentication to servers
- Mutual authentication

## Component	Description

- Kerberos.dll	The SSP that implements an industry-standard protocol that is used with either a password or a smart card for interactive logon. It is also the preferred authentication method for services in Windows 2000 and Windows Server 2003.
- Kdcsvc.dll	The Kerberos Key Distribution Center (KDC) service, which is responsible for providing ticket-granting tickets to clients.
- Ksecdd.sys	The Kernel Security Device Driver is used to communicate with LSASS in user mode.
- Lsasrv.dll	The LSA Server service, which both enforces security policies and acts as the security package manager for the LSA.
- Secur32.dll	The Secur32.dll component is the multiple authentication provider that implements SSPI for user mode applications.

http://blogs.technet.com/b/srd/archive/2014/11/18/additional-information-about-cve-2014-6324.aspx

https://github.com/bidord/pykek

CVE-2014-6324 Kerberos privilege elevation vulnerability


MIT Kerberos

http://web.mit.edu/kerberos/

```
10:40 $ yum search krb5
================================================== N/S matched: krb5 ==================================================
samba-winbind-krb5-locator.x86_64 : Samba winbind krb5 locator
freeradius-krb5.x86_64 : Kerberos 5 support for freeradius
krb5-appl-clients.x86_64 : Kerberos-aware telnet, ftp, rcp, rsh and rlogin clients
krb5-appl-servers.x86_64 : Kerberos-aware telnet, ftp, rcp, rsh and rlogin servers
krb5-devel.x86_64 : Development files needed to compile Kerberos 5 programs
krb5-devel.i686 : Development files needed to compile Kerberos 5 programs
krb5-libs.x86_64 : The shared libraries used by Kerberos 5
krb5-libs.i686 : The shared libraries used by Kerberos 5
krb5-pkinit.x86_64 : The PKINIT module for Kerberos 5
krb5-server.x86_64 : The KDC and related programs for Kerberos 5
krb5-server-ldap.x86_64 : The LDAP storage plugin for the Kerberos 5 KDC
krb5-workstation.x86_64 : Kerberos 5 programs for use on workstations
pam_krb5.i686 : A Pluggable Authentication Module for Kerberos 5
pam_krb5.x86_64 : A Pluggable Authentication Module for Kerberos 5
php-pecl-krb5.x86_64 : Kerberos authentification extension
php-pecl-krb5-devel.x86_64 : Kerberos extension developer files (header)
root-net-krb5.x86_64 : Kerberos (version 5) extension for ROOT
sssd-krb5.x86_64 : The Kerberos authentication back end for the SSSD
sssd-krb5-common.i686 : SSSD helpers needed for Kerberos and GSSAPI authentication
sssd-krb5-common.x86_64 : SSSD helpers needed for Kerberos and GSSAPI authentication
```

```
WSManFault
    Message = WinRM cannot process the request. The following error occurred while using Kerberos authentication: The computer niroy64-cent7x-01 is unknown to Kerberos. Verify that the computer exists on the network, that the name provided is spelled correctly, and that the Kerberos configuration for accessing the computer is correct. The most common Kerberos configuration issue is that an SPN with the format HTTP/niroy64-cent7x-01 is not configured for the target. If Kerberos is not required, specify the Negotiate authentication mechanism and resubmit the operation.

Error number:  -2147024843 0x80070035
The network path was not found.
```

## Kerberos Network components

AD domain:
redmond.corp.microsoft.com

Domain controller:
C:\Users\niroy>echo %LOGONSERVER%
\\CO1-RED-DC-02
co1-red-dc-02.redmond.corp.microsoft.com
IP : 10.222.116.15

Linux host:
niroy64-cent7x-01
niroy64-cent7x-01.scx.com
IP : 10.123.174.26

Windows host:
NIROY-PC1.redmond.corp.microsoft.com
10.123.174.150
fe80::3845:90d0:64ad:14de%4

##Concepts

http://publib.boulder.ibm.com/tividd/td/framework/GC32-0803-00/en_US/HTML/plan20.htm

A Kerberos realm is a set of managed nodes that share the same Kerberos database. The Kerberos database resides on the Kerberos master computer system, which should be kept in a physically secure room. A read-only copy of the Kerberos database might also reside on other Kerberos computer systems. However, all changes to the database must be made on the master computer system. Changing or accessing the contents of a Kerberos database requires the Kerberos master password.

A Kerberos principal is a service or user that is known to the Kerberos system. Each Kerberos principal is identified by its principal name. Principal names consist of three parts: a service or user name, an instance name, and a realm name in the following form:

principal-name.instance-name@realm-name
For example, a principal name could describe the authorization role the user has in a particular realm, such as joe.user@realm1 for a user principal. A principal name can also describe the location of a service on a computer system, for example, ftp.host1@realm2 for a service principal. The instance part of the principal name is optional but is useful for identifying the computer system on which a service resides. Kerberos considers identical services on different computer systems to be different service principals.

Each principal has a principal password, which Kerberos uses during its authentication process to authenticate services and users to each other. With Kerberos, a principal on one computer system in a network can talk to a principal on another computer system in the network with confidence, knowing that the service or user is what or who it says it is.

For each computer system that is part of the Kerberos realm, the ext_srvtab command creates the srvtab file in the /etc directory. This file contains information that relates to service or user principals that have an instance on the computer system. If no service or user principals are on a computer system, the srvtab file is empty.

When a user logs in as a Kerberos principal, Kerberos assigns the user a ticket. Each ticket has a lifetime, which determines the length of time for which the ticket is valid. When a ticket expires, the principal is no longer trusted and is unable to perform additional work until a new ticket has been acquired.

http://www.cmf.nrl.navy.mil/krb/kerberos-faq.html
Kerberos 5 principals are written in a slightly different format:
component/component/component@realm

In practice a Kerberos realm is named by uppercasing the DNS domain name associated with the hosts in the to-be named realm. In other words, if your hosts are all in the foo.org domain, you might call your Kerberos realm FOO.ORG.

TGT is the acronym for a "Ticket Granting Ticket".
TGS is the acronym for the "Ticket Granting Service".
When a user first authenticates to Kerberos, he talks to the Authentication Service on the KDC to get a Ticket Granting Ticket. This ticket is encrypted with the user's password.
The reason the Ticket Granting Ticket exists is so a user doesn't have to enter in their password every time they wish to connect to a Kerberized service or keep a copy of their password around. If the Ticket Granting Ticket is compromised, an attacker can only masquerade as a user until the ticket expires.

In Kerberos, all authentication takes place between clients and servers. So in Kerberos termology, a "Kerberos client" is any entity that gets a service ticket for a Kerberos service. A client is typically a user, but any principal can be a client

The term "Kerberos server" generally refers to the Key Distribution Center, or the KDC


## Call stack to Wsman

```
#0  _HttpProcessRequest (selfCD=0xceacc8, headers=0xd14a50, page=0xd14368) at wsman.c:4119
#1  0x000000000040efca in _InteractionWsman_Transport_ProcessRequest (self_=0xceacc8) at wsman.c:3531
#2  0x00000000004769f0 in _StrandMethod_Aux0 (self=0xceacc8) at strand.c:761
#3  0x000000000047be8d in _Strand_ExecuteLoop (self=0xceacc8, state=1048577) at strand.c:2888
\#4  0x000000000047cfc1 in _Strand_ScheduleImp (self=0xceacc8, methodBit=256, allowMultiSchedule=0 '\000',
    fromStrand=0x0, entryOperationBit=0) at strand.c:3050
#5  0x0000000000475c81 in _StrandInteraction_Left_Post (interaction=0xcead18, msg=0xd149f0) at strand.c:416
#6  0x0000000000421b19 in _Strand_PostAndLeaveStrand_Imp (strand=0xd141c8, info=0xd14218, msg=0xd149f0)
    at ../base/Strand.h:570
#7  0x0000000000421bf7 in Strand_PostAndLeaveStrand (strand=0xd141c8, msg=0xd149f0) at ../base/Strand.h:1076
#8  0x000000000042492f in _HttpSocket_Aux_NewRequest (self_=0xd141c8) at http.c:1194
#9  0x00000000004769f0 in _StrandMethod_Aux0 (self=0xd141c8) at strand.c:761
#10 0x000000000047be8d in _Strand_ExecuteLoop (self=0xd141c8, state=4097) at strand.c:2888
#11 0x000000000047cfc1 in _Strand_ScheduleImp (self=0xd141c8, methodBit=4096, allowMultiSchedule=0 '\000',
    fromStrand=0x0, entryOperationBit=0) at strand.c:3050
#12 0x0000000000421f49 in Strand_ScheduleAux (self=0xd141c8, auxMethodNumber=0) at ../base/Strand.h:1748
#13 0x0000000000423aa4 in _ReadData (handler=0xd141c8) at http.c:748
#14 0x0000000000423b37 in _RequestCallbackRead (handler=0xd141c8) at http.c:767
#15 0x00000000004240ed in _RequestCallback (sel=0x6e1ab0 <s_data+2448>, handlerIn=0xd14250, mask=2,
    currentTimeUsec=1456776425586914) at http.c:983
#16 0x00000000004845b6 in Selector_Run (self=0x6e1ab0 <s_data+2448>, timeoutUsec=1000000, noReadsMode=0 '\000')
    at ../sock/selector.c:1063
#17 0x000000000042a602 in Protocol_Run (self=0xcded08, timeoutUsec=1000000) at protocol.c:1919
#18 0x0000000000406a56 in servermain (argc=1, argv=0x7fff9a9aef68) at server.c:1208
#19 0x0000000000406d24 in main (argc=2, argv=0x7fff9a9aef68) at servermain.c:42
```

## Usefull breakpoints for protocol info

```
(gdb) info b
Num     Type           Disp Enb Address            What
1       breakpoint     keep y   0x000000000040fcb3 in _HttpProcessRequest at wsman.c:4119
        breakpoint already hit 1 time
2       breakpoint     keep y   0x00000000004240e1 in _RequestCallback at http.c:983
        breakpoint already hit 14 times
```

# Commands from Windows to OMI

## Using WinRM

`$ winrm e http://schemas.microsoft.com/wbem/wscim/1/cim-schema/2/SCX_operatingsystem?__cimnamespace=root/scx -r:https://niroy64-cent7x-01:1270 -u:niroy -p:OpsMgr2007R2 -auth:basic -skipcncheck -skipcacheck -encoding:utf-8 -skiprevocationcheck`

## Using Kerberos

`$ winrm e http://schemas.microsoft.com/wbem/wscim/1/cim-schema/2/SCX_operatingsystem?__cimnamespace=root/scx -r:https://niroy64-cent7x-01:1270 -skipcncheck -skipcacheck -encoding:utf-8 -skiprevocationcheck`


# Install krb5-workstation.x86_64

`$ sudo yum install krb5-workstation.x86_64`

```
$ repoquery -l krb5-workstation.x86_64
/usr/bin/k5srvutil
/usr/bin/kadmin
/usr/bin/kdestroy
/usr/bin/kinit
/usr/bin/klist
/usr/bin/kpasswd
/usr/bin/ksu
/usr/bin/kswitch
/usr/bin/ktutil
/usr/bin/kvno
...
```

# Setup configuration

```
sudo cat /etc/krb5.conf
[logging]
 default = FILE:/var/log/krb5libs.log
 kdc = FILE:/var/log/krb5kdc.log
 admin_server = FILE:/var/log/kadmind.log

[libdefaults]
 dns_lookup_realm = false
 ticket_lifetime = 24h
 renew_lifetime = 7d
 forwardable = true
 rdns = false
 default_realm = REDMOND.CORP.MICROSOFT.COM
 default_ccache_name = KEYRING:persistent:%{uid}
```

# Create auth ticket

http://web.mit.edu/Kerberos/krb5-1.13/doc/user/user_commands/kinit.html

```
$ kinit -V
Using default cache: persistent:1000:1000
Using principal: niroy@REDMOND.CORP.MICROSOFT.COM
Password for niroy@REDMOND.CORP.MICROSOFT.COM:
Authenticated to Kerberos v5
```

# Show tickets

http://web.mit.edu/Kerberos/krb5-1.13/doc/user/user_commands/klist.html

```
$ klist
Ticket cache: KEYRING:persistent:1000:1000
Default principal: niroy@REDMOND.CORP.MICROSOFT.COM

Valid starting       Expires              Service principal
02/29/2016 14:09:30  03/01/2016 00:09:30  krbtgt/REDMOND.CORP.MICROSOFT.COM@REDMOND.CORP.MICROSOFT.COM
        renew until 03/07/2016 14:09:17
```
