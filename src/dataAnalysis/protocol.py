# -*- coding: utf-8 -*-
import re
from scapy.all import *



#try to determine the protocol and if it uses an exotic port inspect the payload
def inspectStreamForMedia(data, sport, dport):
	proto=findMedia(sport, dport)
	if proto!="" and proto!="HTTP":
		return (proto,"")
	media=''
	infos=''
	if (re.search("^HTTP/1.[0-1] [0-9]{1,3} OK\r\n", data["payload"])!=None):
		media="HTTP"
		infos="Response"
	else:
		regexp_url="((?:http[s]?://)?(?:[a-zA-Z0-9$%\-_@\.&#\+/!*\(\),]*))"
		result=re.search("^(GET|POST) "+regexp_url+" HTTP/1.[0-1]\r\n", data["payload"])
		if(result!=None):
			media="HTTP"
			infos=result.group(1)+" Request "+result.group(2)
	return (media,infos)


	
def getProtocol(pkt):
	protocol="other"
	if TCP in pkt:
		protocol="TCP"
	elif UDP in pkt:
		protocol="UDP"
	elif ICMP in pkt:
		protocol="ICMP"
	return protocol

#find the protocol of the transfered media (HTTP, IMAP, POP, ...)
def findMedia(dport,sport):
    #sorry, but it seems that python doesn't have switch statement, so lets do it thanks to elif

    if (dport==1 or sport==1):
        return "tcpmux - TCP Port Service Multiplexer"

    elif (dport==2 or sport==2):
        return "compressnet - Management Utility"

    elif (dport==3 or sport==3):
        return "compressnet - Compression Process"

    elif (dport==5 or sport==5):
        return "rje - Remote Job Entry"

    elif (dport==7 or sport==7):
        return "echo"

    elif (dport==9 or sport==9):
        return "discard"

    elif (dport==11 or sport==11):
        return "systat - Active Users"

    elif (dport==13 or sport==13):
        return "Daytime Protocol"

    elif (dport==17 or sport==17):
        return "qotd - Quote of the Day"

    elif (dport==18 or sport==18):
        return "msp - Message Send Protocol"

    elif (dport==19 or sport==19):
        return "chargen - Character Generator"

    elif (dport==20 or sport==20):
        return "ftp"

    elif (dport==21 or sport==21):
        return "ftp control"

    elif (dport==22 or sport==22):
        return "SSH"

    elif (dport==23 or sport==23):
        return "telnet"

    elif (dport==24 or sport==24):
        return "private mail system"

    elif (dport==25 or sport==25):
        return "smpt"

    elif (dport==27 or sport==27):
        return "nsw-fe - NSW User System FE"

    elif (dport==29 or sport==29):
        return "msg-icp"

    elif (dport==31 or sport==31):
        return "msg-auth - MSG Authentication"

    elif (dport==33 or sport==33):
        return "dsp - Display Support Protocol"

    elif (dport==35 or sport==35):
        return "private printer server"

    elif (dport==37 or sport==37):
        return "Time Protocol"

    elif (dport==38 or sport==38):
        return "rap -Route Access Protocol"

    elif (dport==39 or sport==39):
        return "rlp - Resource Location Protocol"

    elif (dport==41 or sport==41):
        return "graphics"

    elif (dport==42 or sport==42):
        return "nameserver - Host Name Server"

    elif (dport==43 or sport==43):
        return "nicname "

    elif (dport==44 or sport==44):
        return "mpm-flags - MPM FLAGS Protocol"

    elif (dport==45 or sport==45):
        return "mpm - Message Processing Module [recv]"

    elif (dport==46 or sport==46):
        return "mpm - Message Processing Module [default send]"

    elif (dport==47 or sport==47):
        return "ni-ftp"

    elif (dport==48 or sport==48):
        return "auditd - Digital Audit Daemon"

    elif (dport==49 or sport==49):
        return "login - Login Host Protocol "

    elif (dport==50 or sport==50):
        return "re-mail-ck - Remote Mail Checking Protocol"

    elif (dport==51 or sport==51):
        return "la-maint - IMP Logical Address Maintenance"

    elif (dport==52 or sport==52):
        return "xns-time - XNS Time Protocol"

    elif (dport==53 or sport==53):
        return "Domain Name Service"

    elif (dport==54 or sport==54):
        return "xns-ch - XNS Clearinghouse"

    elif (dport==55 or sport==55):
        return "isi-gl - ISI Graphics Language"

    elif (dport==56 or sport==56):
        return "xns-auth - XNS Authentication"

    elif (dport==57 or sport==57):
        return "any private terminal access"

    elif (dport==58 or sport==58):
        return "xns-mail - XNS Mail"

    elif (dport==59 or sport==59):
        return "any private file service"

    elif (dport==61 or sport==61):
        return "ni-mail"

    elif (dport==62 or sport==62):
        return "acas - ACA Services"

    elif (dport==64 or sport==64):
        return "covia - Communications Integrator (CI)"

    elif (dport==65 or sport==65):
        return "tacacs-ds - TACACS-Database Service"

    elif (dport==67 or sport==67):
        return "bootps - DHCP"

    elif (dport==68 or sport==68):
        return "bootpc - DHCP"

    elif (dport==69 or sport==69):
        return "tftp - Trivial File Transfer"

    elif (dport==70 or sport==70):
        return "gopher"

    elif (dport==71 or sport==71):
        return "netrjs-1 Remote Job Service"

    elif (dport==72 or sport==72):
        return "netrjs-2 Remote Job Service"

    elif (dport==73 or sport==73):
        return "netrjs-3 Remote Job Service"

    elif (dport==74 or sport==74):
        return "netrjs-4 Remote Job Service"

    elif (dport==75 or sport==75):
        return "any private dial out service"

    elif (dport==76 or sport==76):
        return "deos - Distributed External Object Store"

    elif (dport==77 or sport==77):
        return "any private RJE service"

    elif (dport==78 or sport==78):
        return "vettcp"

    elif (dport==79 or sport==79):
        return "finger"

    elif (dport==80 or sport==80 or dport==8080 or sport==8080):
        return "HTTP"

    elif (dport==81 or sport==81):
        return "host2-ns - HOSTS2 Name Server"

    elif (dport==82 or sport==82):
        return "xfer - XFER Utility"

    elif (dport==83 or sport==83):
        return "mit-ml-dev"

    elif (dport==84 or sport==84):
        return "ctf - Common Trace Facility"

    elif (dport==85 or sport==85):
        return "mit-ml-dev"

    elif (dport==86 or sport==86):
        return "mfcobol - Micro Focus Cobol"

    elif (dport==87 or sport==87):
        return "private terminal link"

    elif (dport==88 or sport==88):
        return "kerberos"

    elif (dport==89 or sport==89):
        return "su-mit-tg - SU/MIT Telnet Gateway"

    elif (dport==90 or sport==90):
        return "dnsix - DNSIX Security Attribute Token Map"

    elif (dport==91 or sport==91):
        return "mit-dov - MIT Dover Spooler"

    elif (dport==92 or sport==92):
        return "npp - Network Printing Protocol"

    elif (dport==93 or sport==93):
        return "dcp - Device Control Protocol"

    elif (dport==94 or sport==94):
        return "objcall - Tivoli Object Dispatcher"

    elif (dport==95 or sport==95):
        return "supdup"

    elif (dport==96 or sport==96):
        return "dixie - DIXIE Protocol Specelification"

    elif (dport==97 or sport==97):
        return "swelift-rvf - Swelift Remote Virtual File Protocol"

    elif (dport==98 or sport==98):
        return "tacnews"

    elif (dport==99 or sport==99):
        return "metagram - Metagram Relay"

    elif (dport==100 or sport==100):
        return "newacct - [unauthorized use]"

    elif (dport==101 or sport==101):
        return "hostname - NIC Host Name Server"

    elif (dport==102 or sport==102):
        return "iso-tsap"

    elif (dport==103 or sport==103):
        return "gppitnp - Genesis Point-To-Point Trans Net"

    elif (dport==104 or sport==104):
        return "acr-nema - ACR-NEMA Digital Imag. &amp; Comm. 300"

    elif (dport==105 or sport==105):
        return "csnet-ns - Mailbox Name Nameserver"

    elif (dport==106 or sport==106):
        return "3com-tsmux"

    elif (dport==107 or sport==107):
        return "rtelnet - Remote Telnet Service"

    elif (dport==108 or sport==108):
        return "snagas - SNA Gateway Access Server"

    elif (dport==109 or sport==109):
        return "pop2"

    elif (dport==110 or sport==110):
        return "pop3"

    elif (dport==111 or sport==111):
        return "sunrpc - SUN Remote Procedure Call"

    elif (dport==112 or sport==112):
        return "mcidas - McIDAS Data Transmission Protocol"

    elif (dport==113 or sport==113):
        return "auth - Authentication Service"

    elif (dport==114 or sport==114):
        return "audionews - Audio News Multicast"

    elif (dport==115 or sport==115):
        return "sftp - Secure File Transfer Protocol"

    elif (dport==116 or sport==116):
        return "ansanotelify - ANSA REX Notelify"

    elif (dport==117 or sport==117):
        return "uucp-path - UUCP Path Service"

    elif (dport==118 or sport==118):
        return "sqlserv - SQL Services"

    elif (dport==119 or sport==119):
        return "nntp - Network News Transfer Protocol"

    elif (dport==120 or sport==120):
        return "cfdptkt"

    elif (dport==121 or sport==121):
        return "erpc - Encore Expedited Remote Pro.Call"

    elif (dport==122 or sport==122):
        return "smakynet"

    elif (dport==123 or sport==123):
        return "ntp - Network Time Protocol"

    elif (dport==124 or sport==124):
        return "ansatrader - ANSA REX Trader"

    elif (dport==125 or sport==125):
        return "locus-map - Locus PC-Interface Net Map Server"

    elif (dport==126 or sport==126):
        return "unitary - Unisys Unitary Login"

    elif (dport==127 or sport==127):
        return "locus-con - Locus PC-Interface Conn Server"

    elif (dport==128 or sport==128):
        return "gss-xlicen - GSS X License Verelification"

    elif (dport==129 or sport==129):
        return "pwdgen - Password Generator Protocol"

    elif (dport==130 or sport==130):
        return "cisco-fna - cisco FNATIVE"

    elif (dport==131 or sport==131):
        return "cisco-tna - cisco TNATIVE"

    elif (dport==132 or sport==132):
        return "cisco-sys - cisco SYSMAINT"

    elif (dport==133 or sport==133):
        return "statsrv - Statistics Service"

    elif (dport==135 or sport==135):
        return "loc-srv - Location Service"

    elif (dport==136 or sport==136):
        return "profile - PROFILE Naming System"

    elif (dport==137 or sport==137):
        return "netbios -ns - NETBIOS Name Service"

    elif (dport==138 or sport==138):
        return "netbios-dgm - NETBIOS Datagram Service"

    elif (dport==139 or sport==139):
        return "netbios-ssn - NETBIOS Session Service"

    elif (dport==140 or sport==140):
        return "emfis-data - EMFIS Data Service"

    elif (dport==141 or sport==141):
        return "emfis-cntl - EMFIS Control Service"

    elif (dport==142 or sport==142):
        return "bl-idm - Britton-Lee IDM"

    elif (dport==143 or sport==143):
        return "imap2,imap4"

    elif (dport==144 or sport==144):
        return "news"

    elif (dport==145 or sport==145):
        return "uaac"

    elif (dport==146 or sport==146):
        return "iso-tp0"

    elif (dport==147 or sport==147):
        return "iso-ip"

    elif (dport==148 or sport==148):
        return "cronus - CRONUS-SUPPORT"

    elif (dport==149 or sport==149):
        return "aed-512 - AED 512 Emulation Service"

    elif (dport==150 or sport==150):
        return "sql-net"

    elif (dport==151 or sport==151):
        return "hems"

    elif (dport==152 or sport==152):
        return "bftp - Background File Transfer Program"

    elif (dport==153 or sport==153):
        return "sgmp"

    elif (dport==154 or sport==154):
        return "netsc-prod"

    elif (dport==155 or sport==155):
        return "netsc-dev"

    elif (dport==156 or sport==156):
        return "sqlsrv - SQL Service"

    elif (dport==157 or sport==157):
        return "knet-cmp - KNET/VM Command/Message Protocol"

    elif (dport==158 or sport==158):
        return "pcmail-srv - PCMail Server"

    elif (dport==159 or sport==159):
        return "nss-routing"

    elif (dport==160 or sport==160):
        return "sgmp-traps"

    elif (dport==161 or sport==161):
        return "SNMP"

    elif (dport==162 or sport==162):
        return "snmptrap - Simple Network Management Protocol Trap"

    elif (dport==163 or sport==163):
        return "cmip-man - CMIP/TCP Manager"

    elif (dport==164 or sport==164):
        return "cmip-agent - CMIP/TCP Agent"

    elif (dport==165 or sport==165):
        return "xns-courier - Xerox"

    elif (dport==166 or sport==166):
        return "s-net - Sirius Systems"

    elif (dport==167 or sport==167):
        return "namp"

    elif (dport==168 or sport==168):
        return "rsvd"

    elif (dport==169 or sport==169):
        return "send"

    elif (dport==170 or sport==170):
        return "print-srv - Network PostScript"

    elif (dport==171 or sport==171):
        return "multiplex - Network Innovations Multiplex"

    elif (dport==172 or sport==172):
        return "cl/1 - Network Innocations CL/1"

    elif (dport==173 or sport==173):
        return "xyplex-mux - Xyplex"

    elif (dport==174 or sport==174):
        return "mailq"

    elif (dport==175 or sport==175):
        return "vmnet"

    elif (dport==176 or sport==176):
        return "genrad-mux"

    elif (dport==177 or sport==177):
        return "xdmcp - X Display Manager Control Protocol"

    elif (dport==178 or sport==178):
        return "nextstep - NeXTSTEP Window Server"

    elif (dport==179 or sport==179):
        return "bgp - Border Gateway Protocol"

    elif (dport==180 or sport==180):
        return "ris - Intergraph"

    elif (dport==181 or sport==181):
        return "unelify"

    elif (dport==182 or sport==182):
        return "audit - Unisys Audit SITP"

    elif (dport==183 or sport==183):
        return "ocbinder"

    elif (dport==184 or sport==184):
        return "ocserver"

    elif (dport==185 or sport==185):
        return "remote-kis"

    elif (dport==186 or sport==186):
        return "kis - KIS Protocol"

    elif (dport==187 or sport==187):
        return "aci - Application Communication Interface"

    elif (dport==188 or sport==188):
        return "mumps - Plus Five's MUMPS"

    elif (dport==189 or sport==189):
        return "qft - Queued File Transport"

    elif (dport==190 or sport==190):
        return "gacp - Gateway Access Protocol"

    elif (dport==191 or sport==191):
        return "prospero - Prospero Directory Service"

    elif (dport==192 or sport==192):
        return "osu-nms - OSU Network Monitoring System"

    elif (dport==193 or sport==193):
        return "srmp - Spider Remote Monitoring Protocol"

    elif (dport==194 or sport==194):
        return "Internet relay chat"

    elif (dport==195 or sport==195):
        return "dn6-nlm-aud - DNSIX Network Level Module Audit"

    elif (dport==196 or sport==196):
        return "dn6-nlm-red - DNSIX Session Mgt Module Audit Redir"

    elif (dport==197 or sport==197):
        return "dls - Directory Location Service"

    elif (dport==198 or sport==198):
        return "dls-mon - Directory Location Service Monitor"

    elif (dport==199 or sport==199):
        return "smux"

    elif (dport==200 or sport==200):
        return "src - IBM System Resource Controller"

    elif (dport==201 or sport==201):
        return "at-rtmp - AppleTalk Routing Maintenance"

    elif (dport==202 or sport==202):
        return "at-nbp - AppleTalk Name Binding"

    elif (dport==203 or sport==203):
        return "at-3 - AppleTalk Unused"

    elif (dport==204 or sport==204):
        return "at-echo - AppleTalk Echo"

    elif (dport==205 or sport==205):
        return "at-5 - AppleTalk Unused"

    elif (dport==206 or sport==206):
        return "at-zis - AppleTalk Zone Information"

    elif (dport==207 or sport==207):
        return "at-7 - AppleTalk Unused"

    elif (dport==208 or sport==208):
        return "at-8 - AppleTalk Unused"

    elif (dport==209 or sport==209):
        return "tam - Trivial Mail Authentication Protocol"

    elif (dport==210 or sport==210):
        return "z39.50"

    elif (dport==211 or sport==211):
        return "914c/g - Texas Instruments 914C/G Terminal"

    elif (dport==212 or sport==212):
        return "anet - ATEXSSTR"

    elif (dport==213 or sport==213):
        return "ipx"

    elif (dport==214 or sport==214):
        return "vmpwscs - VM PWSCS"

    elif (dport==215 or sport==215):
        return "softpc - Insignia Solutions"

    elif (dport==216 or sport==216):
        return "atls - Access Technology License Server"

    elif (dport==217 or sport==217):
        return "dbase - dBASE Unix"

    elif (dport==218 or sport==218):
        return "mpp - Netix Message Posting Protocol"

    elif (dport==219 or sport==219):
        return "uarps - Unisys ARPs"

    elif (dport==220 or sport==220):
        return "imap3"

    elif (dport==221 or sport==221):
        return "fln-spx - Berkeley rlogind with SPX auth"

    elif (dport==222 or sport==222):
        return "rsh-spx - Berkeley rshd with SPX auth"

    elif (dport==223 or sport==223):
        return "cdc - Certelificate Distribution Center"

    elif (dport==243 or sport==243):
        return "sur-meas - Surveet Measurement"

    elif (dport==245 or sport==245):
        return "link"

    elif (dport==246 or sport==246):
        return "dsp3270 - Display Systems Protocol"

    elif (dport==264 or sport==264):
        return "BGMP - Border Gateway Multicast Protocol"

    elif (dport==344 or sport==344):
        return "pdap - Prospero Data Access Protocol"

    elif (dport==345 or sport==345):
        return "pawserv - Perf Analysis Workbench"

    elif (dport==346 or sport==346):
        return "zserv - Zebra server"

    elif (dport==347 or sport==347):
        return "fatserv - Fatmen Server"

    elif (dport==348 or sport==348):
        return "csi-sgwp - Cabletron Management Protocol"

    elif (dport==371 or sport==371):
        return "clearcase"

    elif (dport==372 or sport==372):
        return "ulistserv - Unix Listserv"

    elif (dport==373 or sport==373):
        return "legent-1 - Legent Corporation"

    elif (dport==374 or sport==374):
        return "legent-2 - Legent Corporation"

    elif (dport==375 or sport==375):
        return "hassle"

    elif (dport==376 or sport==376):
        return "nip - Amiga Envoy Network Inquiry Proto"

    elif (dport==377 or sport==377):
        return "tnETOS - NEC Corporation"

    elif (dport==378 or sport==378):
        return "dsETOS - NEC Corporation"

    elif (dport==379 or sport==379):
        return "is99c - TIA/EIA/IS-99 modem client"

    elif (dport==380 or sport==380):
        return "is99s - TIA/EIA/IS-99 modem server"

    elif (dport==381 or sport==381):
        return "hp-collector - hp performance data collector"

    elif (dport==382 or sport==382):
        return "hp-managed-node - hp performance data managed node"

    elif (dport==383 or sport==383):
        return "hp-alarm-mgr - hp performance data alarm manager"

    elif (dport==384 or sport==384):
        return "arns - A Remote Network Server System"

    elif (dport==385 or sport==385):
        return "ibm-app - IBM Application"

    elif (dport==386 or sport==386):
        return "asa - ASA Message Router Object Def."

    elif (dport==387 or sport==387):
        return "aurp - AppleTalk Update-Based Routing Pro."

    elif (dport==388 or sport==388):
        return "unidata-ldm - Unidata LDM Version 4"

    elif (dport==389 or sport==389):
        return "Lightweight Directory Access Protocol - LDAP"

    elif (dport==390 or sport==390):
        return "uis"

    elif (dport==391 or sport==391):
        return "synotics-relay - SynOptics SNMP Relay Port"

    elif (dport==392 or sport==392):
        return "synotics-broker - SynOptics Port Broker Port"

    elif (dport==393 or sport==393):
        return "dis - Data Interpretation System"

    elif (dport==394 or sport==394):
        return "embl-ndt - EMBL Nucleic Data Transfer"

    elif (dport==395 or sport==395):
        return "NETscout Control Protocol"

    elif (dport==396 or sport==396):
        return "netware-ip - Novell NetWare over IP"

    elif (dport==397 or sport==397):
        return "mptn - Multi Protocol Trans. Net."

    elif (dport==398 or sport==398):
        return "kryptolan"

    elif (dport==400 or sport==400):
        return "work-sol - Worksation Solutions"

    elif (dport==401 or sport==401):
        return "ups - Uninteruptible Power Supply"

    elif (dport==402 or sport==402):
        return "genie - Genie Protocol"

    elif (dport==403 or sport==403):
        return "decap"

    elif (dport==404 or sport==404):
        return "nced"

    elif (dport==407 or sport==407):
        return "timbuktu"

    elif (dport==408 or sport==408):
        return "prm-sm - Prospero Resource Manager Sys. Man."

    elif (dport==409 or sport==409):
        return "prm-nm - Prospero Resource Manager Node Man."

    elif (dport==410 or sport==410):
        return "decladebug - DECLadebug Remote Debug Protcol"

    elif (dport==411 or sport==411):
        return "rmt - Remote MT Protocol"

    elif (dport==412 or sport==412):
        return "synoptics-trap - Trap Convetion Port"

    elif (dport==413 or sport==413):
        return "smsp"

    elif (dport==414 or sport==414):
        return "infoseek"

    elif (dport==415 or sport==415):
        return "bnet"

    elif (dport==416 or sport==416):
        return "silverplatter"

    elif (dport==417 or sport==417):
        return "onmux"

    elif (dport==418 or sport==418):
        return "hyper-g"

    elif (dport==419 or sport==419):
        return "ariel1"

    elif (dport==420 or sport==420):
        return "smpte"

    elif (dport==421 or sport==421):
        return "ariel2"

    elif (dport==422 or sport==422):
        return "ariel3"

    elif (dport==423 or sport==423):
        return "opc-job-start - IBM Operations Planning and Control Start"

    elif (dport==424 or sport==424):
        return "opc-job-track - IBM Operations Planning and Control Track"

    elif (dport==425 or sport==425):
        return "icad-el - ICAD"

    elif (dport==426 or sport==426):
        return "smartsdp"

    elif (dport==427 or sport==427):
        return "svrloc - Server Location"

    elif (dport==428 or sport==428):
        return "ocs_cmu"

    elif (dport==429 or sport==429):
        return "ocs_amu"

    elif (dport==430 or sport==430):
        return "utmpsd"

    elif (dport==431 or sport==431):
        return "utmpcd"

    elif (dport==432 or sport==432):
        return "iasd"

    elif (dport==433 or sport==433):
        return "nnsp"

    elif (dport==434 or sport==434):
        return "mobileip-agent"

    elif (dport==435 or sport==435):
        return "mobileip-mn"

    elif (dport==436 or sport==436):
        return "dna-cml"

    elif (dport==437 or sport==437):
        return "comscm"

    elif (dport==438 or sport==438):
        return "dsfgw"

    elif (dport==439 or sport==439):
        return "dasp"

    elif (dport==440 or sport==440):
        return "sgcp"

    elif (dport==441 or sport==441):
        return "decvms-sysmgt"

    elif (dport==442 or sport==442):
        return "cvc_hostd"

    elif (dport==443 or sport==443):
        return "https"

    elif (dport==144 or sport==144):
        return "snpp - Simple Network Paging Protocol"

    elif (dport==445 or sport==445):
        return "microsoft-ds (Microsoft Naked CelifS)"

    elif (dport==446 or sport==446):
        return "ddm-rdb"

    elif (dport==447 or sport==447):
        return "ddm-dfm"

    elif (dport==448 or sport==448):
        return "ddm-byte"

    elif (dport==449 or sport==449):
        return "as-servermap - AS Server Mapper"

    elif (dport==450 or sport==450):
        return "tserver"

    elif (dport==465 or sport==465):
        return "smtp"

    elif (dport==497 or sport==497):
        return "retrospect - Retrospect Backup software"

    elif (dport==500 or sport==500):
        return "ISAKMP"

    elif (dport==502 or sport==502):
        return "Modbus."

    elif (dport==514 or sport==514):
        return "Syslog"

    elif (dport==515 or sport==515):
        return "printer - spooler"

    elif (dport==517 or sport==517):
        return "talk"

    elif (dport==518 or sport==518):
        return "ntalk"

    elif (dport==520 or sport==520):
        return "Routing"

    elif (dport==525 or sport==525):
        return "timed - timeserver"

    elif (dport==526 or sport==526):
        return "tempo - newdate"

    elif (dport==546 or sport==546):
        return "DHCP - Dynamic Host Configuration Protocol"

    elif (dport==548 or sport==548):
        return "AppleShare IP Server"

    elif (dport==554 or sport==554):
        return "RTSP (Real Time Streaming Protocol)"

    elif (dport==563 or sport==563):
        return "nntp sécurisé (ssl)"

    elif (dport==587 or sport==587):
        return "Message Submission for Mail"

    elif (dport==631 or sport==631):
        return "Internet Printing Protocol"

    elif (dport==706 or sport==706):
        return "Secure internet live conferencing"

    elif (dport==873 or sport==873):
        return "rsync"

    elif (dport==993 or sport==993):
        return "imap sécurisé (ssl)"

    elif (dport==995 or sport==995):
        return "pop3 sécurisé (ssl)"

    elif (dport==1080 or sport==1080):
        return "SOCKS"

    elif (dport==1194 or sport==1194):
        return "OpenVPN"

    elif (dport==1352 or sport==1352):
        return "Lotus Notes"

    elif (dport==1414 or sport==1414):
        return "IBM MQSeries"

    elif (dport==1433 or sport==1433):
        return "Microsoft SQL Server"

    elif (dport==1434 or sport==1434):
        return "Microsoft SQL Monitor"

    elif (dport==1521 or sport==1521):
        return "Serveur Oracle"

    elif (dport==1524 or sport==1524):
        return "Ingres</a>"

    elif (dport==1720 or sport==1720):
        return "H323"

    elif (dport==1723 or sport==1723):
        return "PPTP"

    elif (dport==1863 or sport==1863):
        return "MSN (tchat)"

    elif (dport==2427 or sport==2427):
        return "MGCP"

    elif (dport==3000 or sport==3000):
        return "First Class Server"

    elif (dport==3051 or sport==3051):
        return "AMS (Agency Management System)"

    elif (dport==3074 or sport==3074):
        return "nintendo server"

    elif (dport==3306 or sport==3306):
        return "Mysql Server"

    elif (dport==3389 or sport==3389):
        return "Microsoft Terminal Server"

    elif (dport==3632 or sport==3632):
        return "distcc"

    elif (dport==5060 or sport==5060):
        return "serveur SIP"

    elif (dport==5222 or sport==5222):
        return "serveur Jabber"

    elif (dport==5223 or sport==5223):
        return "serveur Jabber sécurisé (ssl)"

    elif (dport==5269 or sport==5269):
        return "server to server Jabber"

    elif (dport==5280 or sport==5280):
        return "serveur BOSH"

    elif (dport==5432 or sport==5432):
        return "serveur PostgreSQL"

    elif (dport==5498 or sport==5498):
        return "Hotline Tracker"

    elif (dport==5500 or sport==5500):
        return "Hotline Server"

    elif (dport==5501 or sport==5501):
        return "Hotline Server"

    elif (dport==5900 or sport==5900):
        return "VNC Server"

    elif (dport==5984 or sport==5984):
        return "Couchdb Server"

    elif (dport==6522 or sport==6522):
        return "Gobby Server (Sobby)"

    elif (dport==6667 or sport==6667):
        return "Serveur IRC"

    elif (dport==6697 or sport==6697):
        return "Serveur IRC sécurisé (ssl)"

    elif (dport==7000 or sport==7000):
        return "Serveur IRC sécurisé (ssl) alternatif"

    elif (dport==7648 or sport==7648):
        return "Cu-seeme"

    elif (dport==8000 or sport==8000):
        return "Hotline"

    elif (dport==8008 or sport==8008):
        return "Serveur CalDAV"

    elif (dport==8098 or sport==8098):
        return "Administration Serveur Microsoft Windows 2003"

    elif (dport==8443 or sport==8443):
        return "Serveur CalDAV sécurisé (ssl)"

    elif (dport==9009 or sport==9009):
        return "Pichat - Peer to peer chat software"

    elif (dport==49300 or sport==49300):
        return "Pronote (client lourd)"

    elif (dport==11371 or sport==11371):
        return "OpenPGP - OpenPGP HTTP Keyserver"
    else:
        return ''
