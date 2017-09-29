# Indicators of Compromise (IOCs)

This is an attempt to document some of the IOCs you may find when [Ruler] has been used.

# Network

The best place to find Ruler is in web-server logs. The User-Agent has been hard-coded to "Ruler", a semi decent attacker would change this. But not everyone reads code...

These logs should be availble in IIS for the Exchange Front-end server. It should also help detect attempts to brute-force credentials with Ruler.

# Local Host (Compromised Host)

The different techniques leave different traces. Even though code can be executed in memory (for Forms) there is still some info written to disk. It turns out that Outlook likes to cache and record data.

## Rules
The primary means of getting a shell with Rules is to use WebDAV. WebDAV is pretty noisy and anything downloaded through WebDAV will be written to a temp location before being executed and deleted.

Find this here: ```%systemdrive%\windows\ServiceProfiles\LocalService\AppData\Local\Temp\TfsStore```

## Forms 

Forms are automatically cached on the client-side. Now finding a form is not necessarily an IOC but parsing the form structure and finding VBScript, that is an IOC. The form needs to be triggered at least once before the cache entry is created.

Forms are cached here: ```%localappdata%\Microsoft\Forms```

There are also some registry entries created in: ```HKEY_CURRENT_USER\Software\Classes\WOW6432Node\CLSID``` this requires a bit more effort to parse and simply points to the file location mentioned above.

An example entry:
HKEY_CURRENT_USER\Software\Classes\WOW6432Node\CLSID\{830D44B2-4CC6-B504-F82E-63149BD3CFC0}
- BaseMsgCls - STRING (Default) IPM.Note
- FormStg - STRING (Default) C:\Users\user\AppData\Local\MICROS~1\FORMS\IPMNOT~1.PEW\FS525C.tmp
- MsgCls - STRING (Default) IPM.Note.grr


# Local Host (Domain Controller/Exchange Server)

Might need to move this to "Network" but at the same time these indicators are in the Windows Event Logs.
Ruler has a hard-coded Workstation name, which is used during NTLM authentication. A savvy attacker may change this in the source code, so these IOCs are not foolproof.

## Domain Controller

Authentication with NTLM results in a direct authenticate against the Domain Controller, this means an authentication log event gets written. This can be parsed for signs of Ruler useage. To do this, look at event 4776 and the workstation name of Ruler. 

Powershell script to do this: [FindRulerOnDC.ps1](https://gist.github.com/staaldraad/a7de22afa69ec10f1ec7d995d2bd913c#file-ondc-ps1)

## Exchange Server

Once again, in the Windows event logs, an authentication attempt might appear. The event will be 4624 in this case.

Powershell script to do this: [FindRulerOnExch.ps1](https://gist.github.com/staaldraad/a7de22afa69ec10f1ec7d995d2bd913c#file-onexch-ps1)







[Ruler]:<https://github.com/sensepost/ruler>
