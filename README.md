The following PyKD script dump the handle tables of the running processes and for each object, display its type, its name, and the processes which have a handle to it in their handle table.

This script is useful to map the communications between the dozens components of large solutions.

For example, the processes MsMpEng.exe (Antimalware Service Executable) and NisSrv.exe (Microsoft Network Realtime Inspection Service) belong to Microsoft Malware Protection.<br/>
Setting the whitelist of processes to MsMpEng.exe and NisSrv.exe, here is an excerpt from the output of the script running on Windows 10 Pro 1607 x64:

<pre><code>
[+] OBJECT_TYPE Directory, OBJECT_NAME "BaseNamedObjects"
	PID 3292: "NisSrv.exe"
	PID 1560: "MsMpEng.exe"
[+] OBJECT_TYPE Desktop, OBJECT_NAME "Default"
	PID 3292: "NisSrv.exe"
	PID 1560: "MsMpEng.exe"
[+] OBJECT_TYPE Directory, OBJECT_NAME "KnownDlls"
	PID 3292: "NisSrv.exe"
	PID 1560: "MsMpEng.exe"
[+] OBJECT_TYPE Event, OBJECT_NAME "MaximumCommitCondition"
	PID 3292: "NisSrv.exe"
	PID 1560: "MsMpEng.exe"
[+] OBJECT_TYPE Event, OBJECT_NAME "MpEvent-A0CEB604-8606-7FAE-6324-766E2293E94E"
	PID 3292: "NisSrv.exe"
	PID 1560: "MsMpEng.exe"
[+] OBJECT_TYPE Event, OBJECT_NAME "MpSvcEvent-265E032F-092F-0928-FD41-50733071C1F2"
	PID 3292: "NisSrv.exe"
	PID 1560: "MsMpEng.exe"
[+] OBJECT_TYPE Section, OBJECT_NAME "__ComCatalogCache__"
	PID 3292: "NisSrv.exe"
	PID 1560: "MsMpEng.exe"
</code></pre>

The processes interact with each other using 7 named objects including 2 Event objects, MpEvent-9CB50B47-78FF-5E5A-9412-A7F3746B8B1B and MpSvcEvent-4F4BCA61-874E-BCC1-ED24-A46A3491D4B1.
