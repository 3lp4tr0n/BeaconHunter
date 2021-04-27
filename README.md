# BeaconHunter

Behaviour based monitoring and hunting tool built in C# tool leveraging ETW tracing. Blue teamers can use this tool to detect and respond to potential Cobalt Strike beacons. Red teamers can use this tool to research ETW bypasses and discover new processes that behave like beacons.

***Author***: Andrew Oliveau (@AndrewOliveau)

![alt text](https://github.com/3lp4tr0n/BeaconHunter/blob/main/screenshots/beacon_network_score.PNG)

### TL;DR
Beacon implants injected in a benign process live in a thread with a `Wait:DelayExecution` state (probably related to Cobalt Strike's `sleep`). Find all processes that contain a thread in a `Wait:DelayExecution` state. Then, leverage ETW tracing to specifically monitor suspicious thread activity:

  - HTTP/HTTPS callbacks
  - DNS queries
  - File system (`cd`,`ls`,`upload`,`rm`)
  - Process termination (`kill`)
  - Shell commands (`run`,`execute`)

Score suspicious behavior. Log, display, and take action against them.
  
## Building / Installation

#### Pre-compiled 
<a href="https://github.com/3lp4tr0n/BeaconHunter/releases">Release</a>

or `git clone` and go to `Release` folder.

#### .NET Framework version 

`4.5`

#### Nuggets:

Tools -> NuGet Package Manager -> Package Manager Console

* `Install-Package ConsoleTables -Version 2.4.2`
* `Install-Package Microsoft.Diagnostics.Tracing.TraceEvent -Version 2.0.64`
* `Install-Package System.Runtime.InteropServices.RuntimeInformation -Version 4.3.0`

## Running BeaconHunter

* Open Powershell or CMD as an Administrator
* `.\BeaconHunter.exe`

### Monitor

##### Network Beacon Score

Score is determined by calculating the time difference between beacon callbacks, then calculating the 1st derivative of delta time between callbacks, and then feeding the answer to an inverse function `100/x` where x is the 1st derivative of delta time between callbacks. (Note: There is probably a better wauy, but it works)

![image](https://user-images.githubusercontent.com/32691065/116275255-71e5b080-a751-11eb-8381-2da3ffe0e9cc.png)

##### IP and PORT stats

![image](https://user-images.githubusercontent.com/32691065/116275526-ba9d6980-a751-11eb-9101-b3ca65502fb5.png)

#### DNS Queries

![image](https://user-images.githubusercontent.com/32691065/116275626-cee16680-a751-11eb-9a81-1975c3f3f6cc.png)


