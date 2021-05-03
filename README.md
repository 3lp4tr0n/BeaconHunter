# BeaconHunter

Behavior based monitoring and hunting tool built in C# tool leveraging ETW tracing. Blue teamers can use this tool to detect and respond to potential Cobalt Strike beacons. Red teamers can use this tool to research ETW bypasses and discover new processes that behave like beacons.

***Author***: Andrew Oliveau (@AndrewOliveau)

![image](https://user-images.githubusercontent.com/32691065/116278258-54661600-a754-11eb-82e4-0976a6d891b5.png)

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

* Open PowerShell or CMD as an Administrator
* `.\BeaconHunter.exe`

### MONITOR

##### Network Beacon Score

* Score is determined by calculating the time difference between beacon callbacks (delta), then calculating the 1st derivative of delta, and then feeding the answer to an inverse function `100/x` where x is the 1st derivative of delta. (Note: There is probably a better way, but it works)

![image](https://user-images.githubusercontent.com/32691065/116634488-34884b00-a92a-11eb-95f6-87797a62361e.png)

##### IP and PORT stats

![image](https://user-images.githubusercontent.com/32691065/116634452-17537c80-a92a-11eb-9c34-a3ce57de0cc2.png)


#### DNS Queries

* Helpful to detect DNS beacons.

![image](https://user-images.githubusercontent.com/32691065/116634931-74036700-a92b-11eb-962b-4eccd479f289.png)

#### Directory Change

![image](https://user-images.githubusercontent.com/32691065/116636023-48ce4700-a92e-11eb-84a5-f6bc68a04634.png)

#### New Uploaded Files

![image](https://user-images.githubusercontent.com/32691065/116636055-60a5cb00-a92e-11eb-88da-a4f08a35c6fa.png)

#### Shell Commands

* Detects PPID spoofing

![image](https://user-images.githubusercontent.com/32691065/116636093-7a471280-a92e-11eb-9ec0-c1c9a7f5b65a.png)

### ACTION

#### Suspend Thread ID - Manual

![image](https://user-images.githubusercontent.com/32691065/116634737-e6c01280-a92a-11eb-94f4-a76dbb1f8ef4.png)

#### Suspend Thread ID - Automated

* Set a score threshold. If Network Beacon Scores goes above threshold, BeaconHunter will automatically suspend the thread.

![image](https://user-images.githubusercontent.com/32691065/116634653-a52f6780-a92a-11eb-8092-293778a6e82a.png)

## References

* ETW Providers: https://gist.github.com/guitarrapc/35a94b908bad677a7310
* ETW Events: https://github.com/jdu2600/Windows10EtwEvents
* TraceEvent Library Guide: https://github.com/microsoft/perfview/blob/main/documentation/TraceEvent/TraceEventProgrammersGuide.md


