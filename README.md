# BeaconHunter

Behaviour based monitoring and hunting tool built in C# tool leveraging ETW tracing.

### TL;DR
Beacon implants injected in a benign process live in a thread with a `Wait:DelayExecution` state (Probably related to Cobalt Strike `sleep`).

Find all processes that contain a thread in a `Wait:DelayExecution` state. 

Leverage ETW tracing to specifically monitor suspicious threads: 
  - network
  - file
  - process termination
  - shell commands
  - registry (TODO)
  - WMI (TODO)
  - IDK Farbs, got any ideas?

Score suspicious behavior.

Log, display, and take action against them.
  
### Building / Installation

#### Pre-compiled 

`git clone` and go to `Release` folder.

#### .NET Framework version 

`4.5`

#### Nuggets:

Tools -> NuGet Package Manager -> Package Manager Console

* `Install-Package ConsoleTables -Version 2.4.2`
* `Install-Package Microsoft.Diagnostics.Tracing.TraceEvent -Version 2.0.64`
* `Install-Package System.Runtime.InteropServices.RuntimeInformation -Version 4.3.0`

