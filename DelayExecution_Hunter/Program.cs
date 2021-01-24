using System;
using System.Diagnostics;
using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing.Parsers.Clr;
using Microsoft.Diagnostics.Tracing.Session;
using Microsoft.Diagnostics.Tracing.Parsers.Kernel;
using Microsoft.Diagnostics.Tracing;
using System.Threading.Tasks;
using System.Collections.Generic;
using System.Threading;
using ConsoleTables;
using System.Runtime;


namespace DelayExecution_Hunter
{
    class Program
    {

        private static bool action = false;
        private static bool monitor = false;
        private static bool beacon_score = false;
        private static bool verbose = false;
        private static string input;
        private static double milliseconds;
        private static double dev;
        private static double delta;
        
        //Beacon score
        private static Dictionary<int, double> proc_timestamp = new Dictionary<int, double>();
        private static Dictionary<int, double> time_delta = new Dictionary<int, double>();
        private static Dictionary<int, double> score = new Dictionary<int, double>();
        private static Dictionary<int, List<double>> derivate = new Dictionary<int, List<double>>(); //might need to change these dictionaries for efficiency
        
        //keep record of PID and suspicious TID. Useful for filtering later on!
        private static Dictionary<int, int> threadIDs = new Dictionary<int, int>();


        static void Main()
        {

            //start ETW collector thread
            Thread etwcollect_thread = new Thread(new ThreadStart(ETWcollect));
            etwcollect_thread.IsBackground = true;
            etwcollect_thread.Start();

            while (true)
            {
                if (monitor == false && action == false)
                {
                    Console.WriteLine("\n------------------------------");
                    Console.WriteLine("\n[1] Monitor");
                    Console.WriteLine("[2] Action");
                    Console.WriteLine("[3] Verbose\n");
                    input = Console.ReadLine();

                    if (input == "1")
                    {
                        monitor = true;
                    }
                    else if (input == "2")
                    {
                        action = true;
                    }
                    else if (input == "3")
                    {
                        if (!verbose)
                        {
                            Console.WriteLine("\n[*] Verbose turned ON");
                            verbose = true;
                        }
                        else
                        {
                            Console.WriteLine("\n[*] Verbose turned OFF");
                            verbose = false;
                        }

                    }
                    else
                    {
                        Console.WriteLine("");
                    }
                }

                if (monitor)
                {
                    Console.WriteLine("\n------------------------------");
                    Console.WriteLine("\nMONITOR");
                    Console.WriteLine("   [1] Network beacon score");
                    Console.WriteLine("   [2] Suspicious PID/TID history");
                    Console.WriteLine("   [3] Command history");
                    Console.WriteLine("   [4] Terminate history");
                    Console.WriteLine("   [5] File history");
                    Console.WriteLine("   [6] IP Stats");
                    Console.WriteLine("   [7] Main menu\n");
                    var input2 = Console.ReadLine();

                    if (input2 == "1")
                    {
                        Console.WriteLine("\nBeacon Score\n");
                        beacon_score = true;
                        while (true)
                        {
                            var input3 = Console.ReadLine();
                            if (input3 == "q")
                            {
                                beacon_score = false;
                                break;
                            }
                            else
                            {
                                Console.WriteLine("\nPress 'q' to go back\n");
                            }
                        }
                    }
                    else if (input2 == "7")
                    {
                        monitor = false;
                    }
                }
                else if (action)
                {
                    Console.WriteLine("\n------------------------------");
                    Console.WriteLine("\nACTION");
                    Console.WriteLine("   [1] Action Option 1");
                    Console.WriteLine("   [2] Action Option 2");
                    Console.WriteLine("   [3] Action Option 3");
                    Console.WriteLine("   [4] Action Option 4");
                    Console.WriteLine("   [5] Main menu\n");
                    var input2 = Console.ReadLine();

                    if (input2 == "1")
                    {
                        Console.WriteLine("Action Option 1 was selected!\n");
                    }
                    else if (input2 == "5")
                    {
                        action = false;
                    }
                }
            }
        }

        static void ETWcollect()
        {
            while (true)
            {
                // Get all process information
                Process[] AllProcesses = Process.GetProcesses();


                foreach (Process proc in AllProcesses)
                {
                    // Check if process is already in timestamp Dictionary. NEED TO CHANGE THIS INCASE PROCESS HAS MORE THAN 1 THREAD WITH EXECUTIONDELAY
                    if (!proc_timestamp.ContainsKey(proc.Id))
                    {

                        try
                        {
                            ProcessThreadCollection myThreads = proc.Threads;

                            foreach (ProcessThread pt in myThreads)
                            {
                                try
                                {
                                    if (pt.WaitReason.ToString() == "ExecutionDelay" && proc.Id != 4) //PID 4 is SYSTEM using SMB
                                    {
                                        
                                        //Notify new processes
                                        Console.WriteLine("\n{0} => New Process with suspicious Thread: {1} -> {2} ({3})", DateTime.Now, proc.ProcessName, proc.Id, pt.Id);

                                        //Add thread ID to threadID dictionary to keep track
                                        threadIDs.Add(proc.Id, pt.Id);

                                        //Get current timestamp of processes to calculate time delta for next network event
                                        milliseconds = DateTime.Now.Subtract(DateTime.MinValue.AddYears(1969)).TotalMilliseconds;

                                        //Add PID/TID to beacon score
                                        proc_timestamp.Add(proc.Id, milliseconds);
                                        time_delta.Add(proc.Id, 0);
                                        derivate.Add(proc.Id, new List<double>() { 0 });
                                        score.Add(proc.Id, 1.0);

                                    }
                                }
                                catch { continue; }
                            }
                        }
                        catch { continue; }
                    }


                }

                //Remove dead processes from Dictionaries
                foreach (var pid in new List<int>(proc_timestamp.Keys))
                {
                    try
                    {
                        Process.GetProcessById(pid);
                    }
                    catch (ArgumentException)
                    {
                        proc_timestamp.Remove(pid);
                        threadIDs.Remove(pid);
                        time_delta.Remove(pid);
                        derivate.Remove(pid);
                        score.Remove(pid);
                        Console.WriteLine("\nDEAD/REMOVED PID: {0}", pid);
                    }
                }



                //THREAD for ETW COLLECTOR
                var Lock = new object();
                Task.Run(() =>
                {

                    TraceEventSession session1 = null;

                    using (session1 = new TraceEventSession("AndrewsETWSession"))
                    {

                        //Kill ETW session right before process ends since it will stay alive if session not disposed (added 2 but only need 1)
                        Console.CancelKeyPress += (object sender, ConsoleCancelEventArgs cancelArgs) =>
                        {
                            if (session1 != null)
                            {
                                session1.Dispose();
                            }

                            cancelArgs.Cancel = false;
                        };
                        //Second Dispose ETW session
                        Console.CancelKeyPress += new ConsoleCancelEventHandler((object sender, ConsoleCancelEventArgs cancelArgs) =>
                        {
                            Console.WriteLine("Control C1 pressed");       
                            session1.Dispose();                            
                            cancelArgs.Cancel = false;                      
                        });

                        //Enable ETW providers to capture data
                        session1.EnableProvider("Microsoft-Windows-WinINet", Microsoft.Diagnostics.Tracing.TraceEventLevel.Informational); // network traffic
                        session1.EnableProvider("Microsoft-Windows-Kernel-Process", Microsoft.Diagnostics.Tracing.TraceEventLevel.Informational, 0x00); // process start and commands
                        session1.EnableProvider("Microsoft-Windows-Kernel-File", Microsoft.Diagnostics.Tracing.TraceEventLevel.Informational, 0x00); // file/directory changes
                        session1.EnableProvider("Microsoft-Windows-Kernel-Audit-API-Calls", Microsoft.Diagnostics.Tracing.TraceEventLevel.Informational, 0x00); // remote process termination


                        var parser = session1.Source.Dynamic;

                        parser.All += e =>  
                        {
                            try
                            {
                                if (e.ProviderName == "Microsoft-Windows-WinINet")
                                {
                                    //Log only if coming from suspicious TID
                                    if (threadIDs[e.ProcessID] == e.ThreadID)   
                                    {
                                        if (e.PayloadByName("ServerName").ToString() != "" && e.PayloadByName("ServerPort").ToString() != "")
                                        {
                                            int ProcessID = e.ProcessID;

                                            milliseconds = DateTime.Now.Subtract(DateTime.MinValue.AddYears(1969)).TotalMilliseconds;

                                            //calculate time difference between beacon callbacks
                                            delta = milliseconds - proc_timestamp[ProcessID];
                                            proc_timestamp[ProcessID] = milliseconds;

                                            //calculate derivative of delta time between callbacks
                                            dev = time_delta[ProcessID] - delta;
                                            time_delta[ProcessID] = delta;

                                            //add 1st derivative of delta to list
                                            derivate[ProcessID].Add(dev);


                                            //calculate score for process
                                            if (dev == 0)
                                            {
                                                score[ProcessID] += 3;
                                            }
                                            else
                                            {
                                                //closer delta is to zero, the higher the score. Yes, jitters will impact score... but how much? ;)
                                                score[ProcessID] += Math.Abs(100.0 / dev);
                                            }

                                            //only show table if in Monitor -> Beacon Score
                                            if (beacon_score)
                                            {
                                                Console.Clear();
                                                Console.WriteLine("\nProcess: {0} Thread {1}\n", e.ProcessID, e.ThreadID);
                                                Console.WriteLine(" Destination: {0}:{1}", e.PayloadByName("ServerName"), e.PayloadByName("ServerPort"));
                                                Console.WriteLine(" Delta time: {0}", delta);
                                                Console.WriteLine(" 1st derivative of delta = {0}", dev);
                                                Console.WriteLine(" Total # of derivatives: " + derivate[ProcessID].Count);
                                                Console.WriteLine(" Date/Time: {0}", e.TimeStamp);
                                                Console.WriteLine(" Timestamp: {0}", e.TimeStampRelativeMSec);
                                                Console.WriteLine(" Score: {0}\n", score[ProcessID]);

                                                //Need this table to be better with more detail. Need to read ConsoleTable documentation
                                                Console.WriteLine("   Suspicious PID Score");
                                                var table = ConsoleTable.From(score).ToString();
                                                Console.WriteLine(table);
                                                Console.WriteLine("\n--------------------------------------------------------");
                                            }

                                        }
                                    }
                                }

                                else if (e.ProviderName == "Microsoft-Windows-Kernel-Process")
                                {
                                    //Log only if coming from suspicious TID
                                    if ((e.ProcessID != -1 && threadIDs[e.ProcessID] == e.ThreadID)) 
                                    {                                        

                                        //Splitted message to get potentially spoofed PPID
                                        string[] messageBits = e.FormattedMessage.Replace(",", string.Empty).Split(' ');
                                        if (verbose)
                                        {
                                            Console.WriteLine("\n------------------------------\n[!] COMMAND\n\nParent Process: {0} {1}\n -> Child Procces: {2}\nFake Parent Process: {3}\nThread ID: {4}\nMessage: {5}\nTime:{6}\n", Process.GetProcessById(e.ProcessID).ProcessName, e.ProcessID,
    e.PayloadByName("ProcessID"), int.Parse(messageBits[10]), e.ThreadID, e.FormattedMessage, DateTime.Now);
                                        }



                                        //Check if PPID spoofing
                                        if (e.ProcessID != int.Parse(messageBits[10]))
                                        {
                                            if (verbose)
                                            {
                                                Console.WriteLine("\n[!] PPID SPOOFING DETECTED !");
                                            }
                                            
                                        }
                                        //Console.WriteLine("\n--------------------------------------------------------\n");
                                    }

                                }

                                //log remote process termination by suspicious PID/TID
                                // if remote process is Sysmon, delete process (TODO)
                                // need to check different OS implementations
                                else if (e.ProviderName == "Microsoft-Windows-Kernel-Audit-API-Calls")
                                {
                                    if (threadIDs[e.ProcessID] == e.ThreadID)
                                    {
                                        if (e.EventName.Split('(', ')')[1] == "2")
                                        {
                                            if (verbose)
                                            {
                                                Console.WriteLine("\n------------------------------");
                                                Console.WriteLine("[!] TERMINATION");
                                                Console.WriteLine("\nProcess: {0}\nPID: {1}\nTID: {2}\nVictim: {3}\n", Process.GetProcessById(e.ProcessID).ProcessName, e.ProcessID, e.ThreadID, e.PayloadByName("TargetProcessId"));
                                                //Console.WriteLine("\n--------------------------------------------------------\n");
                                            }

                                        }
                                    }

                                }

                                else if (e.ProviderName == "Microsoft-Windows-Kernel-File")
                                {

                                    //Log only if coming from suspicious TID
                                    if (threadIDs[e.ProcessID] == e.ThreadID)
                                    {

                                        
                                        //Check directory enumeration
                                        if (e.PayloadByName("FileName").ToString() == "*" && e.EventName == "DirEnum")
                                        {
                                            if (verbose)
                                            {
                                                Console.WriteLine("\n------------------------------\n[!] FILE\n\nProcess: {0}\nPID: {1}\nTID: {2}\n", Process.GetProcessById(e.ProcessID).ProcessName, e.ProcessID, e.ThreadID);
                                                Console.WriteLine("[*] Directory Enumeration");
                                            }

                                        }

                                        //New file
                                        else if (e.EventName == "CreateNewFile")
                                        {
                                            if (verbose)
                                            {
                                                Console.WriteLine("\n------------------------------\n[!] FILE\n\nProcess: {0}\nPID: {1}\nTID: {2}\n", Process.GetProcessById(e.ProcessID).ProcessName, e.ProcessID, e.ThreadID);
                                                Console.WriteLine("[*] New File -> {0}", e.PayloadByName("FileName"));
                                            }

                                        }
                                        
                                        //Check if file REMOVED or MODIFIED
                                        else if (e.PayloadByName("CreateOptions").ToString() == "18874368" || e.PayloadByName("CreateOptions").ToString() == "18874432")
                                        {
                                            if (verbose)
                                            {
                                                Console.WriteLine("\n------------------------------\n[!] FILE\n\nProcess: {0}\nPID: {1}\nTID: {2}\n", Process.GetProcessById(e.ProcessID).ProcessName, e.ProcessID, e.ThreadID);
                                                Console.WriteLine("[*] Removed/Modified File -> {0}", e.PayloadByName("FileName"));
                                            }

                                        }
                                        
                                        //Changing directory 
                                        else if (e.PayloadByName("CreateOptions").ToString() == "16777249")
                                        {
                                            if (verbose)
                                            {
                                                Console.WriteLine("\n------------------------------\n[!] FILE\n\nProcess: {0}\nPID: {1}\nTID: {2}\n", Process.GetProcessById(e.ProcessID).ProcessName, e.ProcessID, e.ThreadID);
                                                Console.WriteLine("[*] Change directory -> {0}", e.PayloadByName("FileName"));
                                            }
                                        }

                                    }
                                } 
                            }
                            catch
                            {

                            }
                        };
                        session1.Source.Process();
                    }


                });

                // After 10 seconds, check for new suspicious processes
                Stopwatch s = new Stopwatch();
                s.Start();
                while (s.Elapsed < TimeSpan.FromSeconds(10))
                {
                    lock (Lock) ;
                   
                }
            }
        }
    }
}
