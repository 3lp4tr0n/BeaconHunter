using System;
using System.Diagnostics;
using Microsoft.Diagnostics.Tracing.Session;
using System.Threading.Tasks;
using System.Collections.Generic;
using System.Threading;
using ConsoleTables;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;


namespace DelayExecution_Hunter
{
    class Program
    {
        // variables 
        private static bool action = false;
        private static bool monitor = false;
        private static bool isSpoof = false;
        private static string input;
        private static double milliseconds;
        private static double dev;
        private static double delta;


        // Monitor bools
        private static bool verbose = true;
        private static bool network_verbose = false;
        private static bool beacon_score = false;
        private static bool pid_tid_history = false;
        private static bool command_history = false;
        private static bool terminate_history = false;
        private static bool file_history = false;

        // Beacon score 2 
        private static Dictionary<int, Dictionary<int, List<double>>> score2 = new Dictionary<int, Dictionary<int, List<double>>>();
       

        private static Dictionary<int, List<int>> threadIDs2 = new Dictionary<int, List<int>>();

        // Keep record of PID and suspicious TID. Useful for ETW filtering later on!
        private static Dictionary<int, int> threadIDs = new Dictionary<int, int>();

        // Keep record of Process connection to IP      //{ PID : {TID : [IP, COUNT]} }
        private static Dictionary<int, Dictionary<int,List<string>>> PID_TID_IP = new Dictionary<int, Dictionary<int,List<string>>>();


        static void Main()
        {

            // Start ETW collector thread
            Thread etwcollect_thread = new Thread(new ThreadStart(ETWcollect));
            etwcollect_thread.IsBackground = true;
            etwcollect_thread.Start();

            while (true)
            {
                if (monitor == false && action == false)
                {
                    Console.WriteLine("\n------------------------------");
                    Console.WriteLine("\nBeaconHunter - @AndrewOliveau");
                    Console.WriteLine("\n\n[1] Monitor");
                    Console.WriteLine("[2] Action");
                    Console.WriteLine("[3] Verbose (Default ON)");
                    Console.WriteLine("[4] Network count verbose (Default OFF)\n");
                    Console.Write("> ");
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
                    else if (input == "4")
                    {
                        if (!network_verbose)
                        {
                            Console.WriteLine("\n[*] Network Verbose turned ON");
                            network_verbose = true;
                        }
                        else
                        {
                            Console.WriteLine("\n[*] Network Verbose turned OFF");
                            network_verbose = false;
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
                    Console.WriteLine("\nMONITOR\n");
                    Console.WriteLine("   [1] Beacon network score");
                    Console.WriteLine("   [2] Suspicious PID/TID history");
                    Console.WriteLine("   [3] Beacon command history");
                    Console.WriteLine("   [4] Process terminate history");
                    Console.WriteLine("   [5] File history");
                    Console.WriteLine("   [6] IP Stats");
                    Console.WriteLine("   [7] Main menu\n");
                    Console.Write("> ");
                    var user_input = Console.ReadLine();

                    if (user_input == "1")
                    {
                        Console.WriteLine("\n------------------------------");
                        Console.WriteLine("\nBeacon Score");
                        Console.WriteLine("\n------------------------------");
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
                                Console.WriteLine("\nEnter 'q' to go back > \n");
                            }
                        }
                    }

                    else if (user_input == "2")
                    {
                        Console.WriteLine("\n------------------------------");
                        Console.WriteLine("\nSuspicious PID/TID");
                        Console.WriteLine("\n------------------------------");
                        PrintLogs("Suspicious_PID_TID_Log.txt");
                        pid_tid_history = true;

                        while (true)
                        {
                            var input3 = Console.ReadLine();
                            if (input3 == "q")
                            {
                                pid_tid_history = false;
                                break;
                            }
                            else
                            {
                                Console.WriteLine("\nEnter 'q' to go back\n");
                            }
                        }
                    }
                    else if (user_input == "3")
                    {
                        Console.WriteLine("\n------------------------------");
                        Console.WriteLine("\nBeacon command history");
                        Console.WriteLine("\n------------------------------");
                        PrintLogs("Process_Log.txt");
                        command_history = true;
                        while (true)
                        {
                            var input3 = Console.ReadLine();
                            if (input3 == "q")
                            {
                                command_history = false;
                                break;
                            }
                            else
                            {
                                Console.WriteLine("\nEnter 'q' to go back\n");
                            }
                        }
                    }
                    else if (user_input == "4")
                    {
                        Console.WriteLine("\n------------------------------");
                        Console.WriteLine("\nTerminate process history");
                        Console.WriteLine("\n------------------------------");
                        PrintLogs("Terminate_Log.txt");
                        terminate_history = true;
                        while (true)
                        {
                            var input3 = Console.ReadLine();
                            if (input3 == "q")
                            {
                                terminate_history = false;
                                break;
                            }
                            else
                            {
                                Console.WriteLine("\nEnter 'q' to go back\n");
                            }
                        }
                    }

                    else if (user_input == "5")
                    {
                        Console.WriteLine("\n------------------------------");
                        Console.WriteLine("\nFile history");
                        Console.WriteLine("\n------------------------------");
                        PrintLogs("File_Log.txt");
                        file_history = true;

                        while (true)
                        {
                            var input3 = Console.ReadLine();
                            if (input3 == "q")
                            {
                                file_history = false;
                                break;
                            }
                            else
                            {
                                Console.WriteLine("\nEnter 'q' to go back\n");
                            }
                        }
                    }
                    else if (user_input == "7")
                    {
                        monitor = false;
                    }
                }
                else if (action)
                {
                    Console.WriteLine("\n------------------------------");
                    Console.WriteLine("\nACTION\n");
                    Console.WriteLine("   [1] Suspend TID");
                    Console.WriteLine("   [2] Action Option 2");
                    Console.WriteLine("   [3] Action Option 3");
                    Console.WriteLine("   [4] Action Option 4");
                    Console.WriteLine("   [5] Main menu\n");
                    Console.Write("> ");
                    var input2 = Console.ReadLine();

                    if (input2 == "1")
                    {
                        Console.WriteLine("\n------------------------------");
                        Console.WriteLine("\nTERMINATE TID\n");

                        Console.Write("[*] Enter TID to terminate ('q' to quit) > ");

                        var tid = Console.ReadLine();
                        
                        try
                        {
                            if (tid == "q")
                            {
                                Console.WriteLine("\n[*] Quit");
                            }
                            else
                            {
                                TerminateTID(int.Parse(tid));
                            }
                        }
                        catch (System.FormatException)
                        {
                            Console.WriteLine("\n[!] Incorrect TID");
                        }

                        
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

                    //if (!proc_timestamp.ContainsKey(proc.Id))
                    if (!threadIDs2.ContainsKey(proc.Id))
                    {

                        try
                        {
                            ProcessThreadCollection myThreads = proc.Threads;

                            foreach (ProcessThread pt in myThreads)
                            {
                                try
                                {
                                    if (pt.WaitReason.ToString() == "ExecutionDelay") //PID 4 is SYSTEM using SMB and is LOUD (need to double check) proc.Id != 4
                                    {
                                        if (!threadIDs2.ContainsKey(proc.Id))
                                        {
                                            if (verbose || pid_tid_history)
                                            {
                                                // Notify new processes
                                                Console.WriteLine("\n{0} => New Process with suspicious Thread: {1} -> {2} ({3})", DateTime.Now, proc.ProcessName, proc.Id, pt.Id);
                                            }

                                            // Log suspicious PID/TID
                                            LogWriter.LogWritePID_TID(proc.ProcessName, proc.Id, pt.Id);


                                            // Add thread ID to threadID dictionary to keep track
                                            threadIDs.Add(proc.Id, pt.Id);

                                            threadIDs2[proc.Id] = new List<int>();
                                            threadIDs2[proc.Id].Add(pt.Id);

                                            // Get current timestamp of processes to calculate time delta for next network event
                                            milliseconds = DateTime.Now.Subtract(DateTime.MinValue.AddYears(1969)).TotalMilliseconds;

                                            score2[proc.Id] = new Dictionary<int, List<double>>();
                                            score2[proc.Id][pt.Id] = new List<double>();
                                            score2[proc.Id][pt.Id].Add(milliseconds);
                                            score2[proc.Id][pt.Id].Add(0); //time_delta
                                            score2[proc.Id][pt.Id].Add(0); //derivative
                                            score2[proc.Id][pt.Id].Add(0); //Count
                                            score2[proc.Id][pt.Id].Add(1); //Score
                                        }

                                        else if (threadIDs2[proc.Id].Count > 0)
                                        {
                                            if (verbose || pid_tid_history)
                                            {
                                                // Notify new processes
                                                Console.WriteLine("\n{0} => New Process with suspicious Thread: {1} -> {2} ({3})", DateTime.Now, proc.ProcessName, proc.Id, pt.Id);
                                            }

                                            // Log suspicious PID/TID
                                            LogWriter.LogWritePID_TID(proc.ProcessName, proc.Id, pt.Id);

                                            // Add new thread
                                            threadIDs2[proc.Id].Add(pt.Id);

                                            // Get current timestamp of processes to calculate time delta for next network event
                                            milliseconds = DateTime.Now.Subtract(DateTime.MinValue.AddYears(1969)).TotalMilliseconds;

                                            // Initialize score
                                            score2[proc.Id][pt.Id] = new List<double>();
                                            score2[proc.Id][pt.Id].Add(milliseconds);
                                            score2[proc.Id][pt.Id].Add(0); //time_delta
                                            score2[proc.Id][pt.Id].Add(0); //derivative
                                            score2[proc.Id][pt.Id].Add(0); //Count
                                            score2[proc.Id][pt.Id].Add(1); //Score

                                        }

                                    }
                                    
                                }
                                catch { continue; }
                            }
                        }
                        catch { continue; }
                    }

                    else
                    {
                        ProcessThreadCollection myThreads = proc.Threads;

                        foreach (ProcessThread pt in myThreads)
                        {
                            try
                            {
                                if (pt.WaitReason.ToString() == "ExecutionDelay")
                                {
                                    if (!threadIDs2[proc.Id].Contains(pt.Id))
                                    {

                                        // Get current timestamp of processes to calculate time delta for next network event
                                        milliseconds = DateTime.Now.Subtract(DateTime.MinValue.AddYears(1969)).TotalMilliseconds;

                                        threadIDs2[proc.Id].Add(pt.Id);
                                        score2[proc.Id][pt.Id] = new List<double>();
                                        score2[proc.Id][pt.Id].Add(milliseconds);
                                        score2[proc.Id][pt.Id].Add(0); //time_delta
                                        score2[proc.Id][pt.Id].Add(0); //derivative
                                        score2[proc.Id][pt.Id].Add(0); //Count
                                        score2[proc.Id][pt.Id].Add(1); //Score

                                        if (verbose || pid_tid_history)
                                        {
                                            Console.WriteLine("\n{0} => New Process with suspicious Thread: {1} -> {2} ({3})", DateTime.Now, proc.ProcessName, proc.Id, pt.Id);
                                        }
                                        LogWriter.LogWritePID_TID(proc.ProcessName, proc.Id, pt.Id);
                                    }
                                }
                            }
                            catch { continue; }
                        }

                    }
                }

                // Remove dead processes from Dictionaries
                foreach (var pid in new List<int>(score2.Keys))
                {
                    try
                    {
                        Process.GetProcessById(pid);
                    }
                    catch (ArgumentException)
                    {

                        threadIDs2.Remove(pid);
                        score2.Remove(pid);

                        if (verbose)
                        {
                            Console.WriteLine("\nDEAD/REMOVED PID: {0}", pid);
                        }
                    }
                }

                // Lock ETW Collector
                var Lock = new object();
                Task.Run(() =>
                {

                    TraceEventSession session1 = null;

                    using (session1 = new TraceEventSession("AndrewsETWSession"))
                    {

                        // Kill ETW session right before process ends since it will stay alive if session not disposed 
                        Console.CancelKeyPress += (object sender, ConsoleCancelEventArgs cancelArgs) =>
                        {
                            if (session1 != null)
                            {
                                session1.Dispose();
                            }

                            cancelArgs.Cancel = false;
                        };

                        // Enable ETW providers to capture data
                        session1.EnableProvider("Microsoft-Windows-WinINet", Microsoft.Diagnostics.Tracing.TraceEventLevel.Informational); // network traffic
                        session1.EnableProvider("Microsoft-Windows-Kernel-Process", Microsoft.Diagnostics.Tracing.TraceEventLevel.Informational, 0x00); // process start and commands
                        session1.EnableProvider("Microsoft-Windows-Kernel-File", Microsoft.Diagnostics.Tracing.TraceEventLevel.Informational, 0x00); // file and directory changes
                        session1.EnableProvider("Microsoft-Windows-Kernel-Audit-API-Calls", Microsoft.Diagnostics.Tracing.TraceEventLevel.Informational, 0x00); // remote process termination

                        var parser = session1.Source.Dynamic;

                        parser.All += e =>
                        {
                            try
                            {
                                if (e.ProviderName == "Microsoft-Windows-WinINet")
                                {
                                    // Log only if coming from suspicious TID
                                    //if (threadIDs[e.ProcessID] == e.ThreadID)
                                    if (threadIDs2[e.ProcessID].Contains(e.ThreadID))
                                    {
                                        // Need to verify if ServerName is the actual IP 
                                        if (e.PayloadByName("ServerName").ToString() != "" && e.PayloadByName("ServerPort").ToString() != "")
                                        {
                                            
                                           

                                            // Get current time
                                            milliseconds = DateTime.Now.Subtract(DateTime.MinValue.AddYears(1969)).TotalMilliseconds;

                                            // Calculate time difference between beacon callbacks
                                            delta = milliseconds - score2[e.ProcessID][e.ThreadID][0];
                                            score2[e.ProcessID][e.ThreadID][0] = milliseconds; // SCORE2

                                            // Calculate derivative of delta time between callbacks
                                            dev = score2[e.ProcessID][e.ThreadID][1] - delta;
                                            score2[e.ProcessID][e.ThreadID][1] = delta; //SCORE2

                                            // Add 1st derivative of delta to list
                                            score2[e.ProcessID][e.ThreadID][2] = dev; //SCORE2

                                            //SCORE2 Count

                                            score2[e.ProcessID][e.ThreadID][3] += 1;

                                            // Calculate score for process
                                            // If the derivative is 0, add fixed points instead of infinity 
                                            if (dev == 0)
                                            {
                                                
                                                score2[e.ProcessID][e.ThreadID][4] += 3;
                                            }
                                            else
                                            {
                                                //closer delta is to zero, the higher the score. Yes, jitters will impact score... but how much? ;)
                                                
                                                score2[e.ProcessID][e.ThreadID][4] += Math.Abs(100.0 / dev);
                                            }

                                            // Log number of IP callbacks by PID/TID
                                            //{ PID : {TID : [IP, COUNT]} }
                                            if (!PID_TID_IP.ContainsKey(e.ProcessID))
                                            {
                                                
                                                PID_TID_IP[e.ProcessID] = new Dictionary<int, List<string>> ();
                                                PID_TID_IP[e.ProcessID][e.ThreadID] = new List<string>();

                                                // IP
                                                PID_TID_IP[e.ProcessID][e.ThreadID].Add(e.PayloadByName("ServerName").ToString());
                                                // Count
                                                PID_TID_IP[e.ProcessID][e.ThreadID].Add(score2[e.ProcessID][e.ThreadID][3].ToString());
                                                
                                                if (network_verbose)
                                                {
                                                    foreach (KeyValuePair<int, List<string>> kvp in PID_TID_IP[e.ProcessID])
                                                    {
                                                        Console.WriteLine(string.Format("Proc = {0} TID = {1}, IP = {2} Count = {3}", Process.GetProcessById(e.ProcessID).ProcessName, kvp.Key, kvp.Value[0], kvp.Value[1]));
                                                    }
                                                }
                                            }

                                            else if (!PID_TID_IP[e.ProcessID].ContainsKey(e.ThreadID))
                                            {
                                                PID_TID_IP[e.ProcessID][e.ThreadID] = new List<string>();
                                                
                                                // IP
                                                PID_TID_IP[e.ProcessID][e.ThreadID].Add(e.PayloadByName("ServerName").ToString());
                                                // Count
                                                PID_TID_IP[e.ProcessID][e.ThreadID].Add(score2[e.ProcessID][e.ThreadID][3].ToString());

                                            }

                                            else
                                            {
                                                // Change count
                                                PID_TID_IP[e.ProcessID][e.ThreadID][1] = score2[e.ProcessID][e.ThreadID][3].ToString();
                                                if (network_verbose)
                                                {
                                                    foreach (KeyValuePair<int, List<string>> kvp in PID_TID_IP[e.ProcessID])
                                                    {

                                                        Console.WriteLine(string.Format("Proc = {0} TID = {1}, IP = {2} Count = {3}", Process.GetProcessById(e.ProcessID).ProcessName, kvp.Key, kvp.Value[0], kvp.Value[1]));
                                                    }
                                                }
                                              
                                                // ^^ NEED TO LOG THIS
                                            }


                                            // Log network traffic to disk
                                            LogWriter.LogWriteNetwork(Process.GetProcessById(e.ProcessID).ProcessName, e.ProcessID, e.ThreadID, e.PayloadByName("ServerName"), e.PayloadByName("ServerPort"), (int)score2[e.ProcessID][e.ThreadID][3]);

                                            // Only show table if in Monitor -> Beacon Score
                                            if (beacon_score)
                                            {
                                                Console.Clear();
                                                Console.WriteLine("\nProcess: {0} Thread {1}\n", e.ProcessID, e.ThreadID);
                                                Console.WriteLine(" Destination: {0}:{1}", e.PayloadByName("ServerName"), e.PayloadByName("ServerPort"));
                                                Console.WriteLine(" Delta time: {0}", delta);
                                                Console.WriteLine(" 1st derivative of delta = {0}", dev);
                                                Console.WriteLine(" Total # of derivatives: " + score2[e.ProcessID][e.ThreadID][3]);
                                                Console.WriteLine(" Date/Time: {0}", e.TimeStamp);
                                                Console.WriteLine(" Timestamp: {0}", e.TimeStampRelativeMSec);
                                                Console.WriteLine(" Score: {0}\n", score2[e.ProcessID][e.ThreadID][4]);

                                                // Need this table to be better with more detail. Need to read ConsoleTable documentation
                                                Console.WriteLine("   Suspicious Network PID Score");
      

                                                //SCORE 2

                                                var table = new ConsoleTable("Process","PID", "TID", "SCORE");
                                                
                                                foreach (int pid in score2.Keys)
                                                {
                                                    //Console.WriteLine("pid: {0}", pid);
                                                    foreach (KeyValuePair<int, List<double>> kvp1 in score2[pid])
                                                    {
                                                       
                                                     //   Console.WriteLine("second: {0}", kvp1.Key);
                                                      //  Console.WriteLine("third: {0}", score2[pid][kvp1.Key][4]);
                                                        table.AddRow(Process.GetProcessById(pid).ProcessName, pid, kvp1.Key, kvp1.Value[4]);
                                                    }

                                                }
                                                table.Write();
                                                //Console.WriteLine(table);
                                                //Console.WriteLine(table);
                                                Console.WriteLine("\n--------------------------------------------------------");
                                            }


                                        }
                                    }
                                }

                                else if (e.ProviderName == "Microsoft-Windows-Kernel-Process")
                                {
                                    // Log only if coming from suspicious TID
                                    if (e.ProcessID != -1 && threadIDs2[e.ProcessID].Contains(e.ThreadID))
                                    {

                                        // Splitted message to get potentially spoofed PPID
                                        string[] messageBits = e.FormattedMessage.Replace(",", string.Empty).Split(' ');
                                        var command = messageBits[17];
                                        if (verbose || command_history)
                                        {
                                            // This looks so ugly but meh
                                            Console.WriteLine("\n------------------------------\n[!] COMMAND\n\nParent Process: {0} {1}\n -> Child Procces: {2}\nFake Parent Process: {3}\nThread ID: {4}\nMessage: {5}\nTime: {6}\n",
                                                Process.GetProcessById(e.ProcessID).ProcessName, e.ProcessID,
                                                        e.PayloadByName("ProcessID"), int.Parse(messageBits[10]), e.ThreadID, command, DateTime.Now);
                                        }

                                        // Check if PPID spoofing
                                        if (e.ProcessID != int.Parse(messageBits[10]))
                                        {
                                            if (verbose || command_history)
                                            {
                                                Console.WriteLine("\n[!] PPID SPOOFING DETECTED !");
                                                isSpoof = true;
                                            }

                                        }

                                        // Log to disk
                                        LogWriter.LogWriteProcess(Process.GetProcessById(e.ProcessID).ProcessName, e.ProcessID,
                                                    e.PayloadByName("ProcessID"), int.Parse(messageBits[10]), e.ThreadID, command, isSpoof);
                                        isSpoof = false;
                                    }
                                }

                                //log remote process termination from suspicious PID/TID
                                // if remote process is Sysmon, delete process (TODO)
                                // need to check different OS implementations
                                else if (e.ProviderName == "Microsoft-Windows-Kernel-Audit-API-Calls")
                                {

                                    //Log only if coming from suspicious TID
                                    if (threadIDs2[e.ProcessID].Contains(e.ThreadID))
                                    {
                                        //Event ID 2 means remote process termination
                                        if (e.EventName.Split('(', ')')[1] == "2")
                                        {
                                            if (verbose || terminate_history)
                                            {
                                                Console.WriteLine("\n------------------------------");
                                                Console.WriteLine("[!] TERMINATION");
                                                Console.WriteLine("\nProcess: {0}\nPID: {1}\nTID: {2}\nVictim: {3}\n", Process.GetProcessById(e.ProcessID).ProcessName, e.ProcessID, e.ThreadID, e.PayloadByName("TargetProcessId"));
                                            }

                                            LogWriter.LogWriteTermination(Process.GetProcessById(e.ProcessID).ProcessName, e.ProcessID, e.ThreadID, e.PayloadByName("TargetProcessId"));

                                        }
                                    }
                                }

                                else if (e.ProviderName == "Microsoft-Windows-Kernel-File")
                                {

                                    // Log only if coming from suspicious TID
                                    if (threadIDs2[e.ProcessID].Contains(e.ThreadID))
                                    {


                                        //Console.WriteLine("EventName: {0}", e.EventName);



                                        // Check directory enumeration
                                        if (e.PayloadByName("FileName").ToString() == "*" && e.EventName == "DirEnum")
                                        {
                                            if (verbose || file_history)
                                            {
                                                Console.WriteLine("\n------------------------------\n[!] FILE\n\nProcess: {0}\nPID: {1}\nTID: {2}\n", Process.GetProcessById(e.ProcessID).ProcessName, e.ProcessID, e.ThreadID);
                                                Console.WriteLine("[*] Directory Enumeration");
                                            }

                                            // Log to disk
                                            LogWriter.LogWriteFile(Process.GetProcessById(e.ProcessID).ProcessName, e.ProcessID, e.ThreadID, "Directory Enumeration");
                                        }

                                        // New file detection
                                        else if (e.EventName == "CreateNewFile")
                                        {
                                            if (verbose || file_history)
                                            {
                                                Console.WriteLine("\n------------------------------\n[!] FILE\n\nProcess: {0}\nPID: {1}\nTID: {2}\n", Process.GetProcessById(e.ProcessID).ProcessName, e.ProcessID, e.ThreadID);
                                                Console.WriteLine("[*] New File -> {0}", e.PayloadByName("FileName"));
                                            }

                                            // Log to disk
                                            LogWriter.LogWriteFile(Process.GetProcessById(e.ProcessID).ProcessName, e.ProcessID, e.ThreadID, "New File", e.PayloadByName("FileName").ToString());
                                        }

                                        // REMOVED or MODIFIED file/path detection
                                        else if (e.PayloadByName("CreateOptions").ToString() == "18874368" || e.PayloadByName("CreateOptions").ToString() == "18874432")
                                        {
                                            if (verbose || file_history)
                                            {
                                                Console.WriteLine("\n------------------------------\n[!] FILE\n\nProcess: {0}\nPID: {1}\nTID: {2}\n", Process.GetProcessById(e.ProcessID).ProcessName, e.ProcessID, e.ThreadID);
                                                Console.WriteLine("[*] Removed/Modified File -> {0}", e.PayloadByName("FileName"));
                                            }

                                            // Log to disk
                                            LogWriter.LogWriteFile(Process.GetProcessById(e.ProcessID).ProcessName, e.ProcessID, e.ThreadID, "New File", e.PayloadByName("FileName").ToString());
                                        }

                                        // Changing directory detection
                                        else if (e.PayloadByName("CreateOptions").ToString() == "16777249")
                                        {
                                            if (verbose || file_history)
                                            {
                                                Console.WriteLine("\n------------------------------\n[!] FILE\n\nProcess: {0}\nPID: {1}\nTID: {2}\n", Process.GetProcessById(e.ProcessID).ProcessName, e.ProcessID, e.ThreadID);
                                                Console.WriteLine("[*] Change directory -> {0}", e.PayloadByName("FileName"));
                                            }
                                            // Log to disk
                                            LogWriter.LogWriteFile(Process.GetProcessById(e.ProcessID).ProcessName, e.ProcessID, e.ThreadID, "Change Directory", e.PayloadByName("FileName").ToString());

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
        static void PrintLogs(string filename)
        {
            try
            {
                string[] lines = File.ReadAllLines(Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location) + "\\" + filename);
                foreach (string line in lines)
                {
                    Console.WriteLine(line);
                }
            }
            catch
            {
            }
        }
        static void TerminateTID(int tid)
        {
            IntPtr handle = OpenThread(ThreadAccess.SUSPEND_RESUME, false, (uint)tid);
            if (handle != IntPtr.Zero)
                SuspendThread(handle);
            Console.WriteLine("\n[*] Suspended TID: {0}", tid);

        }
        public enum ThreadAccess : int
        {
            TERMINATE = (0x0001),
            SUSPEND_RESUME = (0x0002),
            GET_CONTEXT = (0x0008),
            SET_CONTEXT = (0x0010),
            SET_INFORMATION = (0x0020),
            QUERY_INFORMATION = (0x0040),
            SET_THREAD_TOKEN = (0x0080),
            IMPERSONATE = (0x0100),
            DIRECT_IMPERSONATION = (0x0200)
        }

        
        //FIX BELOW

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern int SuspendThread(IntPtr hThread);

        [DllImport("kernel32.dll")]
        static extern IntPtr OpenThread(ThreadAccess dwDesiredAccess, bool bInheritHandle,
           uint dwThreadId);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        static extern bool CloseHandle(IntPtr hObject);

        [DllImport("kernel32.dll")]
        static extern bool TerminateThread(IntPtr hThread, uint dwExitCode);
    }
}