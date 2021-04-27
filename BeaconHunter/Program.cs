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


namespace BeaconHunter
{
    class Program
    {
        // Global variables 
        private static bool action = false;
        private static bool monitor = false;
        private static bool isSpoof = false;
        private static string input;
        private static double milliseconds;
        private static double dev;
        private static double delta;


        // Monitor bools
        private static bool verbose = true;
        private static bool network_verbose = true;
        private static bool beacon_score = false;
        private static bool pid_tid_history = false;
        private static bool command_history = false;
        private static bool terminate_history = false;
        private static bool file_history = false;
        private static bool ip_stats = false;
        private static bool dns_history = false;

        // Action bools
        private static bool network_score_threshold = false;
        private static string threshold;
        private static bool sysmon_protect = true;
        private static int sysmon_pid = 0;

        // Beacon score 
        private static Dictionary<int, Dictionary<int, List<double>>> score = new Dictionary<int, Dictionary<int, List<double>>>();

        // Keep record of PID and suspicious TID. Useful for ETW filtering later on!    // { PID : [TID,TID,...] }
        private static Dictionary<int, List<int>> threadIDs = new Dictionary<int, List<int>>();

        // Keep record of PID / TID network callback to IP      //{ PID : {TID : [IP, COUNT]} }
        private static Dictionary<int, Dictionary<int, List<string>>> PID_TID_IP = new Dictionary<int, Dictionary<int, List<string>>>();

        // Ignore TID list
        private static List<int> Ignore_TID = new List<int>();


        static void Main()
        {
            // You know it
            AsciiArt.BeaconHunter_AsciiArt();

            // Start ETW collector thread
            Thread etwcollect_thread = new Thread(new ThreadStart(ETWcollect));
            etwcollect_thread.IsBackground = true;
            etwcollect_thread.Start();

            // Initialize log folder 
            if (!Directory.Exists(Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location) + "\\Logs"))
            {
                Directory.CreateDirectory(Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location) + "\\Logs");
            }

            while (true)
            {
                if (monitor == false && action == false)
                {
                    Console.WriteLine("\n------------------------------");
                    Console.WriteLine("\nMAIN MENU");
                    Console.WriteLine("\n\n[1] Monitor");
                    Console.WriteLine("[2] Action");
                    Console.WriteLine("[3] System Verbose (default ON)");
                    Console.WriteLine("[4] Network Verbose (default ON)");
                    Console.WriteLine("[5] Protect Sysmon (default ON)\n");
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
                    else if (input == "5")
                    {

                        if (!sysmon_protect)
                        {
                            Console.WriteLine("\n[*] Sysmon Protection turned ON");
                            sysmon_protect = true;
                        }
                        else
                        {
                            Console.WriteLine("\n[*] Sysmon Protection turned OFF");
                            sysmon_protect = false;
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
                    Console.WriteLine("   [2] IP stats");
                    Console.WriteLine("   [3] DNS queries");
                    Console.WriteLine("   [4] Suspicious PID/TID history");
                    Console.WriteLine("   [5] Beacon shell/command history");
                    Console.WriteLine("   [6] Process terminate history");
                    Console.WriteLine("   [7] File system history");
                    Console.WriteLine("   [8] Ignore TID");
                    Console.WriteLine("   [9] Main menu\n");
                    Console.Write("> ");
                    var user_input = Console.ReadLine();

                    if (user_input == "1")
                    {
                        Console.WriteLine("\n------------------------------");
                        Console.WriteLine("\nNetwork Beacon Score");
                        Console.WriteLine("\n------------------------------");

                        NetworkBeaconScore();


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
                                Console.WriteLine("\n[*] Enter 'q' to go back.\n");
                                Console.Write("> ");
                            }
                        }
                    }

                    else if (user_input == "2")
                    {
                        Console.WriteLine("\n------------------------------");
                        Console.WriteLine("\nIP Stats");
                        Console.WriteLine("\n------------------------------");

                        IPStats();

                        ip_stats = true;

                        while (true)
                        {
                            var input3 = Console.ReadLine();
                            if (input3 == "q")
                            {
                                ip_stats = false;
                                break;
                            }
                            else
                            {
                                Console.WriteLine("\n[*] Enter 'q' to go back.\n");
                                Console.Write("> ");
                            }
                        }
                    }
                    else if (user_input == "3")
                    {
                        Console.WriteLine("\n------------------------------");
                        Console.WriteLine("\nDNS Queries");
                        Console.WriteLine("\n------------------------------");

                        PrintLogs("DNS_Log.txt");
                        dns_history = true;
                        while (true)
                        {
                            var input3 = Console.ReadLine();
                            if (input3 == "q")
                            {
                                dns_history = false;
                                break;
                            }
                            else
                            {
                                Console.WriteLine("\n[*] Enter 'q' to go back.\n");
                                Console.Write("> ");
                            }
                        }
                    }
                    else if (user_input == "4")
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
                                Console.WriteLine("\n[*] Enter 'q' to go back.\n");
                                Console.Write("> ");
                            }
                        }
                    }
                    else if (user_input == "5")
                    {
                        Console.WriteLine("\n------------------------------");
                        Console.WriteLine("\nBeacon Command History");
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
                                Console.WriteLine("\n[*] Enter 'q' to go back.\n");
                                Console.Write("> ");
                            }
                        }
                    }
                    else if (user_input == "6")
                    {
                        Console.WriteLine("\n------------------------------");
                        Console.WriteLine("\nTerminate Process History");
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
                                Console.WriteLine("\n[*] Enter 'q' to go back.\n");
                                Console.Write("> ");
                            }
                        }
                    }

                    else if (user_input == "7")
                    {
                        Console.WriteLine("\n------------------------------");
                        Console.WriteLine("\nFile History");
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
                                Console.WriteLine("\n[*] Enter 'q' to go back.\n");
                                Console.Write("> ");
                            }
                        }
                    }
                    else if (user_input == "8")
                    {
                        Console.WriteLine("\n------------------------------");
                        Console.WriteLine("\nIgnore TID");
                        Console.WriteLine("\n------------------------------\n");

                        while (true)
                        {
                            try
                            {
                                Console.Write("[*] Enter TID to ignore from monitoring ('q' to go back) > ");
                                var input3 = Console.ReadLine();
                                if (input3 == "q")
                                {

                                    break;
                                }

                                else if (Convert.ToInt32(input3) < 65535)
                                {
                                    Ignore_TID.Add(Convert.ToInt32(input3));
                                    Console.WriteLine("[*] Ignoring TID {0}", input3);
                                }
                            }
                            catch 
                            {
                                //Console.WriteLine("[!] Invalid input ");
                            }
                        }
                    }
                    else if (user_input == "9")
                    {
                        monitor = false;
                    }
                }
                else if (action)
                {
                    Console.WriteLine("\n------------------------------");
                    Console.WriteLine("\nACTION\n");
                    Console.WriteLine("   [1] Manually suspend TID");
                    Console.WriteLine("   [2] Automatically suspend TID above score threshold");
                    Console.WriteLine("   [3] View manually suspended TID history");
                    Console.WriteLine("   [4] View automatically suspended TIDs from score threshold");
                    Console.WriteLine("   [5] Main menu\n");
                    Console.Write("> ");
                    var input2 = Console.ReadLine();

                    if (input2 == "1")
                    {
                        Console.WriteLine("\n------------------------------");
                        Console.WriteLine("\nTERMINATE TID\n");

                        while (true)
                        {
                            Console.Write("[*] Enter TID to suspend ('q' to quit) > ");
                            var tid = Console.ReadLine();
                            try
                            {
                                if (tid == "q")
                                {
                                    Console.WriteLine("\n[*] Quit.");
                                    break;
                                }
                                else
                                {
                                    SuspendTID(int.Parse(tid));
                                }
                            }
                            catch (System.FormatException)
                            {
                            }
                            catch (System.OverflowException)
                            {
                                Console.WriteLine("\n[!] Value was either too large or too small for TID.\n");
                            }
                        }


                    }
                    else if (input2 == "2")
                    {
                        Console.WriteLine("\n------------------------------");
                        Console.WriteLine("\nSCORE THRESHOLD\n");

                        while (true)
                        {

                            Console.Write("[*] Enter network score threshold for thread suspension ('0' to remove threshold || 'q' to go back) > ");

                            var tmp_threshold = threshold;
                            threshold = Console.ReadLine();

                            try
                            {
                                if (threshold == "q")
                                {
                                    Console.WriteLine("\n[*] Quit.");
                                    threshold = tmp_threshold;
                                    break;
                                }
                                else if (threshold == "0")
                                {
                                    network_score_threshold = false;
                                    Console.WriteLine("\n[*] Removed threshold for thread suspension.\n");
                                    break;
                                }
                                else if (Convert.ToDouble(threshold) <= 1)
                                {
                                    Console.WriteLine("\n[!] Threshold must be above 1.\n");
                                    threshold = tmp_threshold;
                                }

                                else
                                {
                                    network_score_threshold = true;
                                    ThresholdChecker(Convert.ToDouble(threshold));
                                }
                            }
                            catch (System.FormatException)
                            {
                            }
                        }
                    }
                    else if (input2 == "3")
                    {
                        Console.WriteLine("\n------------------------------");
                        Console.WriteLine("\nManually Suspended TIDs");
                        Console.WriteLine("\n------------------------------");

                        PrintLogs("Suspended_TID_Log.txt");

                        while (true)
                        {
                            var input3 = Console.ReadLine();
                            if (input3 == "q")
                            {
                                break;
                            }
                            else
                            {
                                Console.WriteLine("\n[*] Enter 'q' to go back.\n");
                                Console.Write("> ");
                            }
                        }
                    }
                    else if (input2 == "4")
                    {
                        Console.WriteLine("\n------------------------------");
                        Console.WriteLine("\nAutomatically Suspended TIDs");
                        Console.WriteLine("\n------------------------------");

                        PrintLogs("Score_Threshold_Log.txt");

                        while (true)
                        {
                            var input3 = Console.ReadLine();
                            if (input3 == "q")
                            {
                                break;
                            }
                            else
                            {
                                Console.WriteLine("\n[*] Enter 'q' to go back.\n");
                                Console.Write("> ");
                            }
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
                    if (!threadIDs.ContainsKey(proc.Id))
                    {
                        try
                        {
                            ProcessThreadCollection myThreads = proc.Threads;

                            foreach (ProcessThread pt in myThreads)
                            {
                                try
                                {
                                    if (pt.WaitReason.ToString() == "ExecutionDelay")
                                    {
                                        if (!threadIDs.ContainsKey(proc.Id))
                                        {
                                            if (verbose || pid_tid_history)
                                            {
                                                // Notify new processes
                                                Console.WriteLine("\n[*] New Process with suspicious Thread: {0} ({1}) -> {2}", proc.ProcessName, proc.Id, pt.Id);
                                            }

                                            // Log suspicious PID/TID
                                            LogWriter.LogWritePID_TID(proc.ProcessName, proc.Id, pt.Id);


                                            // Add thread ID to threadID dictionary to keep track
                                            threadIDs[proc.Id] = new List<int>();
                                            threadIDs[proc.Id].Add(pt.Id);

                                            // Get current timestamp of processes to calculate time delta for next network event
                                            milliseconds = DateTime.Now.Subtract(DateTime.MinValue.AddYears(1969)).TotalMilliseconds;

                                            score[proc.Id] = new Dictionary<int, List<double>>();
                                            score[proc.Id][pt.Id] = new List<double>();
                                            score[proc.Id][pt.Id].Add(milliseconds);
                                            score[proc.Id][pt.Id].Add(0); // Time delta
                                            score[proc.Id][pt.Id].Add(0); // Derivative
                                            score[proc.Id][pt.Id].Add(0); // Count
                                            score[proc.Id][pt.Id].Add(1); // Score
                                        }

                                        else if (threadIDs[proc.Id].Count > 0)
                                        {
                                            if (verbose || pid_tid_history)
                                            {
                                                // Notify new processes
                                                Console.WriteLine("\n[*] New Process with suspicious Thread: {0} ({1}) -> {2}", proc.ProcessName, proc.Id, pt.Id);
                                            }

                                            // Log suspicious PID/TID
                                            LogWriter.LogWritePID_TID(proc.ProcessName, proc.Id, pt.Id);

                                            // Add new thread for ETW filtering
                                            threadIDs[proc.Id].Add(pt.Id);

                                            // Get current timestamp of processes to calculate time delta for next network event
                                            milliseconds = DateTime.Now.Subtract(DateTime.MinValue.AddYears(1969)).TotalMilliseconds;

                                            // Initialize score
                                            score[proc.Id][pt.Id] = new List<double>();
                                            score[proc.Id][pt.Id].Add(milliseconds);
                                            score[proc.Id][pt.Id].Add(0); // Time delta
                                            score[proc.Id][pt.Id].Add(0); // Derivative
                                            score[proc.Id][pt.Id].Add(0); // Count
                                            score[proc.Id][pt.Id].Add(1); // Score

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
                                    if (!threadIDs[proc.Id].Contains(pt.Id))
                                    {

                                        // Get current timestamp of processes to calculate time delta for next network event
                                        milliseconds = DateTime.Now.Subtract(DateTime.MinValue.AddYears(1969)).TotalMilliseconds;

                                        threadIDs[proc.Id].Add(pt.Id);
                                        score[proc.Id][pt.Id] = new List<double>();
                                        score[proc.Id][pt.Id].Add(milliseconds);
                                        score[proc.Id][pt.Id].Add(0); // Time_delta
                                        score[proc.Id][pt.Id].Add(0); // Derivative
                                        score[proc.Id][pt.Id].Add(0); // Count
                                        score[proc.Id][pt.Id].Add(1); // Score

                                        if (verbose || pid_tid_history)
                                        {
                                            Console.WriteLine("\n[*] New Process with suspicious Thread: {0} ({1}) -> {2}", proc.ProcessName, proc.Id, pt.Id);
                                        }
                                        LogWriter.LogWritePID_TID(proc.ProcessName, proc.Id, pt.Id);
                                    }
                                }
                            }
                            catch { continue; }
                        }

                    }

                    if (sysmon_protect)
                    {
                        // Find sysmon process
                        if (proc.ProcessName == "Sysmon")
                        {
                            sysmon_pid = proc.Id;
                        }
                    }

                }

                // Remove dead processes from Dictionaries
                foreach (var pid in new List<int>(score.Keys))
                {
                    try
                    {
                        Process.GetProcessById(pid);
                    }
                    catch (ArgumentException)
                    {

                        threadIDs.Remove(pid);
                        score.Remove(pid);

                        if (verbose)
                        {
                            Console.WriteLine("\n[!] DEAD/REMOVED PID: {0}\n", pid);
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
                        session1.EnableProvider("Microsoft-Windows-WinINet", Microsoft.Diagnostics.Tracing.TraceEventLevel.Informational); // Network traffic
                        session1.EnableProvider("Microsoft-Windows-Kernel-Process", Microsoft.Diagnostics.Tracing.TraceEventLevel.Informational, 0x00); // Process start and commands
                        session1.EnableProvider("Microsoft-Windows-Kernel-File", Microsoft.Diagnostics.Tracing.TraceEventLevel.Informational, 0x00); // File and diretory changes
                        session1.EnableProvider("Microsoft-Windows-Kernel-Audit-API-Calls", Microsoft.Diagnostics.Tracing.TraceEventLevel.Informational, 0x00); // Remote process termination
                        session1.EnableProvider("Microsoft-Windows-DNS-Client", Microsoft.Diagnostics.Tracing.TraceEventLevel.Informational, 0x00); // DNS queries                        

                        var parser = session1.Source.Dynamic;

                        parser.All += e =>
                        {
                            try
                            {
                                if (e.ProviderName == "Microsoft-Windows-WinINet")
                                {
                                    // Log only if coming from suspicious TID
                                    if (threadIDs[e.ProcessID].Contains(e.ThreadID))
                                    {
                                        // Need to verify if ServerName is the actual IP 
                                        if (e.PayloadByName("ServerName").ToString() != "" && e.PayloadByName("ServerPort").ToString() != "")
                                        {

                                            // Get current time
                                            milliseconds = DateTime.Now.Subtract(DateTime.MinValue.AddYears(1969)).TotalMilliseconds;

                                            // Calculate time difference between beacon callbacks
                                            delta = milliseconds - score[e.ProcessID][e.ThreadID][0];
                                            score[e.ProcessID][e.ThreadID][0] = milliseconds;

                                            // Calculate derivative of delta time between callbacks
                                            dev = score[e.ProcessID][e.ThreadID][1] - delta;
                                            score[e.ProcessID][e.ThreadID][1] = delta;

                                            // Add 1st derivative of delta to list
                                            score[e.ProcessID][e.ThreadID][2] = dev;

                                            //score Count
                                            score[e.ProcessID][e.ThreadID][3] += 1;

                                            // Calculate score for process
                                            // If the derivative is 0, add fixed points instead of infinity since formula is 100/x
                                            if (dev == 0)
                                            {

                                                score[e.ProcessID][e.ThreadID][4] += 3;
                                            }
                                            else
                                            {
                                                //closer delta is to zero, the higher the score. Yes, jitters will impact score... but how much? ;)
                                                score[e.ProcessID][e.ThreadID][4] += Math.Abs(100.0 / dev);
                                            }

                                            // Log number of IP callbacks by PID/TID
                                            //{ PID : {TID : [IP, COUNT]} }
                                            if (!PID_TID_IP.ContainsKey(e.ProcessID))
                                            {

                                                PID_TID_IP[e.ProcessID] = new Dictionary<int, List<string>>();
                                                PID_TID_IP[e.ProcessID][e.ThreadID] = new List<string>();

                                                // IP
                                                PID_TID_IP[e.ProcessID][e.ThreadID].Add(e.PayloadByName("ServerName").ToString());
                                                // Port
                                                PID_TID_IP[e.ProcessID][e.ThreadID].Add(e.PayloadByName("ServerPort").ToString());
                                                // Count
                                                PID_TID_IP[e.ProcessID][e.ThreadID].Add(score[e.ProcessID][e.ThreadID][3].ToString());

                                                if (network_verbose)
                                                {
                                                    foreach (KeyValuePair<int, List<string>> tid in PID_TID_IP[e.ProcessID])
                                                    {
                                                        Console.WriteLine(string.Format("[*] Network callback -> Process: {0} ({1}) | TID: {2} | RHOST: {3} | RPORT: {4} | Count: {5}", Process.GetProcessById(e.ProcessID).ProcessName, e.ProcessID, tid.Key, tid.Value[0], tid.Value[1], tid.Value[2]));
                                                    }
                                                }
                                            }

                                            else if (!PID_TID_IP[e.ProcessID].ContainsKey(e.ThreadID))
                                            {
                                                PID_TID_IP[e.ProcessID][e.ThreadID] = new List<string>();

                                                // IP
                                                PID_TID_IP[e.ProcessID][e.ThreadID].Add(e.PayloadByName("ServerName").ToString());
                                                // Port
                                                PID_TID_IP[e.ProcessID][e.ThreadID].Add(e.PayloadByName("ServerPort").ToString());
                                                // Count
                                                PID_TID_IP[e.ProcessID][e.ThreadID].Add(score[e.ProcessID][e.ThreadID][3].ToString());

                                            }

                                            else
                                            {
                                                // Change count
                                                PID_TID_IP[e.ProcessID][e.ThreadID][2] = score[e.ProcessID][e.ThreadID][3].ToString();
                                                if (network_verbose)
                                                {
                                                    foreach (KeyValuePair<int, List<string>> tid in PID_TID_IP[e.ProcessID])
                                                    {

                                                        Console.WriteLine(string.Format("[*] Network callback -> Process: {0} ({1}) | TID: {2} | RHOST: {3} | RPORT: {4} | Count: {5}", Process.GetProcessById(e.ProcessID).ProcessName, e.ProcessID, tid.Key, tid.Value[0], tid.Value[1], tid.Value[2]));
                                                    }
                                                }
                                            }


                                            // Log network traffic to disk
                                            LogWriter.LogWriteNetwork(Process.GetProcessById(e.ProcessID).ProcessName, e.ProcessID, e.ThreadID, e.PayloadByName("ServerName"), e.PayloadByName("ServerPort"), (int)score[e.ProcessID][e.ThreadID][3]);

                                            // Only show table if in Monitor -> Beacon Score
                                            if (beacon_score)
                                            {
                                                Console.Clear();
                                                Console.WriteLine("\n------------------------------");
                                                Console.WriteLine("\nNetwork Beacon Score");
                                                Console.WriteLine("\n------------------------------");
                                                Console.WriteLine("\nProcess: {0} ({1}) -> Thread {2}\n", Process.GetProcessById(e.ProcessID).ProcessName, e.ProcessID, e.ThreadID);
                                                Console.WriteLine(" Destination: {0}:{1}", e.PayloadByName("ServerName"), e.PayloadByName("ServerPort"));
                                                Console.WriteLine(" Callback delta: {0} ms", delta);
                                                Console.WriteLine(" 1st derivative of delta: {0} ms", dev);
                                                Console.WriteLine(" Date/Time: {0}\n", e.TimeStamp);

                                                NetworkBeaconScore();
                                            }

                                            // Show IP and PORT stats by thread
                                            if (ip_stats)
                                            {
                                                IPStats();
                                            }

                                            // Check if TID above threshold
                                            if (network_score_threshold)
                                            {
                                                ThresholdChecker(Convert.ToDouble(threshold));
                                            }
                                        }
                                    }
                                }

                                else if (e.ProviderName == "Microsoft-Windows-Kernel-Process")
                                {
                                    // Log only if coming from suspicious TID
                                    if (e.ProcessID != -1 && threadIDs[e.ProcessID].Contains(e.ThreadID))
                                    {

                                        // Splitted message to get potentially spoofed PPID
                                        string[] messageBits = e.FormattedMessage.Replace(",", string.Empty).Split(' ');
                                        var command = messageBits[17];
                                        var spoofable_process = int.Parse(messageBits[10]);

                                        if ((verbose || command_history))
                                        {
                                            // This looks so ugly but whatever
                                            Console.WriteLine("\n------------------------------\n[!] COMMAND\n\nParent Process: {0} {1}\n -> Child Procces: {2}\nSpoofable Process: {3}\nThread ID: {4}\nMessage: {5}\nTime: {6}\n",
                                                Process.GetProcessById(e.ProcessID).ProcessName, e.ProcessID,
                                                        e.PayloadByName("ProcessID"), spoofable_process, e.ThreadID, command, DateTime.Now);
                                        }

                                        // Check if PPID spoofing
                                        if (e.ProcessID != spoofable_process)
                                        {
                                            if (verbose || command_history)
                                            {
                                                Console.WriteLine("\n[!] PPID SPOOFING DETECTED !");
                                                isSpoof = true;
                                            }

                                        }

                                        // Log to disk
                                        LogWriter.LogWriteProcess(Process.GetProcessById(e.ProcessID).ProcessName, e.ProcessID,
                                                    e.PayloadByName("ProcessID"), spoofable_process, e.ThreadID, command, isSpoof);
                                        isSpoof = false;
                                    }
                                }

                                // Log remote process termination from suspicious PID/TID
                                // need to check different OS implementations
                                else if (e.ProviderName == "Microsoft-Windows-Kernel-Audit-API-Calls")
                                {

                                    //Log only if coming from suspicious TID
                                    if (threadIDs[e.ProcessID].Contains(e.ThreadID))
                                    {
                                        //Event ID 2 means remote process termination
                                        if (e.EventName.Split('(', ')')[1] == "2")
                                        {
                                            if (verbose || terminate_history)
                                            {
                                                Console.WriteLine("\n------------------------------");
                                                Console.WriteLine("[!] TERMINATION");
                                                Console.WriteLine("\nProcess: {0} ({1})\nTID: {2}\nVictim: {3}\n", Process.GetProcessById(e.ProcessID).ProcessName, e.ProcessID, e.ThreadID, e.PayloadByName("TargetProcessId"));
                                            }

                                            if (sysmon_protect)
                                            {
                                                if ((int)e.PayloadByName("TargetProcessId") == sysmon_pid)
                                                {
                                                    SuspendTID(e.ThreadID);
                                                    Console.WriteLine("[***] Suspended TID {0} from {1} ({2}) for terminating Sysmon.exe", e.ThreadID, Process.GetProcessById(e.ProcessID).ProcessName, e.ProcessID);
                                                }
                                            }


                                            LogWriter.LogWriteTermination(Process.GetProcessById(e.ProcessID).ProcessName, e.ProcessID, e.ThreadID, e.PayloadByName("TargetProcessId"));

                                        }
                                    }
                                }

                                else if (e.ProviderName == "Microsoft-Windows-Kernel-File")
                                {

                                    // Log only if coming from suspicious TID
                                    if (threadIDs[e.ProcessID].Contains(e.ThreadID))
                                    {

                                        // Check directory enumeration
                                        if (e.PayloadByName("FileName").ToString() == "*" && e.EventName == "DirEnum")
                                        {
                                            if (verbose || file_history)
                                            {
                                                Console.WriteLine("\n------------------------------\n[!] FILE\n\nProcess: {0} ({1})\nTID: {2}\n", Process.GetProcessById(e.ProcessID).ProcessName, e.ProcessID, e.ThreadID);
                                                Console.WriteLine("[*] Directory Enumeration\n");
                                            }

                                            // Log to disk
                                            LogWriter.LogWriteFile(Process.GetProcessById(e.ProcessID).ProcessName, e.ProcessID, e.ThreadID, "Directory Enumeration");
                                        }

                                        // New file detection
                                        else if (e.EventName == "CreateNewFile")
                                        {
                                            if (verbose || file_history)
                                            {
                                                Console.WriteLine("\n------------------------------\n[!] FILE\n\nProcess: {0} ({1})\nTID: {2}\n", Process.GetProcessById(e.ProcessID).ProcessName, e.ProcessID, e.ThreadID);
                                                Console.WriteLine("[*] New File -> {0}\n", e.PayloadByName("FileName"));
                                            }

                                            // Log to disk
                                            LogWriter.LogWriteFile(Process.GetProcessById(e.ProcessID).ProcessName, e.ProcessID, e.ThreadID, "New File", e.PayloadByName("FileName").ToString());
                                        }

                                        // Removed or touched file/path detection
                                        else if (e.PayloadByName("CreateOptions").ToString() == "18874368" || e.PayloadByName("CreateOptions").ToString() == "18874432")
                                        {
                                            if ((verbose || file_history) && !Ignore_TID.Contains(e.ThreadID))
                                            {
                                                Console.WriteLine("\n------------------------------\n[!] FILE\n\nProcess: {0} ({1})\nTID: {2}\n", Process.GetProcessById(e.ProcessID).ProcessName, e.ProcessID, e.ThreadID);
                                                Console.WriteLine("[*] Removed/Touched File -> {0}\n", e.PayloadByName("FileName"));
                                            }

                                            // Log to disk
                                            LogWriter.LogWriteFile(Process.GetProcessById(e.ProcessID).ProcessName, e.ProcessID, e.ThreadID, "Removed/Touched File", e.PayloadByName("FileName").ToString());
                                        }

                                        // Changing directory detection
                                        else if (e.PayloadByName("CreateOptions").ToString() == "16777249")
                                        {
                                            if (verbose || file_history)
                                            {
                                                Console.WriteLine("\n------------------------------\n[!] FILE\n\nProcess: {0} ({1})\nTID: {2}\n", Process.GetProcessById(e.ProcessID).ProcessName, e.ProcessID, e.ThreadID);
                                                Console.WriteLine("[*] Change directory -> {0}\n", e.PayloadByName("FileName"));
                                            }
                                            // Log to disk
                                            LogWriter.LogWriteFile(Process.GetProcessById(e.ProcessID).ProcessName, e.ProcessID, e.ThreadID, "Change Directory", e.PayloadByName("FileName").ToString());

                                        }
                                    }
                                }

                                else if (e.ProviderName == "Microsoft-Windows-DNS-Client")
                                {
                                    if (threadIDs[e.ProcessID].Contains(e.ThreadID))
                                    {
                                        if (e.PayloadByName("QueryName").ToString() != "" && e.PayloadByName("QueryResults").ToString() != "")
                                        {
                                            if ((network_verbose || dns_history) && !Ignore_TID.Contains(e.ThreadID))
                                            {
                                                Console.WriteLine("\n------------------------------\n[!] DNS\n\nProcess: {0} ({1})\nTID: {2}\n\n[*] Query: {3}\n[*] Result: {4}\n", Process.GetProcessById(e.ProcessID).ProcessName, e.ProcessID, e.ThreadID, e.PayloadByName("QueryName"), e.PayloadByName("QueryResults"));
                                            }
                                            LogWriter.LogwriteDNS(Process.GetProcessById(e.ProcessID).ProcessName, e.ProcessID, e.ThreadID, e.PayloadByName("QueryName").ToString(), e.PayloadByName("QueryResults").ToString());
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
                string[] lines = File.ReadAllLines(Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location) + "\\Logs\\" + filename);
                foreach (string line in lines)
                {
                    Console.WriteLine(line);
                }
            }
            catch
            {
            }
        }
        static void SuspendTID(int tid)
        {
            IntPtr handle = OpenThread(ThreadAccess.SUSPEND_RESUME, false, (uint)tid);
            if (handle != IntPtr.Zero)
            {
                // Suspend thread
                SuspendThread(handle);

                // Log and stop tracking
                foreach (KeyValuePair<int, List<int>> pid in threadIDs)
                {
                    if (pid.Value.Contains(tid))
                    {
                        LogWriter.LogWriteSuspendTID(Process.GetProcessById(pid.Key).ProcessName, pid.Key, tid, score[pid.Key][tid][4]);
                        threadIDs[pid.Key].RemoveAll(p => p == tid);
                        score[pid.Key].Remove(tid);
                        break;
                    }
                }

                Console.WriteLine("\n[*] Suspended TID: {0}\n", tid);
            }
            else
            {
                Console.WriteLine("\n[*] TID {0} does not exist\n", tid);
            }
        }

        static void ThresholdChecker(double threshold)
        {
            foreach (int pid in score.Keys)
            {
                try
                {
                    foreach (KeyValuePair<int, List<double>> tid in score[pid])
                    {
                        if (tid.Value[4] >= threshold)
                        {
                            // Suspend Thread
                            IntPtr handle = OpenThread(ThreadAccess.SUSPEND_RESUME, false, (uint)tid.Key);
                            if (handle != IntPtr.Zero)
                                SuspendThread(handle);

                            // Log and stop tracking
                            LogWriter.LogWriteScoreThreshold(Process.GetProcessById(pid).ProcessName, pid, tid.Key, tid.Value[4], threshold);
                            threadIDs[pid].RemoveAll(p => p == tid.Key);
                            score[pid].Remove(tid.Key);

                            Console.WriteLine("\n[***] SCORE THRESHOLD -> Suspended TID {0} from {1} ({2}) at threshold {3}\n", tid.Key, Process.GetProcessById(pid).ProcessName, pid, threshold);
                        }
                    }
                }
                catch
                {
                }
            }
        }

        static void NetworkBeaconScore()
        {

            // Create table
            var table = new ConsoleTable("Process", "PID", "TID", "Callback Count", "SCORE");

            foreach (int pid in score.Keys)
            {

                foreach (KeyValuePair<int, List<double>> tid in score[pid])
                {
                    table.AddRow(Process.GetProcessById(pid).ProcessName, pid, tid.Key, tid.Value[3], tid.Value[4]);
                }

            }
            table.Write();
            Console.WriteLine("\n------------------------------");
        }

        static void IPStats()
        {
            var table2 = new ConsoleTable("Process", "PID", "TID", "RHOST", "RPORT", "Callback Count");

            foreach (int pid in PID_TID_IP.Keys)
            {

                foreach (KeyValuePair<int, List<string>> tid in PID_TID_IP[pid])
                {
                    table2.AddRow(Process.GetProcessById(pid).ProcessName, pid, tid.Key, tid.Value[0], tid.Value[1], tid.Value[2]);
                }

            }
            Console.Clear();
            table2.Write();
        }

        // P/Invoke Win API
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


        [DllImport("kernel32.dll", SetLastError = true)]
        static extern int SuspendThread(IntPtr hThread);

        [DllImport("kernel32.dll")]
        static extern IntPtr OpenThread(ThreadAccess dwDesiredAccess, bool bInheritHandle,
           uint dwThreadId);

    }
}
