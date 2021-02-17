using System;
using System.IO;
using System.Reflection;

namespace BeaconHunter
{
    public class LogWriter
    {
        public static string LogDirectory = Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location) + "\\Logs";

        public static void LogWriteProcess(string ProcessName, int ProcessID, object ChildProcess, int SpoofPPID, int ThreadID, string message, bool isSpoof)
        {
            try
            {
                using (StreamWriter w = File.AppendText(LogDirectory + "\\" + "Process_Log.txt"))
                {
                    w.WriteLine("------------------------------");
                    w.WriteLine("{0}", DateTime.Now);
                    w.WriteLine("\tParent Process: {0} ({1})", ProcessName, ProcessID);
                    w.WriteLine("\t-> Child Process: {0}", ChildProcess);
                    w.WriteLine("\tSpoofable PPID: {0}", SpoofPPID);
                    w.WriteLine("\tThread ID: {0}", ThreadID);
                    w.WriteLine("\tMessage: {0}", message);
                    if (isSpoof)
                    {
                        w.WriteLine("[!] PPID SPOOFING DETECTED !");
                    }
                }
            }
            catch (Exception)
            {
            }
        }
        public static void LogWriteNetwork(string ProcessName, object ProcessID, object ThreadID, object ip, object port, int count)
        {
            try
            {
                using (StreamWriter w = File.AppendText(LogDirectory + "\\" + "Network_Log.txt"))
                {
                    w.WriteLine("------------------------------");
                    w.WriteLine("{0}", DateTime.Now);
                    w.WriteLine("\tProcess: {0} ({1})", ProcessName, ProcessID);
                    w.WriteLine("\tThread ID: {0}", ThreadID);
                    w.WriteLine("\tIP: {0}", ip);
                    w.WriteLine("\tPORT: {0}", port);
                    w.WriteLine("\tCount: {0}", count);

                }
            }
            catch (Exception)
            {
            }
        }
        public static void LogWriteTermination(string ProcessName, object ProcessID, object ThreadID, object VictimID)
        {
            try
            {
                using (StreamWriter w = File.AppendText(LogDirectory + "\\" + "Terminate_Log.txt"))
                {
                    w.WriteLine("------------------------------");
                    w.WriteLine("{0}", DateTime.Now);
                    w.WriteLine("\tProcess: {0} ({1})", ProcessName, ProcessID);
                    w.WriteLine("\tThread ID: {0}", ThreadID);
                    w.WriteLine("\tVictim PID: {0}", VictimID);
                }
            }
            catch (Exception)
            {
            }
        }
        public static void LogWriteFile(string ProcessName, object ProcessID, object ThreadID, string Action, string filename = "*")
        {
            try
            {
                using (StreamWriter w = File.AppendText(LogDirectory + "\\" + "File_Log.txt"))
                {
                    w.WriteLine("------------------------------");
                    w.WriteLine("{0}", DateTime.Now);
                    w.WriteLine("\tProcess: {0} ({1})", ProcessName, ProcessID);
                    w.WriteLine("\tThread ID: {0}", ThreadID);
                    w.WriteLine("\tAction: {0}", Action);
                    w.WriteLine("\tPath: {0}", filename);

                }
            }
            catch (Exception)
            {
            }
        }
        public static void LogWritePID_TID(string ProcessName, int ProcessID, int ThreadID)
        {
            try
            {
                using (StreamWriter w = File.AppendText(LogDirectory + "\\" + "Suspicious_PID_TID_Log.txt"))
                {
                    w.WriteLine("------------------------------");
                    w.WriteLine("\n{0} => New Process with suspicious Thread: {1} ({2}) -> {3}", DateTime.Now, ProcessName, ProcessID, ThreadID);

                }
            }
            catch (Exception)
            {
            }
        }
        public static void LogWriteSuspendTID(string process, int pid, int tid, double score)
        {
            try
            {
                using (StreamWriter w = File.AppendText(LogDirectory + "\\" + "Suspended_TID_Log.txt"))
                {
                    w.WriteLine("------------------------------");
                    w.WriteLine("{0}", DateTime.Now);
                    w.WriteLine("\tProcess: {0} ({1})", process, pid);
                    w.WriteLine("\tTID: {0}", tid);
                    w.WriteLine("\tScore: {0}", score);
                }
            }
            catch (Exception)
            {
            }
        }

        public static void LogWriteScoreThreshold(string process, int pid, int tid, double score, double threshold)
        {
            try
            {
                using (StreamWriter w = File.AppendText(LogDirectory + "\\" + "Score_Threshold_Log.txt"))
                {
                    w.WriteLine("------------------------------");
                    w.WriteLine("{0}", DateTime.Now);
                    w.WriteLine("\tProcess: {0} ({1})", process, pid);
                    w.WriteLine("\tTID: {0}", tid);
                    w.WriteLine("\tScore: {0}", score);
                    w.WriteLine("\tThreshold: {0}", threshold);
                }
            }
            catch (Exception)
            {
            }
        }
        public static void LogwriteDNS(string process, int pid, int tid, string query, string result)
        {
            try
            {
                using (StreamWriter w = File.AppendText(LogDirectory + "\\" + "DNS_Log.txt"))
                {
                    w.WriteLine("------------------------------");
                    w.WriteLine("{0}", DateTime.Now);
                    w.WriteLine("\tProcess: {0} ({1})", process, pid);
                    w.WriteLine("\tTID: {0}", tid);
                    w.WriteLine("\tQuery: {0}", query);
                    w.WriteLine("\tResult: {0}", result);
                }
            }
            catch (Exception)
            {
            }
        }
    }
}
