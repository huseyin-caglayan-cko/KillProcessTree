using System.Diagnostics;
using System.Runtime.InteropServices;

namespace KillProcessTree
{
    internal class Program
    {
        static int Main(string[] args)
        {
            if (args.Length < 1)
            {
                Console.WriteLine("Usage: KillProcessTree <processId>");
                return 0;
            }

            if (!int.TryParse(args[0], out int targetProcessId))
            {
                Console.WriteLine($"Could not convert '{args[0]}' to a valid process id.");
                return 1;
            }

            Console.WriteLine("Getting all processes");
            Dictionary<int, Process> processTable = [];
            foreach (var process in Process.GetProcesses())
            {
                processTable[process.Id] =  process;
            }

            if (!processTable.ContainsKey(targetProcessId))
            {
                Console.WriteLine($"Process with Id '{args[0]}' not found.");
                return 1;
            }

            Console.WriteLine("Killing with all descendants");
            KillParentWithDescendants(processTable, targetProcessId);
            
            return 0;

        }

        static void KillParentWithDescendants(Dictionary<int, Process> processTable, int parentProcessId)
        {
            foreach (int childProcessId in processTable.Keys)
            {
                if (GetParentProcessId(childProcessId) == parentProcessId)
                {
                    KillParentWithDescendants(processTable, childProcessId);
                }
            }

            // Kill the parent
            processTable[parentProcessId].Kill();
        }


        /// <summary>
        /// Directly import this OpenProcess call from kernel
        /// </summary>
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr OpenProcess(int dwDesiredAccess, bool bInheritHandle, int dwProcessId);

        
        const int PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;
        
        private static int? GetParentProcessId(int processId)
        {
            // We need to access the parent handle which is not immediately avaiable.
            // For that we need to open a handle to the process. Make sure we specify limited_information as the purpose
            // otherwise NT will deny our request.
            IntPtr hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, processId);
            if (hProcess == IntPtr.Zero)
                return null;

            try
            {
                // Use the process handle to access Information block
                // which includes parent handle
                PROCESS_BASIC_INFORMATION pbi = new();
                int status = NtQueryInformationProcess(
                    hProcess,
                    0, // ProcessBasicInformation
                    ref pbi,
                    Marshal.SizeOf<PROCESS_BASIC_INFORMATION>(),
                    out int returnLength);

                if (status != 0)
                    return null;

                // This should not have populated the id of the parent process
                return pbi.InheritedFromUniqueProcessId.ToInt32();
            }
            finally
            {
                // Makr sure we close this and don't leak.
                // It would not make a difference for this tool but anyway
                CloseHandle(hProcess);
            }
        }

        [StructLayout(LayoutKind.Sequential)]
        struct PROCESS_BASIC_INFORMATION
        {
            public IntPtr Reserved1;
            public IntPtr PebBaseAddress;
            public IntPtr Reserved2_0;
            public IntPtr Reserved2_1;
            public IntPtr UniqueProcessId;
            public IntPtr InheritedFromUniqueProcessId;
        }

        [DllImport("ntdll.dll")]
        static extern int NtQueryInformationProcess(
            IntPtr processHandle,
            int processInformationClass,
            ref PROCESS_BASIC_INFORMATION processInformation,
            int processInformationLength,
            out int returnLength);



        /// <summary>
        /// Directly import this method from Kernel
        /// </summary>
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool CloseHandle(IntPtr hObject);


    }
}
