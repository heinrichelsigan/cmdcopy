﻿#define CLR2COMPATIBILITY
using Microsoft.Win32.SafeHandles;
using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Microsoft.Win32.Api
{

    /// <summary>
    /// InternalWrapper contains wrapper methods and inner classes for User32, Kernel32 and GDI32 Windows Core API calls
    /// Thanks to <see href="https://github.com/dotnet" />,    
    /// <see href="https://pinvoke.net/" />,
    /// <seealso href="https://stackoverflow.com/" /> and
    /// <seealso href="https://codeproject.com" />
    /// </summary>
    [SuppressUnmanagedCodeSecurityAttribute]
    internal static class NativeWrapper
    {

        #region Constants

        internal const uint ERROR_INSUFFICIENT_BUFFER = 0x8007007A;
        internal const uint STARTUP_LOADER_SAFEMODE = 0x10;
        internal const uint S_OK = 0x0;
        internal const uint S_FALSE = 0x1;
        internal const uint ERROR_ACCESS_DENIED = 0x5;
        internal const uint ERROR_FILE_NOT_FOUND = 0x80070002;
        internal const uint FUSION_E_PRIVATE_ASM_DISALLOWED = 0x80131044; // Tried to find unsigned assembly in GAC
        internal const uint RUNTIME_INFO_DONT_SHOW_ERROR_DIALOG = 0x40;
        internal const uint FILE_TYPE_CHAR = 0x0002;
        internal const Int32 STD_OUTPUT_HANDLE = -11;
        internal const uint RPC_S_CALLPENDING = 0x80010115;
        internal const uint E_ABORT = (uint)0x80004004;

        internal const int FILE_ATTRIBUTE_READONLY = 0x00000001;
        internal const int FILE_ATTRIBUTE_DIRECTORY = 0x00000010;
        internal const int FILE_ATTRIBUTE_REPARSE_POINT = 0x00000400;

        private const string kernel32Dll = "kernel32.dll";
        private const string mscoreeDLL = "mscoree.dll";

#if FEATURE_HANDLEREF
        internal static HandleRef NullHandleRef = new HandleRef(null, IntPtr.Zero);
#endif

        internal static IntPtr NullIntPtr = new IntPtr(0);

        // As defined in winnt.h:
        internal const ushort PROCESSOR_ARCHITECTURE_INTEL = 0;
        internal const ushort PROCESSOR_ARCHITECTURE_ARM = 5;
        internal const ushort PROCESSOR_ARCHITECTURE_IA64 = 6;
        internal const ushort PROCESSOR_ARCHITECTURE_AMD64 = 9;

        internal const uint INFINITE = 0xFFFFFFFF;
        internal const uint WAIT_ABANDONED_0 = 0x00000080;
        internal const uint WAIT_OBJECT_0 = 0x00000000;
        internal const uint WAIT_TIMEOUT = 0x00000102;

#if FEATURE_CHARSET_AUTO
        internal const CharSet AutoOrUnicode = CharSet.Auto;
#else
        internal const CharSet AutoOrUnicode = CharSet.Unicode;
#endif

        #endregion

        #region Enums

        /// <summary>
        /// enum PROCESSINFOCLASS 
        /// </summary>
        private enum PROCESSINFOCLASS : int
        {

            ProcessBasicInformation = 0,
            ProcessQuotaLimits,
            ProcessIoCounters,
            ProcessVmCounters,
            ProcessTimes,
            ProcessBasePriority,
            ProcessRaisePriority,
            ProcessDebugPort,
            ProcessExceptionPort,
            ProcessAccessToken,
            ProcessLdtInformation,
            ProcessLdtSize,
            ProcessDefaultHardErrorMode,
            ProcessIoPortHandlers, // Note: this is kernel mode only
            ProcessPooledUsageAndLimits,
            ProcessWorkingSetWatch,
            ProcessUserModeIOPL,
            ProcessEnableAlignmentFaultFixup,
            ProcessPriorityClass,
            ProcessWx86Information,
            ProcessHandleCount,
            ProcessAffinityMask,
            ProcessPriorityBoost,
            MaxProcessInfoClass

        };

        /// <summary>
        /// enum eDesiredAccess process accessing flags
        /// </summary>
        private enum eDesiredAccess : int
        {

            DELETE = 0x00010000,
            READ_CONTROL = 0x00020000,
            WRITE_DAC = 0x00040000,
            WRITE_OWNER = 0x00080000,
            SYNCHRONIZE = 0x00100000,
            STANDARD_RIGHTS_ALL = 0x001F0000,

            PROCESS_TERMINATE = 0x0001,
            PROCESS_CREATE_THREAD = 0x0002,
            PROCESS_SET_SESSIONID = 0x0004,
            PROCESS_VM_OPERATION = 0x0008,
            PROCESS_VM_READ = 0x0010,
            PROCESS_VM_WRITE = 0x0020,
            PROCESS_DUP_HANDLE = 0x0040,
            PROCESS_CREATE_PROCESS = 0x0080,
            PROCESS_SET_QUOTA = 0x0100,
            PROCESS_SET_INFORMATION = 0x0200,
            PROCESS_QUERY_INFORMATION = 0x0400,
            PROCESS_ALL_ACCESS = SYNCHRONIZE | 0xFFF

        }

        /// <summary>
        /// Flags for CoWaitForMultipleHandles
        /// </summary>
        [Flags]
        internal enum COWAIT_FLAGS : int
        {

            /// <summary>
            /// Exit when a handle is signaled.
            /// </summary>
            COWAIT_NONE = 0,

            /// <summary>
            /// Exit when all handles are signaled AND a message is received.
            /// </summary>
            COWAIT_WAITALL = 0x00000001,

            /// <summary>
            /// Exit when an RPC call is serviced.
            /// </summary>
            COWAIT_ALERTABLE = 0x00000002

        }

        /// <summary>
        /// Processor architecture values
        /// </summary>
        internal enum ProcessorArchitectures
        {

            // Intel 32 bit
            X86,

            // AMD64 64 bit
            X64,

            // Itanium 64
            IA64,

            // ARM
            ARM,

            // Who knows
            Unknown

        }

        internal enum CopyProgressResult : uint
        {
            PROGRESS_CONTINUE = 0,
            PROGRESS_CANCEL = 1,
            PROGRESS_STOP = 2,
            PROGRESS_QUIET = 3
        }

        internal enum CopyProgressCallbackReason : uint
        {
            CALLBACK_CHUNK_FINISHED = 0x00000000,
            CALLBACK_STREAM_SWITCH = 0x00000001
        }

        [Flags]
        internal enum CopyFileFlags : uint
        {
            COPY_FILE_FAIL_IF_EXISTS = 0x00000001,
            COPY_FILE_RESTARTABLE = 0x00000002,
            COPY_FILE_OPEN_SOURCE_FOR_WRITE = 0x00000004,
            COPY_FILE_ALLOW_DECRYPTED_DESTINATION = 0x00000008
        }

        #endregion

        #region Member_Properties_Data

        /// <summary>
        /// Default buffer size to use when dealing with the Windows API.
        /// </summary>
        /// <remarks>
        /// This member is intentionally not a constant because we want to allow
        /// unit tests to change it.
        /// </remarks>
        internal static int MAX_PATH = 260;

        private static readonly object IsMonoLock = new object();

        /// <summary>
        /// Gets a flag indicating if we are running under some version of Windows
        /// </summary>
        internal static bool IsWindows
        {
#if CLR2COMPATIBILITY
            get { return true; }
#else
            get { return RuntimeInformation.IsOSPlatform(OSPlatform.Windows); }
#endif
        }

        /// <summary>
        /// Gets a string for the current OS. This matches the OS env variable
        /// for Windows (Windows_NT).
        /// </summary>
        internal static string OSName
        {
            get { return IsWindows ? "Windows_NT" : "Unix"; }
        }

        /// <summary>
        /// System information, initialized when required.
        /// </summary>
        /// <remarks>
        /// Initially implemented as <see cref="Lazy{SystemInformationData}"/>, but
        /// that's .NET 4+, and this is used in MSBuildTaskHost.
        /// </remarks>
        private static SystemInformationData SystemInformation
        {
            get
            {
                if (!_systemInformationInitialized)
                {
                    lock (SystemInformationLock)
                    {
                        if (!_systemInformationInitialized)
                        {
                            _systemInformation = new SystemInformationData();
                            _systemInformationInitialized = true;
                        }
                    }
                }
                return _systemInformation;
            }
        }

        private static SystemInformationData _systemInformation;
        private static bool _systemInformationInitialized;
        private static readonly object SystemInformationLock = new object();

        /// <summary>
        /// Architecture getter
        /// </summary>
        internal static ProcessorArchitectures ProcessorArchitecture => SystemInformation.ProcessorArchitectureType;

        /// <summary>
        /// Native architecture getter
        /// </summary>
        internal static ProcessorArchitectures ProcessorArchitectureNative => SystemInformation.ProcessorArchitectureTypeNative;

        private static int pbCancel;

        #endregion Member_Properties_Data

        #region delegates

        internal delegate CopyProgressResult CopyProgressRoutine(
           long TotalFileSize,
           long TotalBytesTransferred,
           long StreamSize,
           long StreamBytesTransferred,
           uint dwStreamNumber,
           CopyProgressCallbackReason dwCallbackReason,
           IntPtr hSourceFile,
           IntPtr hDestinationFile,
           IntPtr lpData);

        #endregion delegates

        #region InnerClasses_Structs

        /// <summary>
        /// Helper class containing kernel32 functions
        /// </summary>
        internal class Kernel32
        {
            internal const int ATTACH_PARENT_PROCESS = -1;

            /// <summary>
            /// AttachConsole to Windows Form App
            /// </summary>
            /// <param name="dwProcessId"></param>
            /// <returns></returns>
            [DllImport("kernel32.dll")]
            internal static extern bool AttachConsole(int dwProcessId);
        }

        /// <summary>
        /// Helper class containing Gdi32 API functions
        /// </summary>
        internal class GDI32
        {

            internal const int SRCCOPY = 0x00CC0020; // BitBlt dwRop parameter            

            [DllImport("gdi32.dll")]
            internal static extern bool BitBlt(IntPtr hObject, int nXDest, int nYDest,
                int nWidth, int nHeight, IntPtr hObjectSource,
                int nXSrc, int nYSrc, int dwRop);
            [DllImport("GDI32.dll")]
            internal static extern bool BitBlt(int hdcDest, int nXDest, int nYDest,
                int nWidth, int nHeight, int hdcSrc,
                int nXSrc, int nYSrc, int dwRop);

            [DllImport("gdi32.dll")]
            internal static extern IntPtr CreateCompatibleBitmap(IntPtr hDC, int nWidth, int nHeight);
            [DllImport("GDI32.dll")]
            internal static extern int CreateCompatibleBitmap(int hdc, int nWidth, int nHeight);

            [DllImport("gdi32.dll")]
            internal static extern IntPtr CreateCompatibleDC(IntPtr hDC);
            [DllImport("GDI32.dll")]
            internal static extern int CreateCompatibleDC(int hdc);

            [DllImport("gdi32.dll")]
            internal static extern int CreateDC(string lpszDriver, string lpszDevice, string lpszOutput, IntPtr lpInitData);


            [DllImport("gdi32.dll")]
            internal static extern bool DeleteDC(IntPtr hDC);
            [DllImport("GDI32.dll")]
            internal static extern bool DeleteDC(int hdc);


            [DllImport("gdi32.dll")]
            internal static extern bool DeleteObject(IntPtr hObject);
            [DllImport("GDI32.dll")]
            internal static extern bool DeleteObject(int hObject);

            [DllImport("GDI32.dll")]
            internal static extern int GetDeviceCaps(int hdc, int nIndex);

            [DllImport("GDI32.dll")]
            internal static extern int SelectObject(int hdc, int hgdiobj);

            [DllImport("gdi32.dll")]
            internal static extern IntPtr SelectObject(IntPtr hDC, IntPtr hObject);

        }

        /// <summary>
        /// User class containing simplified User32 API functions with int instead of IntPtr
        /// </summary>
        internal class User
        {

            [DllImport("user32.dll")]
            internal static extern int GetDesktopWindow();

            [DllImport("user32.dll")]
            internal static extern IntPtr GetTopWindow(IntPtr hWnd);

        }

        /// <summary>
        /// Helper class containing User32 API functions
        /// </summary>
        internal class User32
        {

            internal const int HT_CAPTION = 0x2;

            internal const uint GW_HWNDFIRST = 0x000;
            internal const uint GW_HWNDLAST = 0x001;
            internal const uint GW_HWNDNEXT = 0x002;
            internal const uint GW_HWNDPREV = 0x003;
            internal const uint GW_OWNER = 0x004;
            internal const uint GW_CHILD = 0x005;
            internal const uint GW_ENABLEDPOPUP = 0x006;

            internal const uint WM_PRINT = 0x317;
            internal const int WM_NCLBUTTONDOWN = 0xA1;
            internal const int WM_APPCOMMAND = 0x319;

            [StructLayout(LayoutKind.Sequential)]
            internal struct RECT
            {
                internal int left;
                internal int top;
                internal int right;
                internal int bottom;
            }

            [Flags]
            internal enum PRF_FLAGS : uint
            {
                CHECKVISIBLE = 0x01,
                CHILDREN = 0x02,
                CLIENT = 0x04,
                ERASEBKGND = 0x08,
                NONCLIENT = 0x10,
                OWNED = 0x20
            }


            [DllImport("user32.dll")]
            internal static extern IntPtr GetDesktopWindow();


            [DllImport("user32.dll")]
            internal static extern IntPtr GetWindowDC(IntPtr hWnd);

            [DllImport("user32.dll")]
            internal static extern IntPtr GetWindowRect(IntPtr hWnd, ref RECT rect);

            [DllImport("user32.dll")]
            internal static extern IntPtr GetTopWindow(IntPtr hWnd);

            [DllImport("user32.dll")]
            internal static extern IntPtr GetWindow(IntPtr hWnd, uint uCmd);
            [DllImport("User32.dll")]
            internal static extern int GetWindowDC(int hWnd);

            [System.Runtime.InteropServices.DllImportAttribute("user32.dll")]
            internal static extern bool ReleaseCapture();

            [DllImport("user32.dll")]
            internal static extern IntPtr ReleaseDC(IntPtr hWnd, IntPtr hDC);
            [DllImport("User32.dll")]
            internal static extern int ReleaseDC(int hWnd, int hDC);


            [System.Runtime.InteropServices.DllImportAttribute("user32.dll")]
            internal static extern int SendMessage(IntPtr hWnd, int Msg, int wParam, int lParam);

            [System.Runtime.InteropServices.DllImportAttribute("user32.dll")]
            internal static extern IntPtr SendMessageW(IntPtr hWnd, int Msg, IntPtr wParam, IntPtr lParam);

            [DllImport("user32.dll")]
            internal static extern IntPtr SendMessage(IntPtr hWnd, uint msg, IntPtr hdc, PRF_FLAGS drawingOptions);

        }


        /// <summary>
        /// Wrap the intptr returned by OpenProcess in a safe handle.
        /// </summary>
        internal class SafeProcessHandle : SafeHandleZeroOrMinusOneIsInvalid
        {

            // Create a SafeHandle, informing the base class
            // that this SafeHandle instance "owns" the handle,
            // and therefore SafeHandle should call
            // our ReleaseHandle method when the SafeHandle
            // is no longer in use
            private SafeProcessHandle() : base(true)
            {
            }
            protected override bool ReleaseHandle()
            {
                return CloseHandle(handle);
            }

            [SuppressMessage("Microsoft.Design", "CA1060:MovePInvokesToNativeMethodsClass", Justification = "Class name is NativeMethodsShared for increased clarity")]
            [DllImport("KERNEL32.DLL")]
            private static extern bool CloseHandle(IntPtr hObject);

        }

        /// <summary>
        /// Contains information about the current state of both physical and virtual memory, including extended memory
        /// </summary>
        [StructLayout(LayoutKind.Sequential, CharSet = AutoOrUnicode)]
        internal class MemoryStatus
        {

            /// <summary>
            /// Initializes a new instance of the <see cref="T:MemoryStatus"/> class.
            /// </summary>
            internal MemoryStatus()
            {
#if (CLR2COMPATIBILITY)
                _length = (uint)Marshal.SizeOf(typeof(NativeWrapper.MemoryStatus));
#else
                _length = (uint)Marshal.SizeOf<NativeMethods.MemoryStatus>();
#endif
            }

            /// <summary>
            /// Size of the structure, in bytes. You must set this member before calling GlobalMemoryStatusEx.
            /// </summary>
            private uint _length;

            /// <summary>
            /// Number between 0 and 100 that specifies the approximate percentage of physical
            /// memory that is in use (0 indicates no memory use and 100 indicates full memory use).
            /// </summary>
            internal uint MemoryLoad;

            /// <summary>
            /// Total size of physical memory, in bytes.
            /// </summary>
            internal ulong TotalPhysical;

            /// <summary>
            /// Size of physical memory available, in bytes.
            /// </summary>
            internal ulong AvailablePhysical;

            /// <summary>
            /// Size of the committed memory limit, in bytes. This is physical memory plus the
            /// size of the page file, minus a small overhead.
            /// </summary>
            internal ulong TotalPageFile;

            /// <summary>
            /// Size of available memory to commit, in bytes. The limit is ullTotalPageFile.
            /// </summary>
            internal ulong AvailablePageFile;

            /// <summary>
            /// Total size of the user mode portion of the virtual address space of the calling process, in bytes.
            /// </summary>
            internal ulong TotalVirtual;

            /// <summary>
            /// Size of unreserved and uncommitted memory in the user mode portion of the virtual
            /// address space of the calling process, in bytes.
            /// </summary>
            internal ulong AvailableVirtual;

            /// <summary>
            /// Size of unreserved and uncommitted memory in the extended portion of the virtual
            /// address space of the calling process, in bytes.
            /// </summary>
            internal ulong AvailableExtendedVirtual;

        }

        /// <summary>
        /// Contains the security descriptor for an object and specifies whether
        /// the handle retrieved by specifying this structure is inheritable.
        /// </summary>
        [StructLayout(LayoutKind.Sequential)]
        internal class SecurityAttributes
        {

            internal SecurityAttributes()
            {
#if (CLR2COMPATIBILITY)
                _nLength = (uint)Marshal.SizeOf(typeof(NativeWrapper.SecurityAttributes));
#else
                _nLength = (uint)Marshal.SizeOf<NativeMethods.SecurityAttributes>();
#endif
            }

            private uint _nLength;

            internal IntPtr lpSecurityDescriptor;

            internal bool bInheritHandle;

        }

        private class SystemInformationData
        {

            /// <summary>
            /// Architecture as far as the current process is concerned.
            /// It's x86 in wow64 (native architecture is x64 in that case).
            /// Otherwise it's the same as the native architecture.
            /// </summary>
            internal readonly ProcessorArchitectures ProcessorArchitectureType;

            /// <summary>
            /// Actual architecture of the system.
            /// </summary>
            internal readonly ProcessorArchitectures ProcessorArchitectureTypeNative;

            /// <summary>
            /// Convert SYSTEM_INFO architecture values to the internal enum
            /// </summary>
            /// <param name="arch"></param>
            /// <returns></returns>
            private static ProcessorArchitectures ConvertSystemArchitecture(ushort arch)
            {
                switch (arch)
                {
                    case PROCESSOR_ARCHITECTURE_INTEL:
                        return ProcessorArchitectures.X86;
                    case PROCESSOR_ARCHITECTURE_AMD64:
                        return ProcessorArchitectures.X64;
                    case PROCESSOR_ARCHITECTURE_ARM:
                        return ProcessorArchitectures.ARM;
                    case PROCESSOR_ARCHITECTURE_IA64:
                        return ProcessorArchitectures.IA64;
                    default:
                        return ProcessorArchitectures.Unknown;
                }
            }

            /// <summary>
            /// Read system info values
            /// </summary>
            internal SystemInformationData()
            {
                ProcessorArchitectureType = ProcessorArchitectures.Unknown;
                ProcessorArchitectureTypeNative = ProcessorArchitectures.Unknown;

                if (IsWindows)
                {
                    var systemInfo = new SYSTEM_INFO();

                    GetSystemInfo(ref systemInfo);
                    ProcessorArchitectureType = ConvertSystemArchitecture(systemInfo.wProcessorArchitecture);

                    GetNativeSystemInfo(ref systemInfo);
                    ProcessorArchitectureTypeNative = ConvertSystemArchitecture(systemInfo.wProcessorArchitecture);
                }
                else
                {
                    try
                    {
                        // On Unix run 'uname -m' to get the architecture. It's common for Linux and Mac
                        using (
                            var proc =
                                Process.Start(
                                    new ProcessStartInfo("uname")
                                    {
                                        Arguments = "-m",
                                        UseShellExecute = false,
                                        RedirectStandardOutput = true,
                                        CreateNoWindow = true
                                    }))
                        {
                            string arch = null;
                            if (proc != null)
                            {
                                // Since uname -m simply returns kernel property, it should be quick.
                                // 1 second is the best guess for a safe timeout.
                                proc.WaitForExit(1000);
                                arch = proc.StandardOutput.ReadLine();
                            }

                            if (!string.IsNullOrEmpty(arch))
                            {
                                if (arch.StartsWith("x86_64", StringComparison.OrdinalIgnoreCase))
                                {
                                    ProcessorArchitectureType = ProcessorArchitectures.X64;
                                }
                                else if (arch.StartsWith("ia64", StringComparison.OrdinalIgnoreCase))
                                {
                                    ProcessorArchitectureType = ProcessorArchitectures.IA64;
                                }
                                else if (arch.StartsWith("arm", StringComparison.OrdinalIgnoreCase))
                                {
                                    ProcessorArchitectureType = ProcessorArchitectures.ARM;
                                }
                                else if (arch.StartsWith("i", StringComparison.OrdinalIgnoreCase)
                                         && arch.EndsWith("86", StringComparison.OrdinalIgnoreCase))
                                {
                                    ProcessorArchitectureType = ProcessorArchitectures.X86;
                                }
                            }
                        }
                    }
                    catch
                    {
                        ProcessorArchitectureType = ProcessorArchitectures.Unknown;
                    }

                    ProcessorArchitectureTypeNative = ProcessorArchitectureType;
                }
            }

        }

        /// <summary>
        /// InternalError Exception derived from <see cref="System.ComponentModel.Win32Exception"/>
        /// </summary>
        internal class InternalErrorException : System.ComponentModel.Win32Exception
        {

            /// <summary>
            /// InternalErrorException parameterless constructor
            /// </summary>
            internal InternalErrorException() : base() { }

            /// <summary>
            /// InternalErrorException constructor with simple msg
            /// </summary>
            /// <param name="msg"><see cref="string">string msg</see> a message to describe the <see cref="EnablerSpoolerException"/></param>
            internal InternalErrorException(string msg) : base(msg)
            {
            }

            /// <summary>
            /// InternalErrorException constructor with simple msg and innerException
            /// </summary>
            /// <param name="msg"><see cref="string">string msg</see> a message to describe the <see cref="EnablerSpoolerException"/></param>
            /// <param name="innerEx"><see cref="Exception">Exception innerEx</see> inner Exception, that was previously thrown</param>        
            internal InternalErrorException(string msg, System.Exception innerEx) : base(msg, innerEx)
            {
            }

        }

        #region Structs

        /// <summary>
        /// Structure that contain information about the system on which we are running
        /// </summary>
        [StructLayout(LayoutKind.Sequential)]
        internal struct SYSTEM_INFO
        {

            // This is a union of a DWORD and a struct containing 2 WORDs.
            internal ushort wProcessorArchitecture;
            internal ushort wReserved;

            internal uint dwPageSize;
            internal IntPtr lpMinimumApplicationAddress;
            internal IntPtr lpMaximumApplicationAddress;
            internal IntPtr dwActiveProcessorMask;
            internal uint dwNumberOfProcessors;
            internal uint dwProcessorType;
            internal uint dwAllocationGranularity;
            internal ushort wProcessorLevel;
            internal ushort wProcessorRevision;

        }

        [StructLayout(LayoutKind.Sequential)]
        private struct PROCESS_BASIC_INFORMATION
        {

            internal IntPtr ExitStatus;
            internal IntPtr PebBaseAddress;
            internal IntPtr AffinityMask;
            internal IntPtr BasePriority;
            internal IntPtr UniqueProcessId;
            internal IntPtr InheritedFromUniqueProcessId;

            internal int Size
            {
                get { return (6 * IntPtr.Size); }
            }

        };

        /// <summary>
        /// Contains information about a file or directory; used by GetFileAttributesEx.
        /// </summary>
        [StructLayout(LayoutKind.Sequential)]
        internal struct WIN32_FILE_ATTRIBUTE_DATA
        {

            internal int fileAttributes;
            internal uint ftCreationTimeLow;
            internal uint ftCreationTimeHigh;
            internal uint ftLastAccessTimeLow;
            internal uint ftLastAccessTimeHigh;
            internal uint ftLastWriteTimeLow;
            internal uint ftLastWriteTimeHigh;
            internal uint fileSizeHigh;
            internal uint fileSizeLow;

        }

        #endregion

        #endregion InnerClasses_Structs

        #region SetErrorMode_[copied_from_BCL]

        private static readonly Version s_threadErrorModeMinOsVersion = new Version(6, 1, 0x1db0);

        internal static int SetErrorMode(int newMode)
        {
#if FEATURE_OSVERSION
            if (Environment.OSVersion.Version < s_threadErrorModeMinOsVersion)
            {
                return SetErrorMode_VistaAndOlder(newMode);
            }
#endif
            int num;
            SetErrorMode_Win7AndNewer(newMode, out num);
            return num;
        }

        [SuppressMessage("Microsoft.Design", "CA1060:MovePInvokesToNativeMethodsClass", Justification = "Class name is NativeMethodsShared for increased clarity")]
        [DllImport("kernel32.dll", EntryPoint = "SetThreadErrorMode", SetLastError = true)]
        private static extern bool SetErrorMode_Win7AndNewer(int newMode, out int oldMode);

        [SuppressMessage("Microsoft.Design", "CA1060:MovePInvokesToNativeMethodsClass", Justification = "Class name is NativeMethodsShared for increased clarity")]
        [DllImport("kernel32.dll", EntryPoint = "SetErrorMode", ExactSpelling = true)]
        private static extern int SetErrorMode_VistaAndOlder(int newMode);

        #endregion SetErrorMode_[copied_from_BCL]

        #region static wrapper methods

        /// <summary>
        /// Get the last write time of the fullpath to a directory. If the pointed path is not a directory, or
        /// if the directory does not exist, then false is returned and fileModifiedTimeUtc is set DateTime.MinValue.
        /// </summary>
        /// <param name="fullPath">Full path to the file in the filesystem</param>
        /// <param name="fileModifiedTimeUtc">The UTC last write time for the directory</param>
        internal static bool GetLastWriteDirectoryUtcTime(string fullPath, out DateTime fileModifiedTimeUtc)
        {
            // This code was copied from the reference manager, if there is a bug fix in that code, see if the same fix should also be made
            // there

            fileModifiedTimeUtc = DateTime.MinValue;

            if (IsWindows)
            {
                WIN32_FILE_ATTRIBUTE_DATA data = new WIN32_FILE_ATTRIBUTE_DATA();
                bool success = false;

                success = GetFileAttributesEx(fullPath, 0, ref data);
                if (success)
                {
                    if ((data.fileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0)
                    {
                        long dt = ((long)(data.ftLastWriteTimeHigh) << 32) | ((long)data.ftLastWriteTimeLow);
                        fileModifiedTimeUtc = DateTime.FromFileTimeUtc(dt);
                    }
                    else
                    {
                        // Path does not point to a directory
                        success = false;
                    }
                }

                return success;
            }

            fileModifiedTimeUtc = Directory.GetLastWriteTimeUtc(fullPath);
            return true;
        }

        /// <summary>
        /// Takes the path and returns the short path
        /// </summary>
        internal static string GetShortFilePath(string path)
        {
            if (!IsWindows)
            {
                return path;
            }

            if (path != null)
            {
                int length = GetShortPathName(path, null, 0);
                int errorCode = Marshal.GetLastWin32Error();

                if (length > 0)
                {
                    StringBuilder fullPathBuffer = new StringBuilder(length);
                    length = GetShortPathName(path, fullPathBuffer, length);
                    errorCode = Marshal.GetLastWin32Error();

                    if (length > 0)
                    {
                        string fullPath = fullPathBuffer.ToString();
                        path = fullPath;
                    }
                }

                if (length == 0 && errorCode != 0)
                {
                    ThrowExceptionForErrorCode(errorCode);
                }
            }

            return path;
        }

        /// <summary>
        /// Takes the path and returns a full path
        /// </summary>
        /// <param name="path"></param>
        /// <returns></returns>
        internal static string GetLongFilePath(string path)
        {
            if (path != null)
            {
                int length = GetLongPathName(path, null, 0);
                int errorCode = Marshal.GetLastWin32Error();

                if (length > 0)
                {
                    StringBuilder fullPathBuffer = new StringBuilder(length);
                    length = GetLongPathName(path, fullPathBuffer, length);
                    errorCode = Marshal.GetLastWin32Error();

                    if (length > 0)
                    {
                        string fullPath = fullPathBuffer.ToString();
                        path = fullPath;
                    }
                }

                if (length == 0 && errorCode != 0)
                {
                    ThrowExceptionForErrorCode(errorCode);
                }
            }

            return path;
        }

        /// <summary>
        /// Retrieves the current global memory status.
        /// </summary>
        internal static MemoryStatus GetMemoryStatus()
        {
            if (NativeWrapper.IsWindows)
            {
                MemoryStatus status = new MemoryStatus();
                bool returnValue = NativeWrapper.GlobalMemoryStatusEx(status);
                if (!returnValue)
                {
                    return null;
                }

                return status;
            }

            return null;
        }

        /// <summary>
        /// Get the last write time of the content pointed to by a file path.
        /// </summary>
        /// <param name="fullPath">Full path to the file in the filesystem</param>
        /// <returns>The last write time of the file, or DateTime.MinValue if the file does not exist.</returns>
        /// <remarks>
        /// This is the most accurate timestamp-extraction mechanism, but it is too slow to use all the time.
        /// See https://github.com/Microsoft/msbuild/issues/2052.
        /// </remarks>
        private static DateTime GetContentLastWriteFileUtcTime(string fullPath)
        {
            DateTime fileModifiedTime = DateTime.MinValue;

            using (SafeFileHandle handle =
                CreateFile(fullPath,
                    GENERIC_READ,
                    FILE_SHARE_READ,
                    IntPtr.Zero,
                    OPEN_EXISTING,
                    FILE_ATTRIBUTE_NORMAL, /* No FILE_FLAG_OPEN_REPARSE_POINT; read through to content */
                    IntPtr.Zero))
            {
                if (!handle.IsInvalid)
                {
                    System.Runtime.InteropServices.ComTypes.FILETIME ftCreationTime, ftLastAccessTime, ftLastWriteTime;
                    if (!GetFileTime(handle, out ftCreationTime, out ftLastAccessTime, out ftLastWriteTime) != true)
                    {
                        long fileTime = ((long)(uint)ftLastWriteTime.dwHighDateTime) << 32 |
                                        (long)(uint)ftLastWriteTime.dwLowDateTime;
                        fileModifiedTime =
                            DateTime.FromFileTimeUtc(fileTime);
                    }
                }
            }

            return fileModifiedTime;
        }

        /// <summary>
        /// Did the HRESULT succeed
        /// </summary>
        internal static bool HResultSucceeded(int hr)
        {
            return (hr >= 0);
        }

        /// <summary>
        /// Did the HRESULT Fail
        /// </summary>
        internal static bool HResultFailed(int hr)
        {
            return (hr < 0);
        }

        /// <summary>
        /// Given an error code, converts it to an HRESULT and throws the appropriate exception.
        /// </summary>
        /// <param name="errorCode"></param>
        internal static void ThrowExceptionForErrorCode(int errorCode)
        {
            // See ndp\clr\src\bcl\system\io\__error.cs for this code as it appears in the CLR.

            // Something really bad went wrong with the call
            // translate the error into an exception

            // Convert the errorcode into an HRESULT (See MakeHRFromErrorCode in Win32Native.cs in
            // ndp\clr\src\bcl\microsoft\win32)
            errorCode = unchecked(((int)0x80070000) | errorCode);

            // Throw an exception as best we can
            Marshal.ThrowExceptionForHR(errorCode);
        }

        /// <summary>
        /// Kills the specified process by id and all of its children recursively.
        /// </summary>
        internal static void KillTree(int processIdToKill)
        {
            // Note that GetProcessById does *NOT* internally hold on to the process handle.
            // Only when you create the process using the Process object
            // does the Process object retain the original handle.

            Process thisProcess = null;
            try
            {
                thisProcess = Process.GetProcessById(processIdToKill);
            }
            catch (ArgumentException)
            {
                // The process has already died for some reason.  So shrug and assume that any child processes
                // have all also either died or are in the process of doing so.
                return;
            }

            try
            {
                DateTime myStartTime = thisProcess.StartTime;

                // Grab the process handle.  We want to keep this open for the duration of the function so that
                // it cannot be reused while we are running.
                SafeProcessHandle hProcess = OpenProcess(eDesiredAccess.PROCESS_QUERY_INFORMATION, false, processIdToKill);
                if (hProcess.IsInvalid)
                {
                    return;
                }

                try
                {
                    try
                    {
                        // Kill this process, so that no further children can be created.
                        thisProcess.Kill();
                    }
                    catch (System.ComponentModel.Win32Exception e)
                    {
                        // Access denied is potentially expected -- it happens when the process that
                        // we're attempting to kill is already dead.  So just ignore in that case.
                        if (e.NativeErrorCode != ERROR_ACCESS_DENIED)
                        {
                            throw;
                        }
                    }

                    // Now enumerate our children.  Children of this process are any process which has this process id as its parent
                    // and which also started after this process did.
                    List<KeyValuePair<int, SafeProcessHandle>> children = GetChildProcessIds(processIdToKill, myStartTime);

                    try
                    {
                        foreach (KeyValuePair<int, SafeProcessHandle> childProcessInfo in children)
                        {
                            KillTree(childProcessInfo.Key);
                        }
                    }
                    finally
                    {
                        foreach (KeyValuePair<int, SafeProcessHandle> childProcessInfo in children)
                        {
                            childProcessInfo.Value.Dispose();
                        }
                    }
                }
                finally
                {
                    // Release the handle.  After this point no more children of this process exist and this process has also exited.
                    hProcess.Dispose();
                }
            }
            finally
            {
                thisProcess.Dispose();
            }
        }

        /// <summary>
        /// Returns the parent process id for the specified process.
        /// Returns zero if it cannot be gotten for some reason.
        /// </summary>
        internal static int GetParentProcessId(int processId)
        {
            int ParentID = 0;
#if !CLR2COMPATIBILITY
            //if (IsUnixLike)
            //{
            //    string line = null;

            //    try
            //    {
            //        // /proc/<processID>/stat returns a bunch of space separated fields. Get that string
            //        using (var r = FileUtilities.OpenRead("/proc/" + processId + "/stat"))
            //        {
            //            line = r.ReadLine();
            //        }
            //    }
            //    catch // Ignore errors since the process may have terminated
            //    {
            //    }

            //    if (!string.IsNullOrWhiteSpace(line))
            //    {
            //        // One of the fields is the process name. It may contain any characters, but since it's
            //        // in parenthesis, we can finds its end by looking for the last parenthesis. After that,
            //        // there comes a space, then the second fields separated by a space is the parent id.
            //        string[] statFields = line.Substring(line.LastIndexOf(')')).Split(new[] { ' ' }, 4);
            //        if (statFields.Length >= 3)
            //        {
            //            ParentID = Int32.Parse(statFields[2]);
            //        }
            //    }
            //}
            //else
#endif
            {
                SafeProcessHandle hProcess = OpenProcess(eDesiredAccess.PROCESS_QUERY_INFORMATION, false, processId);

                if (!hProcess.IsInvalid)
                {
                    try
                    {
                        // UNDONE: NtQueryInformationProcess will fail if we are not elevated and other process is. Advice is to change to use ToolHelp32 API's
                        // For now just return zero and worst case we will not kill some children.
                        PROCESS_BASIC_INFORMATION pbi = new PROCESS_BASIC_INFORMATION();
                        int pSize = 0;

                        if (0 == NtQueryInformationProcess(hProcess, PROCESSINFOCLASS.ProcessBasicInformation, ref pbi, pbi.Size, ref pSize))
                        {
                            ParentID = (int)pbi.InheritedFromUniqueProcessId;
                        }
                    }
                    finally
                    {
                        hProcess.Dispose();
                    }
                }
            }

            return (ParentID);
        }

        /// <summary>
        /// Returns an array of all the immediate child processes by id.
        /// NOTE: The IntPtr in the tuple is the handle of the child process.  CloseHandle MUST be called on this.
        /// </summary>
        internal static List<KeyValuePair<int, SafeProcessHandle>> GetChildProcessIds(int parentProcessId, DateTime parentStartTime)
        {
            List<KeyValuePair<int, SafeProcessHandle>> myChildren = new List<KeyValuePair<int, SafeProcessHandle>>();

            foreach (Process possibleChildProcess in Process.GetProcesses())
            {
                using (possibleChildProcess)
                {
                    // Hold the child process handle open so that children cannot die and restart with a different parent after we've started looking at it.
                    // This way, any handle we pass back is guaranteed to be one of our actual children.
                    SafeProcessHandle childHandle = OpenProcess(eDesiredAccess.PROCESS_QUERY_INFORMATION, false, possibleChildProcess.Id);
                    if (childHandle.IsInvalid)
                    {
                        continue;
                    }

                    bool keepHandle = false;
                    try
                    {
                        if (possibleChildProcess.StartTime > parentStartTime)
                        {
                            int childParentProcessId = GetParentProcessId(possibleChildProcess.Id);
                            if (childParentProcessId != 0)
                            {
                                if (parentProcessId == childParentProcessId)
                                {
                                    // Add this one
                                    myChildren.Add(new KeyValuePair<int, SafeProcessHandle>(possibleChildProcess.Id, childHandle));
                                    keepHandle = true;
                                }
                            }
                        }
                    }
                    finally
                    {
                        if (!keepHandle)
                        {
                            childHandle.Dispose();
                        }
                    }
                }
            }

            return myChildren;
        }

        /// <summary>
        /// Internal, optimized GetCurrentDirectory implementation that simply delegates to the native method
        /// </summary>
        /// <returns></returns>
        internal static string GetCurrentDirectory()
        {
            if (IsWindows)
            {
                StringBuilder sb = new StringBuilder(MAX_PATH);
                int pathLength = GetCurrentDirectory(MAX_PATH, sb);

                return pathLength > 0 ? sb.ToString() : null;
            }

            return Directory.GetCurrentDirectory();
        }

        internal static void XCopy(string oldFile, string newFile)
        {
            CopyFileEx(oldFile, newFile, new CopyProgressRoutine(CopyProgressHandler), IntPtr.Zero, ref pbCancel, CopyFileFlags.COPY_FILE_RESTARTABLE);
        }

        internal static CopyProgressResult CopyProgressHandler(long total, long transferred, long streamSize, long StreamByteTrans, uint dwStreamNumber, CopyProgressCallbackReason reason, IntPtr hSourceFile, IntPtr hDestinationFile, IntPtr lpData)
        {
            return CopyProgressResult.PROGRESS_CONTINUE;
        }

        #region helper methods

        internal static void VerifyThrowInternalError(bool condition, string message, params object[] args)
        {
            if (!condition)
            {
                ThrowInternalError(message, args);
            }
        }

        /// <summary>
        /// This method should be used in places where one would normally put
        /// an "assert". It should be used to validate that our assumptions are
        /// true, where false would indicate that there must be a bug in our
        /// code somewhere. This should not be used to throw errors based on bad
        /// user input or anything that the user did wrong.
        /// </summary>
        internal static void VerifyThrow(bool condition, string unformattedMessage)
        {
            if (!condition)
            {
                ThrowInternalError(unformattedMessage, null, null);
            }
        }

        /// <summary>
        /// Overload for one string format argument.
        /// </summary>
        internal static void VerifyThrow(bool condition, string unformattedMessage, object arg0)
        {
            if (!condition)
            {
                ThrowInternalError(unformattedMessage, arg0);
            }
        }

        /// <summary>
        /// Overload for two string format arguments.
        /// </summary>
        internal static void VerifyThrow(bool condition, string unformattedMessage, object arg0, object arg1)
        {
            if (!condition)
            {
                ThrowInternalError(unformattedMessage, arg0, arg1);
            }
        }

        /// <summary>
        /// Overload for three string format arguments.
        /// </summary>
        internal static void VerifyThrow(bool condition, string unformattedMessage, object arg0, object arg1, object arg2)
        {
            if (!condition)
            {
                ThrowInternalError(unformattedMessage, arg0, arg1, arg2);
            }
        }

        /// <summary>
        /// Overload for four string format arguments.
        /// </summary>
        internal static void VerifyThrow(bool condition, string unformattedMessage, object arg0, object arg1, object arg2, object arg3)
        {
            if (!condition)
            {
                ThrowInternalError(unformattedMessage, arg0, arg1, arg2, arg3);
            }
        }

        /// <summary>
        /// Throws InternalErrorException.
        /// This is only for situations that would mean that there is a bug in MSBuild itself.
        /// </summary>]
        internal static void ThrowInternalError(string message, params object[] args)
        {
            throw new InternalErrorException(FormatString(message, args));
        }

        internal static bool FileExists(string path)
        {
            WIN32_FILE_ATTRIBUTE_DATA data = new WIN32_FILE_ATTRIBUTE_DATA();
            return GetFileAttributesEx(path, 0, ref data);
        }

        /// <summary>
        /// Formats the given string using the variable arguments passed in.
        ///
        /// PERF WARNING: calling a method that takes a variable number of arguments is expensive, because memory is allocated for
        /// the array of arguments -- do not call this method repeatedly in performance-critical scenarios
        ///
        /// Thread safe.
        /// </summary>
        /// <param name="unformatted">The string to format.</param>
        /// <param name="args">Optional arguments for formatting the given string.</param>
        /// <returns>The formatted string.</returns>
        internal static string FormatString(string unformatted, params object[] args)
        {
            string formatted = unformatted;

            // NOTE: String.Format() does not allow a null arguments array
            if ((args?.Length > 0))
            {
#if DEBUG
                // If you accidentally pass some random type in that can't be converted to a string,
                // FormatResourceString calls ToString() which returns the full name of the type!
                foreach (object param in args)
                {
                    // Check it has a real implementation of ToString() and the type is not actually System.String
                    if (param != null)
                    {
                        if (string.Equals(param.GetType().ToString(), param.ToString(), StringComparison.Ordinal) &&
                            param.GetType() != typeof(string))
                        {
                            formatted += string.Format("Invalid resource parameter type, was {0}", param.GetType().FullName);
                        }
                    }
                }
#endif
                // Format the string, using the variable arguments passed in.
                // NOTE: all String methods are thread-safe
                formatted = String.Format(CultureInfo.CurrentCulture, unformatted, args);
            }

            return formatted;
        }

        #endregion helper methods

        #region extension methods

        /// <summary>
        /// Waits while pumping APC messages.  This is important if the waiting thread is an STA thread which is potentially
        /// servicing COM calls from other threads.
        /// </summary>
        [SuppressMessage("Microsoft.Reliability", "CA2001:AvoidCallingProblematicMethods", MessageId = "System.Runtime.InteropServices.SafeHandle.DangerousGetHandle", Scope = "member", Target = "Microsoft.Build.Shared.NativeMethods.#MsgWaitOne(System.Threading.WaitHandle,System.Int32)", Justification = "This is necessary and it has been used for a long time. No need to change it now.")]
        internal static bool MsgWaitOne(this WaitHandle handle)
        {
            return handle.MsgWaitOne(Timeout.Infinite);
        }

        /// <summary>
        /// Waits while pumping APC messages.  This is important if the waiting thread is an STA thread which is potentially
        /// servicing COM calls from other threads.
        /// </summary>
        internal static bool MsgWaitOne(this WaitHandle handle, TimeSpan timeout)
        {
            return MsgWaitOne(handle, (int)timeout.TotalMilliseconds);
        }

        /// <summary>
        /// Waits while pumping APC messages.  This is important if the waiting thread is an STA thread which is potentially
        /// servicing COM calls from other threads.
        /// </summary>
        [SuppressMessage("Microsoft.Reliability", "CA2001:AvoidCallingProblematicMethods", MessageId = "System.Runtime.InteropServices.SafeHandle.DangerousGetHandle", Justification = "Necessary to avoid pumping")]
        internal static bool MsgWaitOne(this WaitHandle handle, int timeout)
        {
            // CoWaitForMultipleHandles allows us to wait in an STA apartment and still service RPC requests from other threads.
            // VS needs this in order to allow the in-proc compilers to properly initialize, since they will make calls from the
            // build thread which the main thread (blocked on BuildSubmission.Execute) must service.
            int waitIndex;
#if FEATURE_HANDLE_SAFEWAITHANDLE
            IntPtr handlePtr = handle.SafeWaitHandle.DangerousGetHandle();
#else
            IntPtr handlePtr = handle.GetSafeWaitHandle().DangerousGetHandle();
#endif
            int returnValue = CoWaitForMultipleHandles(COWAIT_FLAGS.COWAIT_NONE, timeout, 1, new IntPtr[] { handlePtr }, out waitIndex);
            VerifyThrow(returnValue == 0 || ((uint)returnValue == RPC_S_CALLPENDING && timeout != Timeout.Infinite), "Received {0} from CoWaitForMultipleHandles, but expected 0 (S_OK)", returnValue); return returnValue == 0;
        }

        #endregion extension methods

        #endregion static wrapper methods

        #region PInvoke

        /// <summary>
        /// Gets the current OEM code page which is used by console apps
        /// (as opposed to the Windows/ANSI code page used by the normal people)
        /// Basically for each ANSI code page (set in Regional settings) there's a corresponding OEM code page
        /// that needs to be used for instance when writing to batch files
        /// </summary>
        [SuppressMessage("Microsoft.Design", "CA1060:MovePInvokesToNativeMethodsClass", Justification = "Class name is NativeMethodsShared for increased clarity")]
        [DllImport(kernel32Dll)]
        internal static extern int GetOEMCP();

        [SuppressMessage("Microsoft.Design", "CA1060:MovePInvokesToNativeMethodsClass", Justification = "Class name is NativeMethodsShared for increased clarity")]
        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool GetFileAttributesEx(String name, int fileInfoLevel, ref WIN32_FILE_ATTRIBUTE_DATA lpFileInformation);

        [SuppressMessage("Microsoft.Design", "CA1060:MovePInvokesToNativeMethodsClass", Justification = "Class name is NativeMethodsShared for increased clarity")]
        [DllImport(kernel32Dll, SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern uint SearchPath
        (
            string path,
            string fileName,
            string extension,
            int numBufferChars,
            [Out] StringBuilder buffer,
            int[] filePart
        );

        [SuppressMessage("Microsoft.Design", "CA1060:MovePInvokesToNativeMethodsClass", Justification = "Class name is NativeMethodsShared for increased clarity")]
        [DllImport("kernel32.dll", PreserveSig = true, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool FreeLibrary([In] IntPtr module);

        [SuppressMessage("Microsoft.Design", "CA1060:MovePInvokesToNativeMethodsClass", Justification = "Class name is NativeMethodsShared for increased clarity")]
        [DllImport("kernel32.dll", PreserveSig = true, BestFitMapping = false, ThrowOnUnmappableChar = true, CharSet = CharSet.Ansi, SetLastError = true)]
        internal static extern IntPtr GetProcAddress(IntPtr module, string procName);

        [SuppressMessage("Microsoft.Design", "CA1060:MovePInvokesToNativeMethodsClass", Justification = "Class name is NativeMethodsShared for increased clarity")]
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, PreserveSig = true, SetLastError = true)]
        internal static extern IntPtr LoadLibrary(string fileName);

        [SuppressMessage("Microsoft.Design", "CA1060:MovePInvokesToNativeMethodsClass", Justification = "Class name is NativeMethodsShared for increased clarity")]
        [DllImport(mscoreeDLL, SetLastError = true, CharSet = CharSet.Unicode)]
        internal static extern uint GetRequestedRuntimeInfo(String pExe,
                                                String pwszVersion,
                                                String pConfigurationFile,
                                                uint startupFlags,
                                                uint runtimeInfoFlags,
                                                [Out] StringBuilder pDirectory,
                                                int dwDirectory,
                                                out uint dwDirectoryLength,
                                                [Out] StringBuilder pVersion,
                                                int cchBuffer,
                                                out uint dwlength);

        /// <summary>
        /// Gets the fully qualified filename of the currently executing .exe
        /// </summary>
        [SuppressMessage("Microsoft.Design", "CA1060:MovePInvokesToNativeMethodsClass", Justification = "Class name is NativeMethodsShared for increased clarity")]
        [DllImport(kernel32Dll, SetLastError = true, CharSet = CharSet.Unicode)]
        internal static extern int GetModuleFileName(
#if FEATURE_HANDLEREF
            HandleRef hModule,
#else
            IntPtr hModule,
#endif
            [Out] StringBuilder buffer, int length);

        [SuppressMessage("Microsoft.Design", "CA1060:MovePInvokesToNativeMethodsClass", Justification = "Class name is NativeMethodsShared for increased clarity")]
        [DllImport("kernel32.dll")]
        internal static extern IntPtr GetStdHandle(int nStdHandle);

        [SuppressMessage("Microsoft.Design", "CA1060:MovePInvokesToNativeMethodsClass", Justification = "Class name is NativeMethodsShared for increased clarity")]
        [DllImport("kernel32.dll")]
        internal static extern uint GetFileType(IntPtr hFile);

        [SuppressMessage("Microsoft.Design", "CA1060:MovePInvokesToNativeMethodsClass", Justification = "Class name is NativeMethodsShared for increased clarity")]
        [SuppressMessage("Microsoft.Usage", "CA2205:UseManagedEquivalentsOfWin32Api", Justification = "Using unmanaged equivalent for performance reasons")]
        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        internal static extern int GetCurrentDirectory(int nBufferLength, [Out] StringBuilder lpBuffer);

        [SuppressMessage("Microsoft.Design", "CA1060:MovePInvokesToNativeMethodsClass", Justification = "Class name is NativeMethodsShared for increased clarity")]
        [SuppressMessage("Microsoft.Usage", "CA2205:UseManagedEquivalentsOfWin32Api", Justification = "Using unmanaged equivalent for performance reasons")]
        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode, EntryPoint = "SetCurrentDirectory")]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool SetCurrentDirectoryWindows(string path);

        internal static bool SetCurrentDirectory(string path)
        {
            if (IsWindows)
            {
                return SetCurrentDirectoryWindows(path);
            }

            // Make sure this does not throw
            try
            {
                Directory.SetCurrentDirectory(path);
            }
            catch
            {
            }
            return true;
        }

        [SuppressMessage("Microsoft.Design", "CA1060:MovePInvokesToNativeMethodsClass", Justification = "Class name is NativeMethodsShared for increased clarity")]
        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        internal static unsafe extern int GetFullPathName(string target, int bufferLength, char* buffer, IntPtr mustBeZero);

        [SuppressMessage("Microsoft.Design", "CA1060:MovePInvokesToNativeMethodsClass", Justification = "Class name is NativeMethodsShared for increased clarity")]
        [DllImport("KERNEL32.DLL")]
        private static extern SafeProcessHandle OpenProcess(eDesiredAccess dwDesiredAccess, [MarshalAs(UnmanagedType.Bool)] bool bInheritHandle, int dwProcessId);

        [SuppressMessage("Microsoft.Design", "CA1060:MovePInvokesToNativeMethodsClass", Justification = "Class name is NativeMethodsShared for increased clarity")]
        [DllImport("NTDLL.DLL")]
        private static extern int NtQueryInformationProcess(SafeProcessHandle hProcess, PROCESSINFOCLASS pic, ref PROCESS_BASIC_INFORMATION pbi, int cb, ref int pSize);

        [SuppressMessage("Microsoft.Design", "CA1060:MovePInvokesToNativeMethodsClass", Justification = "Class name is NativeMethodsShared for increased clarity")]
        [return: MarshalAs(UnmanagedType.Bool)]
        [DllImport("kernel32.dll", CharSet = AutoOrUnicode, SetLastError = true)]
        private static extern bool GlobalMemoryStatusEx([In, Out] MemoryStatus lpBuffer);

        [SuppressMessage("Microsoft.Design", "CA1060:MovePInvokesToNativeMethodsClass", Justification = "Class name is NativeMethodsShared for increased clarity")]
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, BestFitMapping = false)]
        internal static extern int GetShortPathName(string path, [Out] StringBuilder fullpath, [In] int length);

        [SuppressMessage("Microsoft.Design", "CA1060:MovePInvokesToNativeMethodsClass", Justification = "Class name is NativeMethodsShared for increased clarity")]
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, BestFitMapping = false)]
        internal static extern int GetLongPathName([In] string path, [Out] StringBuilder fullpath, [In] int length);

        [SuppressMessage("Microsoft.Design", "CA1060:MovePInvokesToNativeMethodsClass", Justification = "Class name is NativeMethodsShared for increased clarity")]
        [DllImport("kernel32.dll", CharSet = AutoOrUnicode, SetLastError = true)]
        internal static extern bool CreatePipe(out SafeFileHandle hReadPipe, out SafeFileHandle hWritePipe, SecurityAttributes lpPipeAttributes, int nSize);

        [SuppressMessage("Microsoft.Design", "CA1060:MovePInvokesToNativeMethodsClass", Justification = "Class name is NativeMethodsShared for increased clarity")]
        [DllImport("kernel32.dll", CharSet = AutoOrUnicode, SetLastError = true)]
        internal static extern bool ReadFile(SafeFileHandle hFile, byte[] lpBuffer, uint nNumberOfBytesToRead, out uint lpNumberOfBytesRead, IntPtr lpOverlapped);

        /// <summary>
        /// CoWaitForMultipleHandles allows us to wait in an STA apartment and still service RPC requests from other threads.
        /// VS needs this in order to allow the in-proc compilers to properly initialize, since they will make calls from the
        /// build thread which the main thread (blocked on BuildSubmission.Execute) must service.
        /// </summary>
        [SuppressMessage("Microsoft.Design", "CA1060:MovePInvokesToNativeMethodsClass", Justification = "Class name is NativeMethodsShared for increased clarity")]
        [DllImport("ole32.dll")]
        internal static extern int CoWaitForMultipleHandles(COWAIT_FLAGS dwFlags, int dwTimeout, int cHandles, [MarshalAs(UnmanagedType.LPArray)] IntPtr[] pHandles, out int pdwIndex);

        internal const uint GENERIC_READ = 0x80000000;
        internal const uint FILE_SHARE_READ = 0x1;
        internal const uint FILE_ATTRIBUTE_NORMAL = 0x80;
        internal const uint FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000;
        internal const uint OPEN_EXISTING = 3;

        [DllImport("kernel32.dll", CharSet = AutoOrUnicode, CallingConvention = CallingConvention.StdCall,
            SetLastError = true)]
        internal static extern SafeFileHandle CreateFile(
            string lpFileName,
            uint dwDesiredAccess,
            uint dwShareMode,
            IntPtr lpSecurityAttributes,
            uint dwCreationDisposition,
            uint dwFlagsAndAttributes,
            IntPtr hTemplateFile
            );

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern bool GetFileTime(
            SafeFileHandle hFile,
            out System.Runtime.InteropServices.ComTypes.FILETIME lpCreationTime,
            out System.Runtime.InteropServices.ComTypes.FILETIME lpLastAccessTime,
            out System.Runtime.InteropServices.ComTypes.FILETIME lpLastWriteTime
            );


        /// <summary>
        /// Really truly non pumping wait.
        /// Raw IntPtrs have to be used, because the marshaller does not support arrays of SafeHandle, only
        /// single SafeHandles.
        /// </summary>
        [SuppressMessage("Microsoft.Design", "CA1060:MovePInvokesToNativeMethodsClass", Justification = "Class name is NativeMethodsShared for increased clarity")]
        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        internal static extern Int32 WaitForMultipleObjects(uint handle, IntPtr[] handles, bool waitAll, uint milliseconds);

        [SuppressMessage("Microsoft.Design", "CA1060:MovePInvokesToNativeMethodsClass", Justification = "Class name is NativeMethodsShared for increased clarity")]
        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern void GetSystemInfo(ref SYSTEM_INFO lpSystemInfo);

        [SuppressMessage("Microsoft.Design", "CA1060:MovePInvokesToNativeMethodsClass", Justification = "Class name is NativeMethodsShared for increased clarity")]
        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern void GetNativeSystemInfo(ref SYSTEM_INFO lpSystemInfo);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool CopyFileEx(string lpExistingFileName, string lpNewFileName,
            CopyProgressRoutine lpProgressRoutine, IntPtr lpData, ref Int32 pbCancel,
            CopyFileFlags dwCopyFlags);

        [DllImport("kernel32.dll")]
        internal static extern uint GetCurrentThreadId();

        [DllImport("kernel32.dll")]
        internal static extern uint GetCurrentProcessId();

        #endregion

    }

}
