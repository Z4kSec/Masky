using System;
using System.Runtime.InteropServices;
using DWORD = System.UInt32;

using DI = DInvoke;
using static DInvoke.Data.Native;
using static DInvoke.DynamicInvoke.Generic;

namespace Masky {
    public class Interop {
        public enum TOKEN_INFORMATION_CLASS
        {
            TokenUser = 1,
            TokenGroups,
            TokenPrivileges,
            TokenOwner,
            TokenPrimaryGroup,
            TokenDefaultDacl,
            TokenSource,
            TokenType,
            TokenImpersonationLevel,
            TokenStatistics,
            TokenRestrictedSids,
            TokenSessionId,
            TokenGroupsAndPrivileges,
            TokenSessionReference,
            TokenSandBoxInert,
            TokenAuditPolicy,
            TokenOrigin,
            TokenElevationType,
            TokenLinkedToken,
            TokenElevation,
            TokenHasRestrictions,
            TokenAccessInformation,
            TokenVirtualizationAllowed,
            TokenVirtualizationEnabled,
            TokenIntegrityLevel,
            TokenUIAccess,
            TokenMandatoryPolicy,
            TokenLogonSid,
            MaxTokenInfoClass
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct TOKEN_USER
        {
            public _SID_AND_ATTRIBUTES User;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct _SID_AND_ATTRIBUTES
        {
            public IntPtr Sid;
            public int Attributes;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public int dwProcessId;
            public int dwThreadId;
        }

        public struct STARTUPINFO
        {
            public Int32 cb;
            public string lpReserved;
            public string lpDesktop;
            public string lpTitle;
            public Int32 dwX;
            public Int32 dwY;
            public Int32 dwXSize;
            public Int32 dwYSize;
            public Int32 dwXCountChars;
            public Int32 dwYCountChars;
            public Int32 dwFillAttribute;
            public Int32 dwFlags;
            public Int16 wShowWindow;
            public Int16 cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct SECURITY_ATTRIBUTES
        {
            public int nLength;
            public IntPtr lpSecurityDescriptor;
            public int bInheritHandle;
        }

        public enum SECURITY_IMPERSONATION_LEVEL : int {
            SecurityAnonymous,
            SecurityIdentification,
            SecurityImpersonation,
            SecurityDelegation
        }

        public enum TOKEN_TYPE {
            TokenPrimary = 1,
            TokenImpersonation
        }

        public const DWORD STANDARD_RIGHTS_REQUIRED = 0x000F0000;
        public const DWORD STANDARD_RIGHTS_READ = 0x00020000;
        public const DWORD TOKEN_ASSIGN_PRIMARY = 0x0001;
        public const DWORD TOKEN_DUPLICATE = 0x0002;
        public const DWORD TOKEN_IMPERSONATE = 0x0004;
        public const DWORD TOKEN_QUERY = 0x0008;
        public const DWORD TOKEN_QUERY_SOURCE = 0x0010;
        public const DWORD TOKEN_ADJUST_PRIVILEGES = 0x0020;
        public const DWORD TOKEN_ADJUST_GROUPS = 0x0040;
        public const DWORD TOKEN_ADJUST_DEFAULT = 0x0080;
        public const DWORD TOKEN_ADJUST_SESSIONID = 0x0100;

        public const UInt32 TOKEN_ALL_ACCESS = (STANDARD_RIGHTS_REQUIRED | TOKEN_ASSIGN_PRIMARY | TOKEN_DUPLICATE | TOKEN_IMPERSONATE | TOKEN_QUERY | TOKEN_QUERY_SOURCE | TOKEN_ADJUST_PRIVILEGES | TOKEN_ADJUST_GROUPS | TOKEN_ADJUST_DEFAULT | TOKEN_ADJUST_SESSIONID);


        public enum CreationFlags
        {
            CREATE_SUSPENDED       = 0x00000004,
            CREATE_NEW_CONSOLE     = 0x00000010,
            CREATE_NEW_PROCESS_GROUP   = 0x00000200,
            CREATE_UNICODE_ENVIRONMENT = 0x00000400,
            CREATE_SEPARATE_WOW_VDM    = 0x00000800,
            CREATE_DEFAULT_ERROR_MODE  = 0x04000000,
        }

        [Flags]
        public enum LogonFlags
        {
            LOGON_WITH_PROFILE     = 0x00000001,
            LOGON_NETCREDENTIALS_ONLY  = 0x00000002    
        }

        public static NTSTATUS NtOpenProcessToken(IntPtr ProcessHandle, UInt32 DesiredAccess, out IntPtr TokenHandle)
        {
            var stub = GetSyscallStub("ZwOpenProcessToken");
            var ntOpenProcessToken = (Delegates.NtOpenProcessToken)Marshal.GetDelegateForFunctionPointer(stub, typeof(Delegates.NtOpenProcessToken));

            return ntOpenProcessToken(
                ProcessHandle,
                DesiredAccess,
                out TokenHandle);
        }

        public static bool DuplicateTokenEx(IntPtr hExistingToken, uint dwDesiredAccess, ref SECURITY_ATTRIBUTES lpTokenAttributes, SECURITY_IMPERSONATION_LEVEL ImpersonationLevel, TOKEN_TYPE TokenType, out IntPtr phNewToken)
        {
            var NewToken = new IntPtr();

            object[] parameters = { hExistingToken, dwDesiredAccess, lpTokenAttributes, ImpersonationLevel, TokenType, NewToken };
            var result = (bool)DynamicAPIInvoke("advapi32.dll", "DuplicateTokenEx", typeof(Delegates.DuplicateTokenEx), ref parameters);

            phNewToken = (IntPtr)parameters[5];
            return result;
        }

        public static bool SetThreadToken(IntPtr Thread, IntPtr TokenHandle)
        {
            object[] parameters = { Thread, TokenHandle };
            var result = (bool)DynamicAPIInvoke("advapi32.dll", "SetThreadToken", typeof(Delegates.SetThreadToken), ref parameters);
            return result;
        }

        public static NTSTATUS NtClose(IntPtr hObject)
        {
            var stub = GetSyscallStub("ZwClose");
            var ntClose = (Delegates.NtClose)Marshal.GetDelegateForFunctionPointer(stub, typeof(Delegates.NtClose));

            return ntClose(hObject);
        }
    }

    class Delegates
    {
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate NTSTATUS NtOpenProcessToken(
            IntPtr ProcessHandle,
            UInt32 DesiredAccess,
            out IntPtr TokenHandle);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate bool DuplicateTokenEx(
            IntPtr hExistingToken,
            uint dwDesiredAccess,
            ref Interop.SECURITY_ATTRIBUTES lpTokenAttributes,
            Interop.SECURITY_IMPERSONATION_LEVEL ImpersonationLevel,
            Interop.TOKEN_TYPE TokenType,
            out IntPtr phNewToken);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate bool SetThreadToken(
            IntPtr Thread,
            IntPtr TokenHandle);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate NTSTATUS NtClose(IntPtr hObject);
    }
}