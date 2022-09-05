
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.IO;

namespace Masky
{
    public class Program
    {
        public static bool WriteResultsInFile(List<SpoofedUser> SpoofedUsers, StreamWriter outStream)
        {
            try
            {
                if (SpoofedUsers.Count != 0)
                {
                    string jsonContent = JsonConvert.SerializeObject(SpoofedUsers, Formatting.Indented);
                    outStream.WriteLine(jsonContent);
                }
                else
                {
                    outStream.WriteLine("");
                }
                outStream.Flush();
                outStream.Close();
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine(ex.ToString());
                return false;
            }
            return true;
        }

        public static StreamWriter getOutputStream(string file_path)
        {
            try
            {
                StreamWriter outStream = new StreamWriter(file_path);
                return outStream;
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine(ex.ToString());
                return null;
            }
        }

        public static bool setDebugFile(string file_path)
        {
            try
            {
                StreamWriter dbgStream = new StreamWriter(file_path);
                Console.SetError(dbgStream);
            }
            catch
            {
                return false;
            }
            return true;
        }

        public static void Main(string[] unparsed_args)
        {
            try
            {
                ArgParser args = new ArgParser(unparsed_args);
                if (!args.Parse())
                    return;
                string ca = args.ca;
                string template = args.template;
                string output_file = args.output_file;
                string debug_file = args.debug_file;
                bool current_user_only = args.current_user;

                StreamWriter outStream = getOutputStream(output_file);
                setDebugFile(debug_file);
                Impersonate impersonate = new Impersonate();
                Cert cert = new Cert(ca, template);
                Action action = cert.GetCertUser;
                if (current_user_only)
                    cert.GetCertUser();
                else
                    impersonate.Run(action);
                WriteResultsInFile(cert.spoofedUsers, outStream);
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine(ex.ToString());
            }
            Console.Error.Close();
        }
    }

}

