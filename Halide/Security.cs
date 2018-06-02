using System;
using System.Configuration;
using System.Collections;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Data;
using System.Data.OleDb;
using System.Data.SqlClient;
using System.Drawing;
using System.Drawing.Imaging;
using System.Globalization;
using System.Net;
using System.Net.Mail;
using System.Net.Mime;
using System.IO;
using System.IO.Compression;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.RegularExpressions;
using System.Timers;
using System.Web;
using System.Web.Mail;
using System.Web.Security;
using System.Web.UI;
using System.Web.UI.WebControls;
using System.Web.UI.WebControls.WebParts;
using System.Web.UI.HtmlControls;
using System.Xml;

using Fynydd.Halide.Constants;

namespace Fynydd.Halide
{
    public static class Security
    {
        #region Properties

        /// <summary>
        /// The secret key to use for the symmetric algorithm.
        /// You should change these numbers for your individual use
        /// by adding an encryptionBaseKey attribute to the Halide Settings
        /// config setting within the web.config file.
        /// </summary>
        public static byte[] basekey1
        {
            get
            {
                string key = Configuration.GetKeyValue<string>("EncryptionBaseKey", "", "Fynydd.Halide");

                byte[] _basekey1 = CreateBaseKey(key);

                return _basekey1;
            }
        }

        /// <summary>
        /// The initialization vector to use for the symmetric algorithm.
        /// You should change these numbers for your individual use
        /// by adding an encryptionInitVector attribute to the Halide Settings
        /// config setting within the web.config file.
        /// </summary>
        public static byte[] iv
        {
            get
            {
                string key = Configuration.GetKeyValue<string>("EncryptionInitVector", "", "Fynydd.Halide");

                byte[] _iv = CreateInitVector(key);

                return _iv;
            }
        }

        #endregion

        #region Identity

        /// <summary>
        /// Get the currently logged-in user name (with domain) for the running web page.
        /// </summary>
        /// <example>
        /// <code>
        /// Response.Write (Security.GetIdentity());
        /// </code>
        /// </example>
        /// <returns>String containing the domain and user name currently logged in via the Impersonation method.</returns>
        public static string GetIdentity()
        {
            return WindowsIdentity.GetCurrent().Name;
        }

        /// <summary>
        /// Get the currently logged-in user name (with domain) from the client.
        /// </summary>
        /// <example>
        /// <code>
        /// Response.Write (Security.GetCurrentUser());
        /// </code>
        /// </example>
        /// <returns>String containing the domain and user name currently logged in via the web browser's authentication dialog.</returns>
        public static string GetCurrentUser()
        {
            return HttpContext.Current.User.Identity.Name.ToString();
        }

        #endregion

        #region Encryption

        /// <summary>
        /// Converts a comma-separated string of 24 8-bit values and converts it into a Byte array.
        /// </summary>
        /// <example>
        /// <code>
        /// Byte[] baseKey = Security.CreateBaseKey("151, 4, 109, 42, 135, 99, 67, 82, 242, 233, 16, 200, 9, 83, 196, 178, 56, 74, 90, 36, 206, 129, 81, 229, 67, 82, 242, 233, 16, 200, 9, 83");
        /// </code>
        /// </example>
        /// <param name="key">32 8-bit values in a comma-separated list.</param>
        /// <returns>Byte array</returns>
        public static byte[] CreateBaseKey(this string key)
        {
            byte[] result = { };
            int bitLength = 32;

            try
            {
                if (!string.IsNullOrEmpty(key))
                {
                    string[] bArray = key.Replace(" ", "").Split(',');

                    if (bArray.Length == bitLength)
                    {
                        result = new byte[bitLength];

                        for (int x = 0; x < bArray.Length; x++)
                        {
                            result[x] = Convert.ToByte(bArray[x].Trim());
                        }
                    }
                }
            }

            catch (Exception err)
            {
                throw new Exception("Halide.Security Error: " + err.ToString());
            }

            return result;
        }

        /// <summary>
        /// Converts a comma-separated string of 18 8-bit values and converts it into a Byte array.
        /// </summary>
        /// <example>
        /// <code>
        /// Byte[] baseIV = Security.CreateInitVector("180, 54, 206, 210, 10, 101, 6, 87, 13, 3, 241, 189, 176, 175, 109, 217");
        /// </code>
        /// </example>
        /// <param name="key">18 8-bit values in a comma-separated list.</param>
        /// <returns>Byte array</returns>
        public static byte[] CreateInitVector(this string key)
        {
            byte[] result = { };
            int bitLength = 16;

            try
            {
                if (!string.IsNullOrEmpty(key))
                {
                    string[] bArray = key.Replace(" ", "").Split(',');

                    if (bArray.Length == bitLength)
                    {
                        result = new byte[bitLength];

                        for (int x = 0; x < bArray.Length; x++)
                        {
                            result[x] = Convert.ToByte(bArray[x].Trim());
                        }
                    }
                }
            }

            catch (Exception err)
            {
                throw new Exception("Halide.Security Error: " + err.ToString());
            }

            return result;
        }

        /// <summary>
        /// Generate a comma-separated string of 8-bit values for an encryption base key.
        /// The value is not guaranteed to be unique.
        /// </summary>
        /// <example>
        /// <code>
        /// string baseKey = Security.GenerateKey(32);
        /// </code>
        /// </example>
        /// <param name="count">Number of 8-bit numbers to generate</param>
        /// <returns>Comma-separated string of 8-bit values</returns>
        public static string GenerateKey(int count)
        {
            string result = "";

            if (count > 0)
            {
                try
                {
                    byte[] randomNumber = new byte[count];
                    RNGCryptoServiceProvider Gen = new RNGCryptoServiceProvider();
                    Gen.GetBytes(randomNumber);

                    for (int x = 0; x < count; x++)
                    {
                        if (x > 0)
                        {
                            result += ",";
                        }

                        result += Convert.ToInt32(randomNumber[x]).ToString();
                    }
                }

                catch (Exception err)
                {
                    throw new Exception("Halide.Security Error: " + err.ToString());
                }
            }

            return result;
        }

        /// <summary>
        /// Triple DES 256 bit string encryption.
        /// </summary>
        /// <example>
        /// <code>
        /// Byte[] ivec = { 180, 54, 206, 210, 10, 101, 6, 87, 13, 3, 241, 189, 176, 175, 109, 217 };
        /// Byte[] key = { 151, 4, 109, 42, 135, 99, 67, 82, 242, 233, 16, 200, 9, 83, 196, 178, 56, 74, 90, 36, 206, 129, 81, 229, 67, 82, 242, 233, 16, 200, 9, 83 };
        /// String encryptedVar = Security.Encrypt(dataToEncrypt, key, ivec);
        /// </code>
        /// </example>
        /// <param name="data">Data to encrypt.</param>
        /// <param name="key">24 byte array key for encrypting the data.</param>
        /// <param name="ivec">18 byte array initialization vector for the encryption routine.</param>
        /// <returns>An encrypted string.</returns>
        public static string Encrypt<T>(this T data, byte[] key, byte[] ivec)
        {
            string result = "";

            try
            {
                ASCIIEncoding encoder = new ASCIIEncoding();
                byte[] inputInBytes = null;

                if (typeof(T) == typeof(string) || typeof(T) == typeof(DateTime))
                {
                    byte[] stringBytes = encoder.GetBytes((string)Convert.ChangeType(data, typeof(string)));
                    inputInBytes = stringBytes;
                }

                else if (typeof(T) == typeof(short) || typeof(T) == typeof(Int16))
                {
                    byte[] stringBytes = BitConverter.GetBytes((short)Convert.ChangeType(data, typeof(short)));
                    inputInBytes = stringBytes;
                }

                else if (typeof(T) == typeof(ushort) || typeof(T) == typeof(UInt16))
                {
                    byte[] stringBytes = BitConverter.GetBytes((ushort)Convert.ChangeType(data, typeof(ushort)));
                    inputInBytes = stringBytes;
                }

                else if (typeof(T) == typeof(int) || typeof(T) == typeof(Int32))
                {
                    byte[] stringBytes = BitConverter.GetBytes((int)Convert.ChangeType(data, typeof(int)));
                    inputInBytes = stringBytes;
                }

                else if (typeof(T) == typeof(uint) || typeof(T) == typeof(UInt32))
                {
                    byte[] stringBytes = BitConverter.GetBytes((uint)Convert.ChangeType(data, typeof(uint)));
                    inputInBytes = stringBytes;
                }

                else if (typeof(T) == typeof(long) || typeof(T) == typeof(Int64))
                {
                    byte[] stringBytes = BitConverter.GetBytes((long)Convert.ChangeType(data, typeof(long)));
                    inputInBytes = stringBytes;
                }

                else if (typeof(T) == typeof(ulong) || typeof(T) == typeof(UInt64))
                {
                    byte[] stringBytes = BitConverter.GetBytes((ulong)Convert.ChangeType(data, typeof(ulong)));
                    inputInBytes = stringBytes;
                }

                else if (typeof(T) == typeof(float) || typeof(T) == typeof(Single))
                {
                    byte[] stringBytes = BitConverter.GetBytes((float)Convert.ChangeType(data, typeof(float)));
                    inputInBytes = stringBytes;
                }

                else if (typeof(T) == typeof(double) || typeof(T) == typeof(Double))
                {
                    byte[] stringBytes = BitConverter.GetBytes((double)Convert.ChangeType(data, typeof(double)));
                    inputInBytes = stringBytes;
                }

                if (inputInBytes != null)
                {
                    AesCryptoServiceProvider aesProvider = new AesCryptoServiceProvider();
                    aesProvider.BlockSize = 128;
                    aesProvider.KeySize = 256;
                    ICryptoTransform cryptoTransform = aesProvider.CreateEncryptor(key, ivec);
                    MemoryStream encryptedStream = new MemoryStream();
                    CryptoStream cryptStream = new CryptoStream(encryptedStream, cryptoTransform, CryptoStreamMode.Write);

                    cryptStream.Write(inputInBytes, 0, inputInBytes.Length);
                    cryptStream.FlushFinalBlock();
                    encryptedStream.Position = 0;

                    byte[] bytes = new byte[encryptedStream.Length];
                    encryptedStream.Read(bytes, 0, Convert.ToInt32(encryptedStream.Length));

                    cryptStream.Close();

                    result = Base64PlusStringEncode(bytes);
                }
            }

            catch (Exception err)
            {
                throw new Exception("Halide.Security Error: " + err.ToString());
            }

            return result;
        }

        /// <summary>
        /// Triple DES 256 bit encryption of 64-bit integers.
        /// </summary>
        /// <example>
        /// <code>
        /// String encryptedVar = Security.EncryptInt64(2346517451, "151, 4, 109, 42, 135, 99, 67, 82, 242, 233, 16, 200, 9, 83, 196, 178, 56, 74, 90, 36, 206, 129, 81, 229, 67, 82, 242, 233, 16, 200, 9, 83", "180, 54, 206, 210, 10, 101, 6, 87, 13, 3, 241, 189, 176, 175, 109, 217" );
        /// </code>
        /// </example>
        /// <param name="data">Long integer to encrypt.</param>
        /// <param name="key">24 byte key string for encrypting the data.</param>
        /// <param name="ivec">18 byte initialization vector string for the encryption routine.</param>
        /// <returns>An encrypted string.</returns>
        public static string Encrypt<T>(this T data, string key, string ivec)
        {
            return Encrypt(data, CreateBaseKey(key), CreateInitVector(ivec));
        }

        /// <summary>
        /// Triple DES 256 bit string decryption.
        /// </summary>
        /// <example>
        /// <code>
        /// String decryptedVar = Security.Decrypt(encryptedVar, "151, 4, 109, 42, 135, 99, 67, 82, 242, 233, 16, 200, 9, 83, 196, 178, 56, 74, 90, 36, 206, 129, 81, 229, 67, 82, 242, 233, 16, 200, 9, 83", "180, 54, 206, 210, 10, 101, 6, 87, 13, 3, 241, 189, 176, 175, 109, 217" );
        /// </code>
        /// </example>
        /// <param name="data">String to decrypt.</param>
        /// <param name="key">24 byte key string for decrypting the data. This must match the key used to encrypt the data.</param>
        /// <param name="ivec">18 byte initialization vector string for the decryption routine. This must match the init vector used to encrypt the data.</param>
        /// <returns>A decrypted string</returns>
        public static T Decrypt<T>(this string data, string key, string ivec)
        {
            return Decrypt<T>(data, CreateBaseKey(key), CreateInitVector(ivec));
        }

        /// <summary>
        /// Triple DES 256 bit string decryption.
        /// </summary>
        /// <example>
        /// <code>
        /// Byte[] ivec = { 180, 54, 206, 210, 10, 101, 6, 87, 13, 3, 241, 189, 176, 175, 109, 217 };
        /// Byte[] key = { 151, 4, 109, 42, 135, 99, 67, 82, 242, 233, 16, 200, 9, 83, 196, 178, 56, 74, 90, 36, 206, 129, 81, 229, 67, 82, 242, 233, 16, 200, 9, 83 };
        /// String decryptedVar = Security.Decrypt(encryptedVar, bytekey, ivec);
        /// </code>
        /// </example>
        /// <param name="data">String to decrypt.</param>
        /// <param name="key">24 byte array key for decrypting the data. This must match the key used to encrypt the data.</param>
        /// <param name="ivec">18 byte array init vector for decrypting the data. This must match the init vector used to encrypt the data.</param>
        /// <returns>A decrypted string</returns>
        public static T Decrypt<T>(this string data, byte[] key, byte[] ivec)
        {
            T result = default(T);
            string newData = data;
            ASCIIEncoding encoder = new ASCIIEncoding();

            AesCryptoServiceProvider aesProvider = new AesCryptoServiceProvider();
            aesProvider.BlockSize = 128;
            aesProvider.KeySize = 256;
            ICryptoTransform cryptoTransform = aesProvider.CreateDecryptor(key, ivec);
            MemoryStream decryptedStream = new MemoryStream();

            try
            {
                byte[] inputInBytes = Base64PlusStringDecodeToBytes(newData);
                CryptoStream cryptStream = new CryptoStream(decryptedStream, cryptoTransform, CryptoStreamMode.Write);

                cryptStream.Write(inputInBytes, 0, inputInBytes.Length);
                cryptStream.FlushFinalBlock();
                decryptedStream.Position = 0;

                byte[] bytes = new byte[decryptedStream.Length];
                decryptedStream.Read(bytes, 0, Convert.ToInt32(decryptedStream.Length));

                cryptStream.Close();

                try
                {
                    if (typeof(T) == typeof(string) || typeof(T) == typeof(DateTime))
                    {
                        string decrypted = encoder.GetString(bytes);

                        if (string.IsNullOrEmpty(decrypted))
                        {
                            if (typeof(T) == typeof(string))
                            {
                                result = (T)Convert.ChangeType("", typeof(T));
                            }

                            else
                            {
                                DateTime fallback = new DateTime();
                                result = (T)Convert.ChangeType(fallback, typeof(T));
                            }
                        }

                        else
                        {
                            result = (T)Convert.ChangeType(decrypted, typeof(T));
                        }
                    }

                    else if (typeof(T) == typeof(short) || typeof(T) == typeof(Int16))
                    {
                        short decrypted = BitConverter.ToInt16(bytes, 0);
                        result = (T)Convert.ChangeType(decrypted, typeof(T));
                    }

                    else if (typeof(T) == typeof(ushort) || typeof(T) == typeof(UInt16))
                    {
                        ushort decrypted = BitConverter.ToUInt16(bytes, 0);
                        result = (T)Convert.ChangeType(decrypted, typeof(T));
                    }

                    else if (typeof(T) == typeof(int) || typeof(T) == typeof(Int32))
                    {
                        int decrypted = BitConverter.ToInt32(bytes, 0);
                        result = (T)Convert.ChangeType(decrypted, typeof(T));
                    }

                    else if (typeof(T) == typeof(uint) || typeof(T) == typeof(UInt32))
                    {
                        uint decrypted = BitConverter.ToUInt32(bytes, 0);
                        result = (T)Convert.ChangeType(decrypted, typeof(T));
                    }

                    else if (typeof(T) == typeof(long) || typeof(T) == typeof(Int64))
                    {
                        long decrypted = BitConverter.ToInt64(bytes, 0);
                        result = (T)Convert.ChangeType(decrypted, typeof(T));
                    }

                    else if (typeof(T) == typeof(ulong) || typeof(T) == typeof(UInt64))
                    {
                        ulong decrypted = BitConverter.ToUInt64(bytes, 0);
                        result = (T)Convert.ChangeType(decrypted, typeof(T));
                    }

                    else if (typeof(T) == typeof(float) || typeof(T) == typeof(Single))
                    {
                        float decrypted = BitConverter.ToSingle(bytes, 0);
                        result = (T)Convert.ChangeType(decrypted, typeof(T));
                    }

                    else if (typeof(T) == typeof(double) || typeof(T) == typeof(Double))
                    {
                        double decrypted = BitConverter.ToDouble(bytes, 0);
                        result = (T)Convert.ChangeType(decrypted, typeof(T));
                    }
                }

                catch
                {
                    result = default(T);
                }
            }

            catch
            {
                result = default(T);
            }

            return result;
        }

        /// <summary>
        /// MD5 encodes the passed string.
        /// </summary>
        /// <example>
        /// <code>
        /// string encodedVar = Security.MD5String(stringVar);
        /// </code>
        /// </example>
        /// <param name="input">The string to encode.</param>
        /// <returns>An MD5 encoded string.</returns>
        public static string MD5String(this string input)
        {
            // Create a new instance of the MD5CryptoServiceProvider object.
            MD5 md5Hasher = MD5.Create();

            // Convert the input string to a byte array and compute the hash.
            byte[] data = md5Hasher.ComputeHash(Encoding.Default.GetBytes(input));

            // Create a new Stringbuilder to collect the bytes
            // and create a string.
            StringBuilder sBuilder = new StringBuilder();

            // Loop through each byte of the hashed data 
            // and format each one as a hexadecimal string.
            for (int i = 0; i < data.Length; i++)
            {
                sBuilder.Append(data[i].ToString("x2"));
            }

            // Return the hexadecimal string.
            return sBuilder.ToString();
        }

        /// <summary>
        /// Verified a string against the passed MD5 hash.
        /// </summary>
        /// <example>
        /// <code>
        /// if (Security.MD5VerifyString(stringVar, hash))...
        /// </code>
        /// </example>
        /// <param name="input">The string to compare.</param>
        /// <param name="hash">The hash to compare against.</param>
        /// <returns>true if the input and the hash are the same, false otherwise.</returns>
        public static bool MD5VerifyString(this string input, string hash)
        {
            bool result = false;

            // Hash the input.
            string hashOfInput = MD5String(input);

            // Create a StringComparer and compare the hashes.
            StringComparer comparer = StringComparer.OrdinalIgnoreCase;

            if (0 == comparer.Compare(hashOfInput, hash))
            {
                result = true;
            }

            return result;
        }

        /// <summary>
        /// Base64 encodes a string.
        /// </summary>
        /// <example>
        /// <code>
        /// string encodedVar = Security.Base64StringEncode(stringVar);
        /// </code>
        /// </example>
        /// <param name="input">A string to encode.</param>
        /// <returns>A base64 encoded string.</returns>
        public static string Base64StringEncode(this string input)
        {
            byte[] encbuff = System.Text.Encoding.UTF8.GetBytes(input);
            return Convert.ToBase64String(encbuff);
        }

        /// <summary>
        /// Base64 decodes a string.
        /// </summary>
        /// <example>
        /// <code>
        /// string decodedVar = Security.Base64StringDecode(stringVar);
        /// </code>
        /// </example>
        /// <param name="input">A base64 encoded string.</param>
        /// <returns>A decoded string.</returns>
        public static string Base64StringDecode(this string input)
        {
            byte[] decbuff = Convert.FromBase64String(input);
            return System.Text.Encoding.UTF8.GetString(decbuff);
        }

        /// <summary>
        /// Base64+ encodes a string (valid in REST URL).
        /// </summary>
        /// <example>
        /// <code>
        /// string encodedVar = Security.Base64PlusStringEncode(bytes);
        /// </code>
        /// </example>
        /// <param name="input">A byte array to encode.</param>
        /// <returns>A base64+ encoded string.</returns>
        public static string Base64PlusStringEncode(this byte[] input)
        {
            return Convert.ToBase64String(input).Replace("/", "~").Replace("+", "-").Replace("=", "");
        }

        /// <summary>
        /// Base64+ encodes a string (valid in REST URL).
        /// </summary>
        /// <example>
        /// <code>
        /// string encodedVar = Security.Base64PlusStringEncode(stringVar);
        /// </code>
        /// </example>
        /// <param name="input">A string to encode.</param>
        /// <returns>A base64+ encoded string.</returns>
        public static string Base64PlusStringEncode(this string input)
        {
            byte[] encbuff = System.Text.Encoding.UTF8.GetBytes(input);
            return Base64PlusStringEncode(encbuff);
        }

        /// <summary>
        /// Base64+ decodes a string (valid in REST URL). Handles missing padding characters.
        /// </summary>
        /// <example>
        /// <code>
        /// byte[] decodedVar = Security.Base64PlusStringDecodeToBytes(stringVar);
        /// </code>
        /// </example>
        /// <param name="input">A base64+ encoded string.</param>
        /// <returns>A decoded byte array.</returns>
        public static byte[] Base64PlusStringDecodeToBytes(this string input)
        {
            byte[] decbuff = { };

            if (!string.IsNullOrEmpty(input))
            {
                int missing_padding = 4 - input.Length % 4;

                if (missing_padding == 4)
                {
                    missing_padding = 0;
                }

                decbuff = Convert.FromBase64String(input.Replace("~", "/").Replace("-", "+").PadRight(input.Length + missing_padding, '='));
            }

            return decbuff;
        }

        /// <summary>
        /// Base64+ decodes a string (valid in REST URL). Handles missing padding characters.
        /// </summary>
        /// <example>
        /// <code>
        /// string decodedVar = Security.Base64PlusStringDecode(stringVar);
        /// </code>
        /// </example>
        /// <param name="input">A base64+ encoded string.</param>
        /// <returns>A decoded string.</returns>
        public static string Base64PlusStringDecode(this string input)
        {
            byte[] decbuff = Base64PlusStringDecodeToBytes(input);
            return System.Text.Encoding.UTF8.GetString(decbuff);
        }

        #endregion
    }
}
