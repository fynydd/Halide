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
    public static class Encryption
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
                string key = Config.GetKeyValue<string>("EncryptionBaseKey", "", "Fynydd.Halide");

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
                string key = Config.GetKeyValue<string>("EncryptionInitVector", "", "Fynydd.Halide");

                byte[] _iv = CreateInitVector(key);

                return _iv;
            }
        }

        #endregion

        #region Key generation

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

        #endregion

        #region Encryption and decryption methods

        /// <summary>
        /// AES256 string encryption.
        /// </summary>
        /// <example>
        /// <code>
        /// Byte[] ivec = { 180, 54, 206, 210, 10, 101, 6, 87, 13, 3, 241, 189, 176, 175, 109, 217 };
        /// Byte[] key = { 151, 4, 109, 42, 135, 99, 67, 82, 242, 233, 16, 200, 9, 83, 196, 178, 56, 74, 90, 36, 206, 129, 81, 229, 67, 82, 242, 233, 16, 200, 9, 83 };
        /// string encryptedVar = Security.Encrypt<string>(dataToEncrypt, key, ivec);
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
        /// AES256 string encryption.
        /// </summary>
        /// <example>
        /// <code>
        /// string encryptedVar = Security.Encrypt<string>(myData, "151, 4, 109, 42, 135, 99, 67, 82, 242, 233, 16, 200, 9, 83, 196, 178, 56, 74, 90, 36, 206, 129, 81, 229, 67, 82, 242, 233, 16, 200, 9, 83", "180, 54, 206, 210, 10, 101, 6, 87, 13, 3, 241, 189, 176, 175, 109, 217" );
        /// </code>
        /// </example>
        /// <param name="data">Data to encrypt.</param>
        /// <param name="key">24 byte key string for encrypting the data.</param>
        /// <param name="ivec">18 byte initialization vector string for the encryption routine.</param>
        /// <returns>A BASE64+ encrypted string.</returns>
        public static string Encrypt<T>(this T data, string key, string ivec)
        {
            return Encrypt(data, CreateBaseKey(key), CreateInitVector(ivec));
        }

        /// <summary>
        /// AES256 string encryption.
        /// </summary>
        /// <example>
        /// <code>
        /// string encryptedVar = Security.Encrypt<string>(myData);
        /// </code>
        /// </example>
        /// <param name="data">Data to encrypt.</param>
        /// <returns>A BASE64+ encrypted string.</returns>
        public static string Encrypt<T>(this T data)
        {
            string key = Config.GetKeyValue("EncryptionBaseKey", "Fynydd.Halide");
            string ivec = Config.GetKeyValue("EncryptionInitVector", "Fynydd.Halide");

            return Encrypt(data, CreateBaseKey(key), CreateInitVector(ivec));
        }

        /// <summary>
        /// AES256 string decryption.
        /// </summary>
        /// <example>
        /// <code>
        /// string decryptedVar = Security.Decrypt<string>(encryptedVar, "151, 4, 109, 42, 135, 99, 67, 82, 242, 233, 16, 200, 9, 83, 196, 178, 56, 74, 90, 36, 206, 129, 81, 229, 67, 82, 242, 233, 16, 200, 9, 83", "180, 54, 206, 210, 10, 101, 6, 87, 13, 3, 241, 189, 176, 175, 109, 217" );
        /// </code>
        /// </example>
        /// <param name="data">String to decrypt.</param>
        /// <param name="key">24 byte key string for decrypting the data. This must match the key used to encrypt the data.</param>
        /// <param name="ivec">18 byte initialization vector string for the decryption routine. This must match the init vector used to encrypt the data.</param>
        /// <returns>A decrypted variable</returns>
        public static T Decrypt<T>(this string data, string key, string ivec)
        {
            return Decrypt<T>(data, CreateBaseKey(key), CreateInitVector(ivec));
        }

        /// <summary>
        /// AES256 string decryption.
        /// </summary>
        /// <example>
        /// <code>
        /// string decryptedVar = Security.Decrypt<string>(encryptedVar);
        /// </code>
        /// </example>
        /// <param name="data">String to decrypt.</param>
        /// <returns>A decrypted variable</returns>
        public static T Decrypt<T>(this string data)
        {
            string key = Config.GetKeyValue("EncryptionBaseKey", "Fynydd.Halide");
            string ivec = Config.GetKeyValue("EncryptionInitVector", "Fynydd.Halide");

            return Decrypt<T>(data, CreateBaseKey(key), CreateInitVector(ivec));
        }

        /// <summary>
        /// AES256 string decryption.
        /// </summary>
        /// <example>
        /// <code>
        /// Byte[] ivec = { 180, 54, 206, 210, 10, 101, 6, 87, 13, 3, 241, 189, 176, 175, 109, 217 };
        /// Byte[] key = { 151, 4, 109, 42, 135, 99, 67, 82, 242, 233, 16, 200, 9, 83, 196, 178, 56, 74, 90, 36, 206, 129, 81, 229, 67, 82, 242, 233, 16, 200, 9, 83 };
        /// String decryptedVar = Security.Decrypt<string>(encryptedVar, bytekey, ivec);
        /// </code>
        /// </example>
        /// <param name="data">String to decrypt.</param>
        /// <param name="key">24 byte array key for decrypting the data. This must match the key used to encrypt the data.</param>
        /// <param name="ivec">18 byte array init vector for decrypting the data. This must match the init vector used to encrypt the data.</param>
        /// <returns>A decrypted variable</returns>
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

        #endregion

        #region Hashing and encoding

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
            var output = Convert.ToBase64String(input);

            output = output.Split('=')[0]; // Remove padding
            output = output.Replace('+', '-'); // 62nd char of encoding
            output = output.Replace('/', '_'); // 63rd char of encoding

            return output;
        }

        /// <summary>
        /// Base64Url encodes a string (valid in REST URL).
        /// </summary>
        /// <example>
        /// <code>
        /// string encodedVar = Security.Base64UrlEncode(bytes);
        /// </code>
        /// </example>
        /// <param name="input">A byte array to encode.</param>
        /// <returns>A Base64Url encoded string.</returns>
        public static string Base64UrlEncode(this byte[] input)
        {
            return Base64PlusStringEncode(input);
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
        /// Base64Url encodes a string (valid in REST URL).
        /// </summary>
        /// <example>
        /// <code>
        /// string encodedVar = Security.Base64UrlEncode(stringVar);
        /// </code>
        /// </example>
        /// <param name="input">A string to encode.</param>
        /// <returns>A Base64Url encoded string.</returns>
        public static string Base64UrlEncode(this string input)
        {
            return Base64PlusStringEncode(input);
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
            var output = input;

            output = output.Replace('-', '+'); // 62nd char of encoding
            output = output.Replace('_', '/'); // 63rd char of encoding

            switch (output.Length % 4) // Pad with trailing '='s
            {
                case 0:
                    break; // No padding needed
                case 2:
                    output += "==";
                    break;
                case 3:
                    output += "=";
                    break;
                default:
                    throw new ArgumentOutOfRangeException(nameof(input), "Invalid Base64Url encoding");
            }

            var converted = Convert.FromBase64String(output);

            return converted;
        }

        /// <summary>
        /// Base64Url decodes a string (valid in REST URL). Handles missing padding characters.
        /// </summary>
        /// <example>
        /// <code>
        /// byte[] decodedVar = Security.Base64UrlDecodeToBytes(stringVar);
        /// </code>
        /// </example>
        /// <param name="input">A Base64Url encoded string.</param>
        /// <returns>A decoded byte array.</returns>
        public static byte[] Base64UrlDecodeToBytes(this string input)
        {
            return Base64PlusStringDecodeToBytes(input);
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

        /// <summary>
        /// Base64Url decodes a string (valid in REST URL). Handles missing padding characters.
        /// </summary>
        /// <example>
        /// <code>
        /// string decodedVar = Security.Base64UrlDecodeToString(stringVar);
        /// </code>
        /// </example>
        /// <param name="input">A Base64Url encoded string.</param>
        /// <returns>A decoded string.</returns>
        public static string Base64UrlDecodeToString(this string input)
        {
            return Base64PlusStringDecode(input);
        }

        #endregion

        #region Javascript Web Tokens

        /// <summary>
        /// Generate a javascript web token (JWT) using hash-based message authentication code (HMAC).
        /// 
        /// Use cases:
        /// 1. Stateless sessions stored in browser cookies
        /// 2. Email verification codes
        /// 3. Session IDs with the ability to differentiate between expired and invalid IDs
        /// 
        /// Notes:
        /// 1. The HMAC is not a digital signature!
        /// 2. Use longer keys / hashes(e.g.HS512) for increased security
        /// 3. Keys longer than the hash size don’t provide additional security
        /// 4. Tokens where issuer and ultimate consumer is the same party
        /// </summary>
        /// <example>
        /// In the example, the value for jwt (the token) is:
        /// eyAiYWxnIjogIkhTMjU2IiwgInR5cCI6ICJKV1QiIH0.eyAic3ViIjogInRlc3QiLCAibmFtZSI6ICJNaWNoYWVsIEFyZ2VudGluaSIgfQ.Gb7z2CJSrWdBhZ7lGZK9qdcac_ktuOuqiCBJo3sG_lA
        /// <code>
        /// string base64Secret = Encryption.Base64StringEncode("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@");
        /// string payload = "{ \"sub\": \"test\", \"name\": \"Michael Argentini\" }";
        /// string jwt = Encryption.GenerateJWT(payload, base64Secret, "HS256");
        /// </code>
        /// </example>
        /// <param name="payload">Primary data block to pack into the token, using JSON syntax.</param>
        /// <param name="base64Secret">A 64-byte secret which you have already Base 64 encoded.</param>
        /// <param name="hashingAlgorithm">HS256, HS384, or HS512.</param>
        /// <returns>A Base 64 Url-encoded JWT token</returns>
        public static string GenerateJWT(string payload, string base64Secret, string hashingAlgorithm = "HS256")
        {
            string jwt = "";
            string header = "{ \"alg\": \"" + hashingAlgorithm.ToUpper() + "\", \"typ\": \"JWT\" }";
            byte[] secretBytes;

            if (string.IsNullOrWhiteSpace(base64Secret) == false)
            {
                string secret = Base64StringDecode(base64Secret);

                if (secret.Length == 64)
                {
                    secretBytes = secret.ToByteArray();

                    string headerAndPayload = Base64UrlEncode(header) + "." + Base64UrlEncode(payload);
                    byte[] hashValue = null;

                    if (hashingAlgorithm.ToUpper() == "HS256")
                    {
                        using (HMACSHA256 hmac = new HMACSHA256(secretBytes))
                        {
                            hashValue = hmac.ComputeHash(headerAndPayload.ToByteArray());
                        }
                    }

                    else if (hashingAlgorithm.ToUpper() == "HS384")
                    {
                        using (HMACSHA384 hmac = new HMACSHA384(secretBytes))
                        {
                            hashValue = hmac.ComputeHash(headerAndPayload.ToByteArray());
                        }
                    }

                    else if (hashingAlgorithm.ToUpper() == "HS512")
                    {
                        using (HMACSHA512 hmac = new HMACSHA512(secretBytes))
                        {
                            hashValue = hmac.ComputeHash(headerAndPayload.ToByteArray());
                        }
                    }

                    if (hashValue != null)
                    {
                        jwt = headerAndPayload + "." + Base64UrlEncode(hashValue);
                    }
                }
            }

            return jwt;
        }

        /// <summary>
        /// Verify a javascript web token (JWT) which uses hash-based message authentication code (HMAC).
        /// Hashing algorithm is determined automatically from the header of the token.
        /// 
        /// Use cases:
        /// 1. Stateless sessions stored in browser cookies
        /// 2. Email verification codes
        /// 3. Session IDs with the ability to differentiate between expired and invalid IDs
        /// 
        /// Notes:
        /// 1. The HMAC is not a digital signature!
        /// 2. Use longer keys / hashes(e.g.HS512) for increased security
        /// 3. Keys longer than the hash size don’t provide additional security
        /// 4. Tokens where issuer and ultimate consumer is the same party
        /// </summary>
        /// <example>
        /// <code>
        /// string base64Secret = Encryption.Base64StringEncode("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@");
        /// string payload = "{ \"sub\": \"test\", \"name\": \"Michael Argentini\" }";
        /// string jwt = Encryption.GenerateJWT(payload, base64Secret, "HS256");
        /// if (Encryption.VerifyJWT(jwt, base64Secret))
        /// {
        ///     // token has a valid signature...
        /// }
        /// </code>
        /// </example>
        /// <param name="jwt">Javascript Web Token</param>
        /// <param name="base64Secret">A 64-byte secret which you have already Base 64 encoded</param>
        /// <returns>true if the signature is valid, false if not</returns>
        public static bool VerifyJWT(string jwt, string base64Secret)
        {
            bool result = false;

            if (string.IsNullOrWhiteSpace(base64Secret) == false)
            {
                if (string.IsNullOrWhiteSpace(jwt) == false)
                {
                    string[] portions = jwt.Split('.');

                    if (portions.Length > 2)
                    {
                        string header = portions[0];
                        string headerDecoded = Base64UrlDecodeToString(header).ToUpper().Replace(" ", "");
                        string payload = portions[1];
                        string signature = portions[2];
                        string hashAlgorithm = "HS256";

                        if (headerDecoded.Contains("\"ALG\":\"HS384\""))
                        {
                            hashAlgorithm = "HS384";
                        }

                        else if (headerDecoded.Contains("\"ALG\":\"HS512\""))
                        {
                            hashAlgorithm = "HS512";
                        }

                        if (GenerateJWT(Base64UrlDecodeToString(payload), base64Secret, hashAlgorithm) == jwt)
                        {
                            result = true;
                        }
                    }
                }
            }

            return result;
        }

        #endregion
    }
}
