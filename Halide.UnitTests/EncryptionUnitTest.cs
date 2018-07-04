﻿using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;

using Fynydd.Halide;
using Fynydd.Halide.Constants;

namespace Fynydd.Halide.UnitTests
{
    /// <summary>
    /// Summary description for IdentificationUnitTests
    /// </summary>
    [TestClass]
    public class EncryptionUnitTests
    {
        string stringData = "Now is the time for all good men to come to the aid of their party.";
        DateTime dateTimeData = new DateTime(2018, 06, 01, 20, 09, 10);
        int intData = int.MaxValue;
        long longData = long.MaxValue;
        ulong ulongData = ulong.MaxValue;
        double doubleData = double.MaxValue;

        byte[] baseKey = Encryption.CreateBaseKey("151, 4, 109, 42, 135, 99, 67, 82, 242, 233, 16, 200, 9, 83, 196, 178, 56, 74, 90, 36, 206, 129, 81, 229, 67, 82, 242, 233, 16, 200, 9, 83");
        byte[] initVector = Encryption.CreateInitVector("180, 54, 206, 210, 10, 101, 6, 87, 13, 3, 241, 189, 176, 175, 109, 217");

        string Secret64bit = Encryption.Base64StringEncode("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@");
        string Secret128bit = Encryption.Base64StringEncode("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@");

        [TestMethod]
        public void Encrypt()
        {
            string encrypted = stringData.Encrypt<string>(baseKey, initVector);
            Assert.AreEqual("nnxyz91rqBjVkHr39sXhuE_xq92SuMLmesW0frDM6nLNclhtuvPvmSoudINJ5INwZymg6M9eYYPNn22P1Iis3TiDMpnPGw9QTSTVXdomJ3g", encrypted);

            string decryptedString = encrypted.Decrypt<string>(baseKey, initVector);
            Assert.AreEqual(stringData, decryptedString);


            encrypted = dateTimeData.Encrypt(baseKey, initVector);
            Assert.AreEqual("IpBUnBFx5fMKeM5sSyaS1xaPwWC4wEibRSgQOjK930Y", encrypted);

            DateTime decryptedDateTime = encrypted.Decrypt<DateTime>(baseKey, initVector);
            Assert.AreEqual(dateTimeData, decryptedDateTime);


            encrypted = intData.Encrypt(baseKey, initVector);
            Assert.AreEqual("X23XSLQDr1o8oq8xL-N39Q", encrypted);

            int decryptedInt = encrypted.Decrypt<int>(baseKey, initVector);
            Assert.AreEqual(intData, decryptedInt);


            encrypted = longData.Encrypt(baseKey, initVector);
            Assert.AreEqual("Mhrerm4zQYoNhTmUa6OnnQ", encrypted);

            long decryptedLong = encrypted.Decrypt<long>(baseKey, initVector);
            Assert.AreEqual(longData, decryptedLong);


            encrypted = ulongData.Encrypt(baseKey, initVector);
            Assert.AreEqual("d7gg-s0DzZbLNPtoO49BZQ", encrypted);

            ulong decryptedULong = encrypted.Decrypt<ulong>(baseKey, initVector);
            Assert.AreEqual(ulongData, decryptedULong);


            encrypted = doubleData.Encrypt(baseKey, initVector);
            Assert.AreEqual("lvZd7REGsrCrMuHntjnptA", encrypted);

            double decryptedDouble = encrypted.Decrypt<double>(baseKey, initVector);
            Assert.AreEqual(doubleData, decryptedDouble);
        }

        [TestMethod]
        public void Base64()
        {
            string encoded = Encryption.Base64StringEncode(stringData);

            Assert.AreEqual("Tm93IGlzIHRoZSB0aW1lIGZvciBhbGwgZ29vZCBtZW4gdG8gY29tZSB0byB0aGUgYWlkIG9mIHRoZWlyIHBhcnR5Lg==", encoded, "Base64 string encode failure");
            Assert.AreEqual(stringData, Encryption.Base64StringDecode(encoded), "Base64 string decode failure");

            encoded = Encryption.Base64UrlEncode(stringData);

            Assert.AreEqual("Tm93IGlzIHRoZSB0aW1lIGZvciBhbGwgZ29vZCBtZW4gdG8gY29tZSB0byB0aGUgYWlkIG9mIHRoZWlyIHBhcnR5Lg", encoded, "Base64Url encode failure");
            Assert.AreEqual(stringData, Encryption.Base64UrlDecodeToString(encoded), "Base64Url decode failure");
        }

        [TestMethod]
        public void JWT()
        {
            string payload = "{ \"sub\": \"test\", \"name\": \"Michael Argentini\" }";
            string jwt = "";

            // HS256
            jwt = Encryption.GenerateJWT(payload, Secret64bit);
            Assert.AreEqual("eyAiYWxnIjogIkhTMjU2IiwgInR5cCI6ICJKV1QiIH0.eyAic3ViIjogInRlc3QiLCAibmFtZSI6ICJNaWNoYWVsIEFyZ2VudGluaSIgfQ.Gb7z2CJSrWdBhZ7lGZK9qdcac_ktuOuqiCBJo3sG_lA", jwt, "HS256 failure");

            // Verify HS256
            Assert.AreEqual(true, Encryption.VerifyJWT(jwt, Secret64bit), "HS256 signature verification failure");

            // HS384
            jwt = Encryption.GenerateJWT(payload, Secret128bit, "HS384");
            Assert.AreEqual("eyAiYWxnIjogIkhTMzg0IiwgInR5cCI6ICJKV1QiIH0.eyAic3ViIjogInRlc3QiLCAibmFtZSI6ICJNaWNoYWVsIEFyZ2VudGluaSIgfQ._XH-P-UL3uLJBDV0x2K97ulz8TRUEFy8EwRyA8oCUbdJk7gVASC7WywGtqZCdw2C", jwt, "HS384 failure");

            // Verify HS384
            Assert.AreEqual(true, Encryption.VerifyJWT(jwt, Secret128bit), "HS384 signature verification failure");

            // HS512
            jwt = Encryption.GenerateJWT(payload, Secret128bit, "HS512");
            Assert.AreEqual("eyAiYWxnIjogIkhTNTEyIiwgInR5cCI6ICJKV1QiIH0.eyAic3ViIjogInRlc3QiLCAibmFtZSI6ICJNaWNoYWVsIEFyZ2VudGluaSIgfQ.NZus5Z-v0bhZUu-FaNZEQYSa4h3wC3SmmDT7lL9om1q3-YNr3Pk_sR2m1vP5N-awhByrm6W-8O3r-Qpd5vQPUw", jwt, "HS512 failure");

            // Verify HS512
            Assert.AreEqual(true, Encryption.VerifyJWT(jwt, Secret128bit), "HS512 signature verification failure");
        }
    }
}
