using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;

using Fynydd.Halide;
using Fynydd.Halide.Constants;

namespace Fynydd.Halide.UnitTests
{
    /// <summary>
    /// Summary description for IdentificationUnitTests
    /// </summary>
    [TestClass]
    public class SecurityUnitTests
    {
        string stringData = "Now is the time for all good men to come to the aid of their party.";
        DateTime dateTimeData = new DateTime(2018, 06, 01, 20, 09, 10);
        int intData = int.MaxValue;
        long longData = long.MaxValue;
        ulong ulongData = ulong.MaxValue;
        double doubleData = double.MaxValue;

        byte[] baseKey = Security.CreateBaseKey("151, 4, 109, 42, 135, 99, 67, 82, 242, 233, 16, 200, 9, 83, 196, 178, 56, 74, 90, 36, 206, 129, 81, 229, 67, 82, 242, 233, 16, 200, 9, 83");
        byte[] initVector = Security.CreateInitVector("180, 54, 206, 210, 10, 101, 6, 87, 13, 3, 241, 189, 176, 175, 109, 217");

        [TestMethod]
        public void Encrypt()
        {
            string encrypted = stringData.Encrypt<string>(baseKey, initVector);
            Assert.AreEqual("nnxyz91rqBjVkHr39sXhuE~xq92SuMLmesW0frDM6nLNclhtuvPvmSoudINJ5INwZymg6M9eYYPNn22P1Iis3TiDMpnPGw9QTSTVXdomJ3g", encrypted);

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
    }
}
