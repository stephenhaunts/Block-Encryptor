/**
* Block Encrypter : Example of encrypting a block of data with AES using a PBKDF and protecting with a HMAC.
* 
* Copyright (C) 2014 Stephen Haunts
* http://www.stephenhaunts.com
* 
* This file is part of Block Encrypter.
* 
* Block Encrypter is free software: you can redistribute it and/or modify it under the terms of the
* GNU General Public License as published by the Free Software Foundation, either version 2 of the
* License, or (at your option) any later version.
* 
* Block Encrypter is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
* without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
* 
* See the GNU General Public License for more details <http://www.gnu.org/licenses/>.
* 
* Authors: Stephen Haunts
*/

using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Text;

namespace BlockEncrypter.Tests.Unit
{
    [TestClass]
    public class BlockEncrypterTests
    {
        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException), "textToEncrypt")]
        public void EncryptStringBlockThrowsArgumentNullExceptionIfTextToEncryptIsNull()
        {
            BlockEncrypter.EncryptStringBlock(null, null);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException), "password")]
        public void EncryptStringBlockThrowsArgumentNullExceptionIfPasswordIsNull()
        {
            BlockEncrypter.EncryptStringBlock("blah blah blah blah blah blah", null);
        }

        [TestMethod]        
        public void EncryptStringBlockEncryptsTextWithAPasswordAndResultIsNotNull()
        {
            string encrypted = BlockEncrypter.EncryptStringBlock("This is my message to encrypt.", Encoding.ASCII.GetBytes("Pa55w0rd"));
            Assert.IsNotNull(encrypted);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException), "dataToEncrypt")]
        public void EncryptByteBlockThrowsArgumentNullExceptionIfTextToEncryptIsNull()
        {
            BlockEncrypter.EncryptByteBlock(null, null);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException), "password")]
        public void EncryptByteBlockThrowsArgumentNullExceptionIfPasswordIsNull()
        {            
            byte[] testBytes = ByteHelpers.GetBytes("blah blah blah blah blah blah");
            BlockEncrypter.EncryptByteBlock(testBytes, null);
        }

        [TestMethod]
        public void EncryptByteBlockEncryptsTextWithAPasswordAndResultIsNotNull()
        {
            byte[] testBytes = ByteHelpers.GetBytes("This is my message to encrypt.");
            byte[] encrypted = BlockEncrypter.EncryptByteBlock(testBytes, Encoding.ASCII.GetBytes("Pa55w0rd"));

            Assert.IsNotNull(encrypted);
        }
     
        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException), "textToEncrypt")]
        public void DecryptStringBlockThrowsArgumentNullExceptionIfTextToDecryptIsNull()
        {
            BlockEncrypter.DecryptStringBlock(null, null);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException), "password")]
        public void DecryptStringBlockThrowsArgumentNullExceptionIfPasswordIsNull()
        {
            BlockEncrypter.DecryptStringBlock("blah blah blah blah blah blah", null);
        }

        [TestMethod]
        public void DecryptStringBlockkDecryptsBlockBackToOriginalPlainText()
        {
            const string originalMessage = "This is my message to encrypt.";

            string encrypted = BlockEncrypter.EncryptStringBlock(originalMessage, Encoding.ASCII.GetBytes("Pa55w0rd"));
            string decrypted = BlockEncrypter.DecryptStringBlock(encrypted, Encoding.ASCII.GetBytes("Pa55w0rd"));

            Assert.AreEqual(originalMessage, decrypted);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException), "dataToEncrypt")]
        public void DecryptByteBlockThrowsArgumentNullExceptionIfTextToDecryptIsNull()
        {
            BlockEncrypter.DecryptByteBlock(null, null);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException), "password")]
        public void DecryptByteBlockThrowsArgumentNullExceptionIfPasswordIsNull()
        {
            byte[] testBytes = ByteHelpers.GetBytes("blah blah blah blah blah blah");
            BlockEncrypter.DecryptByteBlock(testBytes, null);
        }

        [TestMethod]
        public void DecryptByteBlockDecryptsBlockBackToOriginalPlainText()
        {
            const string originalMessage = "This is my message to encrypt.";
            byte[] testBytes = ByteHelpers.GetBytes(originalMessage);

            byte[] encrypted = BlockEncrypter.EncryptByteBlock(testBytes, Encoding.ASCII.GetBytes("Pa55w0rd"));
            byte[] decrypted = BlockEncrypter.DecryptByteBlock(encrypted, Encoding.ASCII.GetBytes("Pa55w0rd"));
            
            Assert.IsTrue(ByteHelpers.ByteArrayCompare(testBytes, decrypted));
        }
    }
}
