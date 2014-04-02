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
using System.Security.Cryptography;

namespace BlockEncrypter
{
    public static class BlockEncrypter
    {
        private readonly static GZipCompression Compressor = new GZipCompression();

        public static string EncryptStringBlock(string textToEncrypt, byte [] password)
        {       
            if (string.IsNullOrEmpty(textToEncrypt))
            {
                throw new ArgumentNullException("textToEncrypt");
            }

            if (password == null)
            {
                throw new ArgumentNullException("password");
            }

            return Convert.ToBase64String(EncryptByteBlock(ByteHelpers.GetBytes(textToEncrypt), password));                            
        }

        public static byte[] EncryptByteBlock(byte[]  dataToEncrypt, byte[] password)
        {
            if (dataToEncrypt == null)
            {
                throw new ArgumentNullException("dataToEncrypt");
            }

            if (password == null)
            {
                throw new ArgumentNullException("password");
            }

            var aes = new Aes();

            using (var rngCsp = new RNGCryptoServiceProvider())
            {
                var salt = new byte[32];
                rngCsp.GetBytes(salt);

                var compressed = Compressor.Compress(dataToEncrypt);

                var encrpytedMessage = aes.Encrypt(compressed, password, salt, 70000);
                var fullMessage = ByteHelpers.Combine(salt, encrpytedMessage);

                return fullMessage;
            }
        }

        public static string DecryptStringBlock(string textToDecrypt, byte [] password)
        {
            if (string.IsNullOrEmpty(textToDecrypt))
            {
                throw new ArgumentNullException("textToDecrypt");
            }

            if (password == null)
            {
                throw new ArgumentNullException("password");
            }

            return ByteHelpers.GetString(DecryptByteBlock(Convert.FromBase64String(textToDecrypt), password));           
        }

        public static byte[] DecryptByteBlock(byte[] dataToDecrypt, byte[] password)
        {
            if (dataToDecrypt == null)
            {
                throw new ArgumentNullException("dataToDecrypt");
            }

            if (password == null)
            {
                throw new ArgumentNullException("password");
            }

            var aes = new Aes();          

            var salt = ByteHelpers.CreateSpecialByteArray(32);
            var message = ByteHelpers.CreateSpecialByteArray(dataToDecrypt.Length - 32);
            Buffer.BlockCopy(dataToDecrypt, 0, salt, 0, 32);
            Buffer.BlockCopy(dataToDecrypt, 32, message, 0, dataToDecrypt.Length - 32);

            var deCompressed = Compressor.Decompress(aes.Decrypt(message, password, salt, 70000));
           
            return deCompressed;
        }
    }
}
