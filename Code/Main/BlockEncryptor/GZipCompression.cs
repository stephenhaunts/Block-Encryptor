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
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;

namespace BlockEncrypter
{
    public class GZipCompression
    {        
        public byte[] Compress(byte[] input)
        {
            if (input == null)
            {
                throw new ArgumentNullException("input");
            }

            byte[] output;

            using (var ms = new MemoryStream())
            {
                var gs = new GZipStream(ms, CompressionMode.Compress);
                gs.Write(input, 0, input.Length);
                gs.Close();

                output = ms.ToArray();

                ms.Close();
            }

            return output;
        }
        
        public byte[] Decompress(byte[] input)
        {
            if (input == null)
            {
                throw new ArgumentNullException("input");
            }

            var output = new List<byte>();

            using (var ms = new MemoryStream(input))
            {
                var gs = new GZipStream(ms, CompressionMode.Decompress);
                var readByte = gs.ReadByte();

                while (readByte != -1)
                {
                    output.Add((byte)readByte);
                    readByte = gs.ReadByte();
                }

                gs.Close();
                ms.Close();
            }

            return output.ToArray();
        }
    }
}
