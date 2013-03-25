/**
 *   Copyright (c) 2013, Coverity, Inc. 
 *   All rights reserved.
 *
 *   Redistribution and use in source and binary forms, with or without modification, 
 *   are permitted provided that the following conditions are met:
 *   - Redistributions of source code must retain the above copyright notice, this 
 *   list of conditions and the following disclaimer.
 *   - Redistributions in binary form must reproduce the above copyright notice, this
 *   list of conditions and the following disclaimer in the documentation and/or other
 *   materials provided with the distribution.
 *   - Neither the name of Coverity, Inc. nor the names of its contributors may be used
 *   to endorse or promote products derived from this software without specific prior 
 *   written permission from Coverity, Inc.
 *   
 *   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
 *   EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 *   OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND INFRINGEMENT ARE DISCLAIMED.
 *   IN NO EVENT SHALL THE COPYRIGHT HOLDER OR  CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 *   INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 *   NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR 
 *   PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, 
 *   WHETHER IN CONTRACT,  STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) 
 *   ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY 
 *   OF SUCH DAMAGE.
 */
using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Coverity.Security.Tests
{
    [TestClass]
    public class FilterTest
    {
        string[] colorTrueTests = {
                //Named Color
                "AliceBlue",
                "white",
                "PaleVioletRed",

                //Hex Color
                "#fff",
                "#FFF",
                "#0fF056"
        };

        string[] colorFalseTests = {
                //named Color
                "#1",
                "this is not a name",
                "efe fef",
                "foo()<>{}",
                "\09 thisIsPossibleButNotConsidered",

                //Hex Color
                "#1",
                "12345",
                "#12",
                "#1223",
                "#12233",
                "#122g34",
                "\0#123",
                "\f#123",
                "\n#123",
                ""
        };

        [TestMethod]
        public void TestAsCssColorDefault_Invalid()
        {
            string defaultColour = "blue";
            foreach (var color in colorFalseTests)
            {
                string filtered = Filter.AsCssColor(color, defaultColour);
                Assert.IsTrue(filtered == defaultColour);

            }
        }

        [TestMethod]
        public void TestAsCssColor_Invalid()
        {
            string invalid = "invalid";
            foreach (var color in colorFalseTests)
            {
                string filtered = Filter.AsCssColor(color);
                Assert.IsTrue(filtered == invalid);

            }
        }

        [TestMethod]
        public void TestAsCssColorDefault_Valid()
        {
            string defaultColour = "blue";
            foreach (var color in colorTrueTests)
            {
                string filtered = Filter.AsCssColor(color, defaultColour);
                Assert.IsTrue(filtered == color);

            }
        }

        [TestMethod]
        public void TestAsCssColor_Valid()
        {
            foreach (var color in colorTrueTests)
            {
                string filtered = Filter.AsCssColor(color);
                Assert.IsTrue(filtered == color);
            }
        }


        string[] numberFalseTests = {
            //asNumber
            ".",
            "+65266+",
            "-+1.266",
            "65.65.",

            //asHex
            "0xefefefg",
            "0xag",
            "abc",
            "\\x15"
        };
        string[] numberTrueTests = {
            //asNumber
            "+1.425",
            "65.",
            "-64.32",
            "42",
            "-.04",
            "0.2323232",

            //asHex
            "0xefefef",
            "0x0ff",
            "0x234345"
        };

        [TestMethod]
        public void TestAsNumber_Valid()
        {
            foreach (var number in numberTrueTests)
            {
                string filtered = Filter.AsNumber(number);
                Assert.IsTrue(filtered == number);
            }
        }

        [TestMethod]
        public void TestAsNumberDefault_Valid()
        {
            string defaultNumber = "1";
            foreach (var number in numberTrueTests)
            {
                string filtered = Filter.AsNumber(number, defaultNumber);
                Assert.IsTrue(filtered == number);
            }
        }

        [TestMethod]
        public void TestAsNumberDefault_Invalid()
        {
            string defaultNumber = "1";
            foreach (var number in numberFalseTests)
            {
                string filtered = Filter.AsNumber(number, defaultNumber);
                Assert.IsTrue(filtered == defaultNumber);
            }
        }

        [TestMethod]
        public void TestAsNumber_Invalid()
        {
            string defaultNumber = "0";
            foreach (var number in numberFalseTests)
            {
                string filtered = Filter.AsNumber(number);
                Assert.IsTrue(filtered == defaultNumber);
            }
        }


        [TestMethod]
        public void TestAsNumberOctal_Valid()
        {
            string octal = "0777";
            string filtered = Filter.AsNumber(octal);
            Assert.IsTrue(Convert.ToInt32(filtered) == Convert.ToInt32(octal));
        }

        string[] urlFalseTests = {
            "javascript:test('http:')",
            "jaVascRipt:test",
            "\\UNC-PATH\\",
            "data:test",
            "about:blank",
            "javascript\n:",
            "vbscript:IE",
            "data&#58boo",
            "dat\0a:boo"
        };

        string[] urlTrueTests = {
            "\\\\UNC-PATH\\",
            "http://host/url",
            "hTTp://host/url",
            "//coverity.com/lo",
            "/base/path",
            "https://coverity.com",
            "mailto:srl@coverity.com",
            "maiLto:srl@coverity.com",
            "ftp://coverity.com/elite.warez.tgz",
            ""
        };

        string[] urlFlexibleTrueTests = {
                "tel:5556667777",
                "gopher:something something",
                "test.html"
        };

        [TestMethod]
        public void TestFlexibleUrl_Valid()
        {
            foreach (var url in urlTrueTests)
            {
                string filtered = Filter.AsFlexibleURL(url);
                Assert.IsTrue(filtered == url);
            }
            foreach (var url in urlFlexibleTrueTests)
            {
                string filtered = Filter.AsFlexibleURL(url);
                Assert.IsTrue(filtered == url);
            }
        }

        [TestMethod]
        public void TestFlexibleUrl_Invalid()
        {
            foreach (var url in urlFalseTests)
            {
                string filtered = Filter.AsFlexibleURL(url);
                Assert.IsTrue(filtered == "./" + url);
            }
        }

        [TestMethod]
        public void TestUrl_Invalid()
        {
            foreach (var url in urlFalseTests)
            {
                string filtered = Filter.AsURL(url);
                Assert.IsTrue(filtered == "./" + url);
            }
        }

        [TestMethod]
        public void TestUrl_Valid()
        {
            foreach (var url in urlTrueTests)
            {
                string filtered = Filter.AsURL(url);
                Assert.IsTrue(filtered == url);
            }
        }

    }
}
