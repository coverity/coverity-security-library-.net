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
using System.Text.RegularExpressions;

namespace Coverity.Security
{
    /**
     * Filter is a small set of methods for filtering tainted data that cannot be escaped. These
     * methods may change the semantics of the data if it cannot be determined to be safe, however
     * great care has been taken in the design to ensure that they behave in a way that "makes
     * sense" intuitively
     * <p>
     * These methods fit into the nested escaper framework that the Escape class supports, and
     * should be used as the innermost "escaper" to ensure correctness, e.g.
     * &lt;iframe src="@Cov.AsURL(param.web)"> &lt;/iframe>
     * Ensure that that param.web cannot escape the src attribute, but also ensures that it cannot
     * be a URL that causes XSS.
     * <p>
     * While Coverity's static analysis product references these escaping routines
     * as exemplars and understands their behavior, there is no dependency on
     * Coverity products and these routines are completely standalone. Feel free to
     * use them! Just make sure you use them correctly.
     */
    public class Filter
    {
        private static readonly Regex OctalRegex = new Regex("^(0+)([0-7]*)$", RegexOptions.Compiled);
        private static readonly Regex NumberRegex = new Regex("^[-+]?((\\.[0-9]+)|([0-9]+\\.?[0-9]*))$", RegexOptions.Compiled);
        private static readonly Regex HexRegex = new Regex("^0x[0-9a-fA-F]+$", RegexOptions.Compiled);
        private static readonly Regex CssHexColorRegex = new Regex("^#[0-9a-fA-F]{3}([0-9a-fA-F]{3})?$", RegexOptions.Compiled);
        private static readonly Regex CssNamedColorRegex = new Regex("^[a-zA-Z]{1,20}$", RegexOptions.Compiled);
        private static readonly Regex UrlRegex = new Regex("^(/|\\\\\\\\|https?:|ftp:|mailto:).*$", (RegexOptions.Compiled | RegexOptions.IgnoreCase));
        private static readonly Regex SchemeRegex = new Regex("^(javascript|vbscript|data|about)$", RegexOptions.Compiled);


        /// <summary>
        /// AsNumber is useful for outputting dynamic data as a number in a JavaScript
        /// context, e.g.
        /// &lt;script>
        /// var userNum = @Cov.AsNumber(USER_DATA)
        /// &lt;/script>
        /// 
        /// It allows decimal and hex numbers (e.g. 0x41) through unmodified, unless they have
        /// leading 0s and may be interpreted as octal numbers, in which case the leading 0s
        /// are stripped.
        /// </summary>
        /// <param name="number">The potential number to filter</param>
        /// <returns>A sanitised number or 0 if there is no conversion</returns>
        public static string AsNumber(string number)
        {
            return AsNumber(number, "0");
        }

        /// <summary>
        /// Identical to AsNumber, except you can provide your own default value
        /// </summary>
        /// <param name="number">The potential number to filter</param>
        /// <param name="defaultNumber">A default string to return if the number argument is not a Number </param>
        /// <returns>A sanitised number or defaultNumber if there is no conversion</returns>
        public static string AsNumber(string number, string defaultNumber)
        {
            if (number == null)
                return null;
            var trimNumber = number.Trim();

            //Do not allow octal to keep in line with java parse* functions
            var octal = OctalRegex.Match(trimNumber);
            if (octal.Success)
                return octal.Groups[2].Value;

            if (NumberRegex.IsMatch(trimNumber))
                return trimNumber;
            if (HexRegex.IsMatch(trimNumber))
                return trimNumber;
            return defaultNumber;
        }

        /// <summary>
        /// asCssColor is useful when you need to insert dynamic data into a CSS color context, e.g.
        /// &lt;style>
        /// .userprofile {
        /// background-color: @Cov:AsCssColor(USER_DATA)
        /// }
        /// &lt;/style> 
        /// 
        /// It should be used for colors since it is not possible to specify colors inside
        /// CSS strings
        /// 
        /// This method validates that the parameter is a valid color, or returns the string "invalid".
        /// The string invalid was chosen since it is a token that is not valid in this context, so
        /// this rule will be ignored by the CSS parser, but additional rules will still be parsed
        /// properly.
        /// 
        /// The effect of this is that it will be as if the CSS rule was never specified.
        /// 
        /// We have chosen to provide an illegal token instead of a default such as "transparent"
        /// or "inherit" since the defaults are different for different color contexts, e.g.
        /// background-color defaults to transparent, while color defaults to inherit. This will
        /// essentially preserve those semantics.
        /// </summary>
        /// <param name="color">The potential css color to filter</param>
        /// <returns>The color specified or the string "invalid"</returns>
        public static string AsCssColor(string color)
        {
            return AsCssColor(color, "invalid");
        }

        /// <summary>
        /// Identical to AsCssColor, except you can provide your own default value
        /// </summary>
        /// <param name="color">The potential css color to filter</param>
        /// <param name="defaultColor">A default string to return if the color argument is not a potentially valid CSS color </param>
        /// <returns>A sanitised color or defaultColor if there is no conversion</returns>
        public static string AsCssColor(string color, string defaultColor)
        {
            if (color == null)
                return null;
            if (CssHexColorRegex.Match(color).Success)
                return color;
            if (CssNamedColorRegex.Match(color).Success)
                return color;

            return defaultColor;
        }

        /// <summary>
        ///  URL filtering to ensure that the URL is a safe non-relative URL or transforms it to a safe relative URL.
        ///  <p>
        ///  Specifically, if the URL starts with one of the following it will be unaltered:
        ///  <ul>
        ///  <li>/ to allow URLs of the form /path/from/root.jsp</li>
        ///  <li>\\ to allow UNC paths of the form \\server\some\file.xls</li>
        ///  <li>http:</li>
        ///  <li>https:</li>
        ///  <li>ftp:</li>
        ///  <li>mailto:</li>
        ///  </ul>
        ///  
        ///  Our research shows that these URLs will not cause an XSS defect by being accessed, and is intended to
        ///  be used in cases where having a user point a URL at their own content is intended.
        ///  
        ///  Other URLs are made safe by turning them into URLs relative to the current document, e.g.
        ///  file.html becomes ./file.html
        ///  ?query becomse ./?query
        ///  #hash becomes ./#hash
        ///  javascript:alert(1) becomes ./javascript:alert(1)
        ///  
        ///  
        ///  This methods will not prevent XSS if it is used to show active content such as:
        ///  <ul>
        ///  <li>JavaScript src</li>
        ///  <li>CSS src</li>
        ///  <li>CSS \@import</li>
        ///  <li>Embeded Flash files</li>
        ///  <li>Java Applets</li>
        ///  <li>Embeded PDFs</li>
        ///  <li>Pretty much any other plugin</li>
        ///  <li>etc</li>
        ///  </ul>
        /// </summary>
        /// <param name="url">The potentially tainted URL to be Filtered</param>
        /// <returns>A safe version of the URL or <code>null</code> if <code>input</code> is null</returns>
        public static string AsUrl(string url)
        {
            if (url == null)
                return null;

            if (url.Length == 0)
                return url;

            if (UrlRegex.Match(url).Success)
                return url;

            //Our fallback is to transform this to a relative URL
            return "./" + url;
        }

        /// <summary>
        /// This function should be semantically identical to the above function with the exception
        /// of using a scheme blacklist instead of a scheme whitelist.
        /// 
        /// It disallows javascript, vbscript, data and about URLs and turns these URLs into
        /// relative URLs the same way the above does.
        /// 
        /// It allows all other schemes as long as the scheme name is directly followed by a colon (:)
        /// 
        /// The complexity of this function is necessary due to the parsing that browsers do when
        /// they encounter URLs, e.g. stripping new lines and NUL bytes. 
        /// </summary>
        /// <param name="url">The potentially tainted URL to be filtered</param>
        /// <returns>A safe version of the URL or <code>null</code> if <code>input</code> is null</returns>
        public static string AsFlexibleUrl(string url)
        {
            if (url == null)
                return null;

            //Assumption: / is not an escape character in any context
            //Note: this allows scheme-relative URLs e.g. //google.com/
            if (url.StartsWith("/"))
            {
                return url;
            }

            var i = 0;
            //Allow UNC paths
            if (url.StartsWith("\\\\"))
            {
                return url;
            }

            //Find a potential scheme name
            for (; i < url.Length; i++)
            {
                var c = url[i];
                //These are valid scheme characters from RFC 3986
                //Assumption: These are not escape characters in any context
                if (!(
                    (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                    (c >= '0' && c <= '9') || (c == '.') || (c == '+')
                     || (c == '-')
                    ))
                {
                    break;
                }
            }


            //i == first non-scheme value
            if (i == url.Length)
            {
                //The whole string is consists only of a-z A-Z 0-9 .+-
                return url;
            }

            if (url[i] == ':' && ValidateScheme(url.Substring(0, i).ToLower()))
            {
                //We've extracted what we think is a scheme, confirmed it definitely is a scheme
                //then confirmed the scheme is safe, return the original string
                return url;
            }

            //Our fallback is to transform this to a relative URL
            return "./" + url;
        }

        private static bool ValidateScheme(string scheme)
        {
            return !SchemeRegex.Match(scheme).Success;
        }
    }
}
