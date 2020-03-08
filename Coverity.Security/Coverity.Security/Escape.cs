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
using System.Text;

namespace Coverity.Security
{
    public static class Escape
    {
        /// <summary>
        ///  HTML entity escaping for text content and attributes.
        ///  <p>
        ///  HTML entity escaping that is appropriate for the most common HTML contexts:
        ///  PCDATA and "normal" attributes (non-URI, non-event, and non-CSS attributes). <br />
        ///  Note that we do not recommend using non-quoted HTML attributes since
        ///  the security obligations vary more between web browser. We recommend
        ///  to always quote (single or double quotes) HTML attributes.<br />
        ///  This method is generic to HTML entity escaping, and therefore escapes more
        ///  characters than usually necessary -- mostly to handle non-quoted attribute values.
        ///  If this method is somehow too slow, such as you output megabytes of text with spaces,
        ///  please use the <see cref="HtmlText"/> method which only escape HTML text specific
        ///  characters.
        /// 
        ///  <p>
        ///  The following characters are escaped:
        ///  <ul>
        ///  <li>
        ///  HTML characters: <code>' (U+0022)</code>, <code>" (U+0027)</code>, 
        ///                   <code>\ (U+005C)</code>, <code>/ (U+002F)</code>, 
        ///                   <code>&lt; (U+003C)</code>, <code>&gt; (U+003E)</code>, 
        ///                   <code>&amp; (U+0026)</code>
        ///  </li>
        ///  <li>
        ///  Control characters: <code>\t (U+0009)</code>, <code>\n (U+000A)</code>, 
        ///                      <code>\f (U+000C)</code>, <code>\r (U+000D)</code>, 
        ///                      <code>SPACE (U+0020)</code>
        ///  </li>
        ///  <li>
        ///  Unicode newlines: <code>LS (U+2028)</code>, <code>PS (U+2029)</code>
        ///  </li>
        ///  </ul>
        /// </summary>
        /// <param name="input">Input the string to be escaped</param>
        /// <returns>the HTML escaped string or <code>null</code> if <code>input</code> is null</returns>
        public static string Html(string input)
        {
            if (input == null)
                return null;

            var output = AllocateStringBuilder(input.Length);
            foreach (var c in input)
            {
                switch (c)
                {
                    // Control chars
                    case '\t':
                        output.Append("&#x09;");
                        break;
                    case '\n':
                        output.Append("&#x0A;");
                        break;
                    case '\f':
                        output.Append("&#x0C;");
                        break;
                    case '\r':
                        output.Append("&#x0D;");
                        break;
                    // Chars that have a meaning for HTML
                    case '\'':
                        output.Append("&#39;");
                        break;
                    case '\\':
                        output.Append("&#x5C;");
                        break;
                    case ' ':
                        output.Append("&#x20;");
                        break;
                    case '/':
                        output.Append("&#x2F;");
                        break;
                    case '"':
                        output.Append("&quot;");
                        break;
                    case '<':
                        output.Append("&lt;");
                        break;
                    case '>':
                        output.Append("&gt;");
                        break;
                    case '&':
                        output.Append("&amp;");
                        break;
                    // Unicode new lines
                    case '\u2028':
                        output.Append("&#x2028;");
                        break;
                    case '\u2029':
                        output.Append("&#x2029;");
                        break;

                    default:
                        output.Append(c);
                        break;
                }
            }
            return output.ToString();

        }

        /// <summary>
        ///  Faster HTML entity escaping for tag content or quoted attributes values only.
        ///  <p>
        ///  HTML entity escaping that is specific to text elements such as the content of
        ///  a typical HTML tag (<code>div</code>, <code>p</code>, etc.).<br />
        ///  This method is not appropriate in all cases, and especially when appending data
        ///  in a non-quoted context (e.g., an HTML attribute value that is not surrounded by
        ///  single or double quotes). Note that we however, highly discourage the use 
        ///  of non-quoted attributes.
        ///  
        ///  <p>
        ///  The following characters are escaped:
        ///  <ul>
        ///  <li>
        ///  HTML characters: <code>' (U+0022)</code>, <code>" (U+0027)</code>,  
        ///                  <code>&lt; (U+003C)</code>, <code>&gt; (U+003E)</code>,  
        ///                   <code>&amp; (U+0026)</code>
        ///  </li>
        ///  </ul>
        /// </summary>
        /// <param name="input">Input the string to be escaped</param>
        /// <returns>The HTML escaped string or <code>null</code> if <code>input</code> is null</returns>
        public static string HtmlText(string input)
        {
            if (input == null)
                return null;

            var output = AllocateStringBuilder(input.Length);
            foreach (var c in input)
            {
                switch (c)
                {
                    case '\'':
                        output.Append("&#39;");
                        break;
                    case '"':
                        output.Append("&quot;");
                        break;
                    case '<':
                        output.Append("&lt;");
                        break;
                    case '>':
                        output.Append("&gt;");
                        break;
                    case '&':
                        output.Append("&amp;");
                        break;
                    default:
                        output.Append(c);
                        break;
                }
            }
            return output.ToString();

        }

        /// <summary>
        ///  URI encoder.
        ///  <p>
        ///  URI encoding for query string values of the URI: 
        ///  <code>/example/?name=URI_ENCODED_VALUE_HERE</code> <br />
        ///  Note that this method is not sufficient to protect for cross-site scripting
        ///  in a generic URI context, but only for query string values. If you
        ///  need to escape a URI in an <code>href</code> attribute (for example), 
        ///  ensure that:
        ///  <ul>
        ///    <li>The scheme is allowed (restrict to http, https, or mailto)</li>
        ///    <li>Use the HTML escaper <see cref="Html"/> on the entire URI</li>
        ///  </ul>
        ///  <p>
        ///  This URI encoder processes the following characters:
        ///  <ul>
        ///  <li>
        ///  URI characters: <code>' (U+0022)</code>, <code>" (U+0027)</code>, 
        ///                  <code>\ (U+005C)</code>, <code>/ (U+002F)</code>, 
        ///                  <code>&lt; (U+003C)</code>, <code>&gt; (U+003E)</code>,  
        ///                  <code>&amp; (U+0026)</code>, 
        ///                  <code>&lt; (U+003C)</code>, <code>&gt; (U+003E)</code>, 
        ///                  code>! (U+0021)</code>, <code># (U+0023)</code>, 
        ///                  <code>$ (U+0024)</code>, <code>% (U+0025)</code>, 
        ///                  <code>( (U+0028)</code>, <code>) (U+0029)</code>, 
        ///                  <code>* (U+002A)</code>, <code>+ (U+002B)</code>, 
        ///                  <code>, (U+002C)</code>, <code>. (U+002E)</code>, 
        ///                  <code>: (U+003A)</code>, <code>; (U+003B)</code>, 
        ///                  <code>= (U+003D)</code>, <code>? (U+003F)</code>, 
        ///                  <code>@ (U+0040)</code>, <code>[ (U+005B)</code>, 
        ///                  <code>] (U+005D)</code> 
        ///   </li>
        ///   <li>
        ///   Control characters: <code>\t (U+0009)</code>, <code>\n (U+000A)</code>, 
        ///                       <code>\f (U+000C)</code>, <code>\r (U+000D)</code>, 
        ///                       <code>SPACE (U+0020)</code>
        ///   </li>
        ///   </ul>
        /// </summary>
        /// <param name="input">Input the string to be escaped</param>
        /// <returns>The URI encoded string or <code>null</code> if <code>input</code> is null</returns>
        public static string UriParam(string input)
        {
            if (input == null)
                return null;

            var output = AllocateStringBuilder(input.Length);
            foreach (var c in input)
            {
                switch (c)
                {
                    // Control chars
                    case '\t':
                        output.Append("%09");
                        break;
                    case '\n':
                        output.Append("%0A");
                        break;
                    case '\f':
                        output.Append("%0C");
                        break;
                    case '\r':
                        output.Append("%0D");
                        break;
                    // RFC chars to encode, plus % ' " < and >, and space
                    case ' ':
                        output.Append("%20");
                        break;
                    case '!':
                        output.Append("%21");
                        break;
                    case '"':
                        output.Append("%22");
                        break;
                    case '#':
                        output.Append("%23");
                        break;
                    case '$':
                        output.Append("%24");
                        break;
                    case '%':
                        output.Append("%25");
                        break;
                    case '&':
                        output.Append("%26");
                        break;
                    case '\'':
                        output.Append("%27");
                        break;
                    case '(':
                        output.Append("%28");
                        break;
                    case ')':
                        output.Append("%29");
                        break;
                    case '*':
                        output.Append("%2A");
                        break;
                    case '+':
                        output.Append("%2B");
                        break;
                    case ',':
                        output.Append("%2C");
                        break;
                    case '.':
                        output.Append("%2E");
                        break;
                    case '/':
                        output.Append("%2F");
                        break;
                    case ':':
                        output.Append("%3A");
                        break;
                    case ';':
                        output.Append("%3B");
                        break;
                    case '<':
                        output.Append("%3C");
                        break;
                    case '=':
                        output.Append("%3D");
                        break;
                    case '>':
                        output.Append("%3E");
                        break;
                    case '?':
                        output.Append("%3F");
                        break;
                    case '@':
                        output.Append("%40");
                        break;
                    case '[':
                        output.Append("%5B");
                        break;
                    case ']':
                        output.Append("%5D");
                        break;
                    default:
                        output.Append(c);
                        break;
                }
            }
            return output.ToString();

        }

        /// <summary>
        ///  Alias for <see cref="UriParam"/>.
        /// </summary>
        /// <param name="input">Input the string to be escaped</param>
        /// <returns>The URI encoded string or <code>null</code> if <code>input</code> is null</returns>
        public static string Uri(string input)
        {
            return UriParam(input);
        }

        /// <summary>
        ///  JavaScript String Unicode escaper.
        ///  <p>
        ///  JavaScript String Unicode escaping (<code>\UXXXX</code>) to be used in single or double quoted
        ///  JavaScript strings: 
        ///  <pre>
        ///  &lt;script type="text/javascript"&gt;
        ///    window.myString = 'JS_STRING_ESCAPE_HERE';
        ///    window.yourString = "JS_STRING_ESCAPE_HERE";
        ///  &lt;/script&gt;
        ///  </pre>
        ///  <p>
        ///  This JavaScript string escaper processes the following characters:
        ///  <ul>
        ///  <li>
        ///  JS String characters: <code>' (U+0022)</code>, <code>" (U+0027)</code>, 
        ///                        <code>\ (U+005C)</code> 
        ///  </li>
        ///  <li>
        ///  URI encoding characters: <code>% (U+0025)</code>
        ///  </li>
        ///  <li>
        ///  HTML characters: <code>/ (U+002F)</code>,
        ///                   <code>&lt; (U+003C)</code>, <code>&gt; (U+003E)</code>, 
        ///                   <code>&amp; (U+0026)</code>
        ///  </li>
        ///  <li>
        ///  Control characters: <code>\b (U+0008)</code>, <code>\t (U+0009)</code>, 
        ///                      <code>\n (U+000A)</code>, <code>0x0b (U+000B)</code>, 
        ///                      <code>\f (U+000C)</code>, <code>\r (U+000D)</code> 
        ///  </li>
        ///  <li>
        ///  Unicode newlines: <code>LS (U+2028)</code>, <code>PS (U+2029)</code> 
        ///  </li>
        ///  </ul>
        /// </summary>
        /// <param name="input">input the string to be escaped</param>
        /// <returns>The JavaScript string Unicode escaped string or <code>null</code> if <code>input</code> is null</returns>
        public static string JsString(string input)
        {
            if (input == null)
                return null;

            var output = AllocateStringBuilder(input.Length);
            foreach (var c in input)
            {
                switch (c)
                {
                    case '\b':
                        output.Append("\\u0008");
                        break;
                    case '\t':
                        output.Append("\\u0009");
                        break;
                    case '\n':
                        output.Append("\\u000A");
                        break;
                    case '\u000b':
                        output.Append("\\u000B");
                        break;
                    case '\f':
                        output.Append("\\u000C");
                        break;
                    case '\r':
                        output.Append("\\u000D");
                        break;
                    // JavaScript String chars
                    case '\'':
                        output.Append("\\u0027");
                        break;
                    case '"':
                        output.Append("\\u0022");
                        break;
                    case '\\':
                        output.Append("\\u005C");
                        break;
                    // URI encoding char
                    case '%':
                        output.Append("\\u0025");
                        break;
                    // HTML chars for closing the parent context
                    case '&':
                        output.Append("\\u0026");
                        break;
                    case '/':
                        output.Append("\\u002F");
                        break;
                    case '<':
                        output.Append("\\u003C");
                        break;
                    case '>':
                        output.Append("\\u003E");
                        break;
                    // Unicode
                    case '\u2028':
                        output.Append("\\u2028");
                        break;
                    case '\u2029':
                        output.Append("\\u2029");
                        break;
                    default:
                        output.Append(c);
                        break;
                }
            }
            return output.ToString();

        }

        /// <summary>
        ///  JavaScript regex content escaper.
        ///  <p>
        ///  Escape for a JavaScript regular expression:
        ///  <pre>
        ///  &lt;script type="text/javascript"&gt;
        ///    var b = /^JS_REGEX_ESCAPE_HERE/.test(document.location);
        ///  &lt;/script&gt;
        ///  </pre>
        ///  <p>
        ///  Note that when using a regular expression inside a JavaScript string such as:
        ///  <pre>&lt;script type="text/javascript"&gt;
        ///    var b = (new RegExp('^CONTENT_HERE')).test(document.location);
        ///  &lt;/script&gt;</pre>
        ///  You should first escape using the {@link #jsRegex(String)} escaper, and make sure
        ///  that the JavaScript string itself is properly rendered using the {@link #jsString(String)}
        ///  escaper. This is a nested context scenario in which we have a JavaScript regex
        ///  inside a JavaScript string, for which we need to first escape the inner most context
        ///  and walking back the stack of context to the outer most one.
        ///  </p>
        ///  <p>
        ///  This JavaScript regex escaper processes the following characters:
        ///  <ul>
        ///  <li>
        ///  Regex characters: <code>\ (U+005C)</code>, <code>/ (U+002F)</code>, 
        ///                    <code>( (U+0028)</code>, <code>[ (U+005B)</code>, 
        ///                    <code>{ (U+007B)</code>, <code>] (U+005D)</code>, 
        ///                    <code>} (U+007D)</code>, <code>) (U+0029)</code>, 
        ///                    <code>* (U+002A)</code>, <code>+ (U+002B)</code>, 
        ///                    <code>- (U+002D)</code>, <code>. (U+002E)</code>, 
        ///                    <code>? (U+003F)</code>, <code>! (U+0021)</code>, 
        ///                    <code>^ (U+005E)</code>, <code>$ (U+0024)</code>, 
        ///                    <code>| (U+007C)</code> 
        ///  </li>
        ///  <li>
        ///  Control characters: <code>\t (U+0009)</code>, <code>\n (U+000A)</code>, 
        ///                      <code>\v (U+000B)</code>, 
        ///                      <code>\f (U+000C)</code>, <code>\r (U+000D)</code> 
        ///  </li>
        ///  </ul>
        /// </summary>
        /// <param name="input">Input the string to be escaped</param>
        /// <returns>The escaped JavaScript regex or <code>null</code> if <code>input</code> is null</returns>
        public static string JsRegex(string input)
        {
            if (input == null)
                return null;

            var output = AllocateStringBuilder(input.Length);
            foreach (var c in input)
            {
                switch (c)
                {
                    case '\t':
                        output.Append("\\t");
                        break;
                    case '\n':
                        output.Append("\\n");
                        break;
                    case '\u000b':
                        output.Append("\\v");
                        break;
                    case '\f':
                        output.Append("\\f");
                        break;
                    case '\r':
                        output.Append("\\r");
                        break;
                    // Escape sequence, and regexp terminator
                    case '\\':
                        output.Append("\\\\");
                        break;
                    case '/':
                        output.Append("\\/");
                        break;
                    // Regexp specific characters
                    case '(':
                        output.Append("\\(");
                        break;
                    case '[':
                        output.Append("\\[");
                        break;
                    case '{':
                        output.Append("\\{");
                        break;
                    case ']':
                        output.Append("\\]");
                        break;
                    case ')':
                        output.Append("\\)");
                        break;
                    case '}':
                        output.Append("\\}");
                        break;
                    case '*':
                        output.Append("\\*");
                        break;
                    case '+':
                        output.Append("\\+");
                        break;
                    case '-':
                        output.Append("\\-");
                        break;
                    case '.':
                        output.Append("\\.");
                        break;
                    case '?':
                        output.Append("\\?");
                        break;
                    case '!':
                        output.Append("\\!");
                        break;
                    case '^':
                        output.Append("\\^");
                        break;
                    case '$':
                        output.Append("\\$");
                        break;
                    case '|':
                        output.Append("\\|");
                        break;
                    default:
                        output.Append(c);
                        break;
                }
            }
            return output.ToString();

        }

        /// <summary>
        ///  CSS String escaper.
        ///  <p>
        ///  CSS escaper for strings such as CSS selector or quoted URI: 
        ///  <pre>
        ///  &lt;style"&gt;
        ///   a[href *= "DATA_HERE"] {...}
        ///   li { background: url('DATA_HERE'); }
        ///  &lt;/style&gt;
        ///  </pre>
        ///  <p>
        ///  This CSS string escaper processes the following characters:
        ///  <ul>
        ///  <li>
        ///  CSS string characters: <code>' (U+0022)</code>, <code>" (U+0027)</code>, 
        ///                         <code>\ (U+005C)</code>
        ///  </li>
        ///  <li>
        ///  HTML characters: <code>/ (U+002F)</code>,
        ///                   <code>&lt; (U+003C)</code>, <code>&gt; (U+003E)</code>, 
        ///                   <code>&amp; (U+0026)</code>
        ///  </li>
        ///  <li>
        ///  Control characters: <code>\b (U+0008)</code>, 
        ///                      <code>\t (U+0009)</code>, <code>\n (U+000A)</code>, 
        ///                      <code>\f (U+000C)</code>, <code>\r (U+000D)</code> 
        ///  </li>
        ///  <li>
        ///  Unicode newlines: <code>LS (U+2028)</code>, <code>PS (U+2029)</code>
        ///  </li>
        ///  </ul>
        /// </summary>
        /// <param name="input">Input the string to be escaped</param>
        /// <returns>The CSS string escaped or <code>null</code> if <code>input</code> is null</returns>
        public static string CssString(string input)
        {
            if (input == null)
                return null;

            var output = AllocateStringBuilder(input.Length);
            foreach (var c in input)
            {
                switch (c)
                {
                    case '\b':
                        output.Append("\\08 ");
                        break;
                    case '\t':
                        output.Append("\\09 ");
                        break;
                    case '\n':
                        output.Append("\\0A ");
                        break;
                    case '\f':
                        output.Append("\\0C ");
                        break;
                    case '\r':
                        output.Append("\\0D ");
                        break;
                    // String chars
                    case '\'':
                        output.Append("\\27 ");
                        break;
                    case '"':
                        output.Append("\\22 ");
                        break;
                    case '\\':
                        output.Append("\\5C ");
                        break;
                    // HTML chars for closing the parent context
                    case '&':
                        output.Append("\\26 ");
                        break;
                    case '/':
                        output.Append("\\2F ");
                        break;
                    case '<':
                        output.Append("\\3C ");
                        break;
                    case '>':
                        output.Append("\\3E ");
                        break;
                    // Unicode
                    case '\u2028':
                        output.Append("\\002028 ");
                        break;
                    case '\u2029':
                        output.Append("\\002029 ");
                        break;
                    default:
                        output.Append(c);
                        break;
                }
            }
            return output.ToString();

        }

        /// <summary>
        ///  SQL LIKE clause escaper.
        ///  <p>
        ///  Similar to <see cref="SqlLikeClause"/>, but allows to specify the escape character
        ///  to be used. When a character different than <code>@</code> is used, <code>@</code> will
        ///  not be escaped by the escaper, and the specified escape character will be.
        /// </p>
        /// </summary>
        /// <param name="input">The string to be escaped</param>
        /// <param name="escape">The escape character to be used </param>
        /// <returns>The SQL LIKE escaped string or <code>null</code> if <code>input</code> is null</returns>
        public static string SqlLikeClause(string input, char escape = '@')
        {
            if (input == null)
                return null;

            var output = AllocateStringBuilder(input.Length);
            foreach (var c in input)
            {
                if (c == escape || c == '_' || c == '%')
                {
                    output.Append(escape);
                }
                output.Append(c);
            }
            return output.ToString();

        }

        /// <summary>
        /// Compute the allocation size of the StringBuilder based on the length.
        /// </summary>
        /// <param name="length">Length of the original string to to escape</param>
        /// <returns>A stringbuilder with a buffer size twice that of the original string</returns>
        private static StringBuilder AllocateStringBuilder(int length)
        {
            // Allocate enough temporary buffer space to avoid reallocation in most
            // cases. If you believe you will output large amount of data at once
            // you might need to change the factor.
            int buflen = length;
            if (length * 2 > 0)
                buflen = length * 2;
            return new StringBuilder(buflen);
        }
    }
}
