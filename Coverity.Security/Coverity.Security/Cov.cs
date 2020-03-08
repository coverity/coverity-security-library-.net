using System;
using System.Web;
using JetBrains.Annotations;

namespace Coverity.Security
{
    [PublicAPI]
    public static class Cov
    {
#if NETSTANDARD
        public static string Html(string input) => Escape.Html(input);

        public static string HtmlText(string input) => Escape.HtmlText(input);

        public static string JsString(string input) => Escape.JsString(input);

        public static string JsRegex(string input) => Escape.JsRegex(input);

        public static string CssString(string input) => Escape.CssString(input);

        public static string AsNumber(string input) => Filter.AsNumber(input);

        public static string AsNumber(string input, string defaultNumber) => Filter.AsNumber(input, defaultNumber);

        public static string AsCssColor(string input) => Filter.AsCssColor(input);

        public static string AsCssColor(string input, string defaultColor) => Filter.AsCssColor(input, defaultColor);
#else
        public static IHtmlString Html(object input)
        {
            switch (input)
            {
                case string s:
                    return new HtmlString(Escape.Html(s));
                case IHtmlString htmlString:
                    return new HtmlString(Escape.Html(htmlString.ToHtmlString()));
                default:
                    return null;
            }
        }
        
        public static IHtmlString HtmlText(object input)
        {
            switch (input)
            {
                case string s:
                    return new HtmlString(Escape.HtmlText(s));
                case IHtmlString htmlString:
                    return new HtmlString(Escape.HtmlText(htmlString.ToHtmlString()));
                default:
                    return null;
            }
        }
        
        public static IHtmlString JsString(object input)
        {
            switch (input)
            {
                case string s:
                    return new HtmlString(Escape.JsString(s));
                case IHtmlString htmlString:
                    return new HtmlString(Escape.JsString(htmlString.ToHtmlString()));
                default:
                    return null;
            }
        }

        public static IHtmlString JsRegex(object input)
        {
            switch (input)
            {
                case string s:
                    return new HtmlString(Escape.JsRegex(s));
                case IHtmlString htmlString:
                    return new HtmlString(Escape.JsRegex(htmlString.ToHtmlString()));
                default:
                    return null;
            }
        }

        public static IHtmlString CssString(object input)
        {
            switch (input)
            {
                case string s:
                    return new HtmlString(Escape.CssString(s));
                case IHtmlString htmlString:
                    return new HtmlString(Escape.CssString(htmlString.ToHtmlString()));
                default:
                    return null;
            }
        }

        public static IHtmlString AsNumber(object input)
        {
            switch (input)
            {
                case string s:
                    return new HtmlString(Filter.AsNumber(s));
                case IHtmlString htmlString:
                    return new HtmlString(Filter.AsNumber(htmlString.ToHtmlString()));
                default:
                    return null;
            }
        }

        public static IHtmlString AsNumber(object input, string defaultNumber)
        {
            switch (input)
            {
                case string s:
                    return new HtmlString(Filter.AsNumber(s, defaultNumber));
                case IHtmlString htmlString:
                    return new HtmlString(Filter.AsNumber(htmlString.ToHtmlString(), defaultNumber));
                default:
                    return null;
            }
        }

        public static IHtmlString AsCssColor(object input)
        {
            switch (input)
            {
                case string s:
                    return new HtmlString(Filter.AsCssColor(s));
                case IHtmlString htmlString:
                    return new HtmlString(Filter.AsCssColor(htmlString.ToHtmlString()));
                default:
                    return null;
            }
        }

        public static IHtmlString AsCssColor(object input, string defaultColor)
        {
            switch (input)
            {
                case string s:
                    return new HtmlString(Filter.AsCssColor(s, defaultColor));
                case IHtmlString htmlString:
                    return new HtmlString(Filter.AsCssColor(htmlString.ToHtmlString(), defaultColor));
                default:
                    return null;
            }
        }
#endif
        public static string Uri(object input)
        {
            switch (input)
            {
                case string s:
                    return Escape.Uri(s);
#if NET4 
                case IHtmlString htmlString:
                    return Escape.Uri(htmlString.ToHtmlString());
#endif
                default:
                    return null;
            }
        }

        public static string UriParam(object input)
        {
            switch (input)
            {
                case string s:
                    return Escape.UriParam(s);
#if NET4 
                case IHtmlString htmlString:
                    return Escape.UriParam(htmlString.ToHtmlString());
#endif
                default:
                    return null;
            }
        }

        public static string AsUrl(object input)
        {
            switch (input)
            {
                case string s:
                    return Filter.AsUrl(s);
#if NET4 
                case IHtmlString htmlString:
                    return Filter.AsURL(htmlString.ToHtmlString());
#endif
                default:
                    return null;
            }
        }

        public static string AsFlexibleUrl(object input)
        {
            switch (input)
            {
                case string s:
                    return Filter.AsFlexibleUrl(s);
#if NET4 
                case IHtmlString htmlString:
                    return Filter.AsFlexibleURL(htmlString.ToHtmlString());
#endif
                default:
                    return null;
            }
        }
    }
}
