using System;
using System.Web;

namespace Coverity.Security
{
    public class Cov
    {
        public static IHtmlString Html(Object input)
        {
            if (input is string)
            {
                return new HtmlString(Escape.Html((string)input));
            }
            else if (input is IHtmlString)
            {
                return new HtmlString(Escape.Html(((IHtmlString)input).ToHtmlString()));
            }
            return null;
        }

        public static IHtmlString HtmlText(Object input)
        {
            if (input is string)
            {
                return new HtmlString(Escape.HtmlText((string)input));
            }
            else if (input is IHtmlString)
            {
                return new HtmlString(Escape.HtmlText(((IHtmlString)input).ToHtmlString()));
            }
            return null;
        }

        public static string Uri(Object input)
        {
            if (input is string)
            {
                return Escape.Uri((string)input);
            }
            else if (input is IHtmlString)
            {
                return Escape.Uri(((IHtmlString)input).ToHtmlString());
            }
            return null;
        }

        public static string UriParam(Object input)
        {
            if (input is string)
            {
                return Escape.UriParam((string)input);
            }
            else if (input is IHtmlString)
            {
                return Escape.UriParam(((IHtmlString)input).ToHtmlString());
            }
            return null;
        }

        public static IHtmlString JsString(Object input)
        {
            if (input is string)
            {
                return new HtmlString(Escape.JsString((string)input));
            }
            else if (input is IHtmlString)
            {
                return new HtmlString(Escape.JsString(((IHtmlString)input).ToHtmlString()));
            }
            return null;
        }

        public static IHtmlString JsRegex(Object input)
        {
            if (input is string)
            {
                return new HtmlString(Escape.JsRegex((string)input));
            }
            else if (input is IHtmlString)
            {
                return new HtmlString(Escape.JsRegex(((IHtmlString)input).ToHtmlString()));
            }
            return null;
        }

        public static IHtmlString CssString(Object input)
        {
            if (input is string)
            {
                return new HtmlString(Escape.CssString((string)input));
            }
            else if (input is IHtmlString)
            {
                return new HtmlString(Escape.CssString(((IHtmlString)input).ToHtmlString()));
            }
            return null;
        }

        public static IHtmlString AsNumber(Object input)
        {
            if (input is string)
            {
                return new HtmlString(Filter.AsNumber((string)input));
            }
            else if (input is IHtmlString)
            {
                return new HtmlString(Filter.AsNumber(((IHtmlString)input).ToHtmlString()));
            }
            return null;
        }

        public static IHtmlString AsNumber(Object input, string defaultNumber)
        {
            if (input is string)
            {
                return new HtmlString(Filter.AsNumber((string)input, defaultNumber));
            }
            else if (input is IHtmlString)
            {
                return new HtmlString(Filter.AsNumber(((IHtmlString)input).ToHtmlString(), defaultNumber));
            }
            return null;
        }

        public static IHtmlString AsCssColor(Object input)
        {
            if (input is string)
            {
                return new HtmlString(Filter.AsCssColor((string)input));
            }
            else if (input is IHtmlString)
            {
                return new HtmlString(Filter.AsCssColor(((IHtmlString)input).ToHtmlString()));
            }
            return null;
        }

        public static IHtmlString AsCssColor(Object input, string defaultColor)
        {
            if (input is string)
            {
                return new HtmlString(Filter.AsCssColor((string)input, defaultColor));
            }
            else if (input is IHtmlString)
            {
                return new HtmlString(Filter.AsCssColor(((IHtmlString)input).ToHtmlString(), defaultColor));
            }
            return null;
        }

        public static string AsURL(Object input)
        {
            if (input is string)
            {
                return Filter.AsURL((string)input);
            }
            else if (input is IHtmlString)
            {
                return Filter.AsURL(((IHtmlString)input).ToHtmlString());
            }
            return null;
        }

        public static string AsFlexibleURL(Object input)
        {
            if (input is string)
            {
                return Filter.AsFlexibleURL((string)input);
            }
            else if (input is IHtmlString)
            {
                return Filter.AsFlexibleURL(((IHtmlString)input).ToHtmlString());
            }
            return null;
        }
    }
}
