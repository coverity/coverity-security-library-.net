using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Mvc;
using Coverity.Security;

namespace Coverity.Security.Example.Controllers
{
    public class ExampleController : Controller
    {
        //
        // GET: /Example/
        [ValidateInput(false)] // Living life on the edge
        public ActionResult Index(string name, string url, string font, string jsString, string number, string cssId,
            string backgroundUrl, string backgroundColour, string linkFragment)
        {
            ViewBag.Name = name;
            ViewBag.Attribute = name;
            ViewBag.Url = url;
            ViewBag.Font = font;
            ViewBag.JsString = jsString;
            ViewBag.Number = number;
            ViewBag.CssID = cssId;
            ViewBag.BackgroundUrl = backgroundUrl;
            ViewBag.BackgroundColor = backgroundColour;
            ViewBag.LinkFragment = linkFragment;
            return View();
        }
    }
}
