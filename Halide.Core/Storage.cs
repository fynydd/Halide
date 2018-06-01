using System;
using System.Web;

using Fynydd.Halide.Constants;

namespace Fynydd.Halide
{
    public static class Storage
    {
        /// <summary>
        /// Transforms relative path to exact path for web and console apps.
        /// </summary>
        /// <example>
        /// <code>
        /// string realPath = relativePath.MapPath();
        /// </code>
        /// </example>
        /// <param name="path">Web-style path to a file (e.g. "/downloads/file.jpg").</param>
        /// <returns>C:\files\downloads\file.jpg</returns>
        public static string MapPath(this string path)
        {
            string filename = "";

            if (path.Length > 1)
            {
                if (path.Substring(1, 1) == ":")
                {
                    // Handle weird scenarios where libraries like libsass return 
                    // hybrid paths like "C:/paths/with/forward-slashes/"
                    path = path.Replace("/", "\\");
                }

                if (path.Contains("\\"))
                {
                    filename = path;
                }

                else
                {
                    if (HttpContext.Current != null)
                    {
                        filename = HttpContext.Current.Server.MapPath(path);
                    }

                    else
                    {
                        if (path.StartsWith("/"))
                        {
                            path = path.Substring(1, path.Length - 1);
                        }

                        filename = AppDomain.CurrentDomain.BaseDirectory + path.Replace("/", "\\");
                    }
                }
            }

            return filename;
        }
    }
}
