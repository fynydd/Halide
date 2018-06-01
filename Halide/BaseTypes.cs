using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Formatters.Binary;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;

using Fynydd.Halide.Constants;

namespace Fynydd.Halide
{
    public static class BaseTypes
    {
        #region Strings and string output

        /// <summary>
        /// Get the left "length" characters of a string.
        /// </summary>
        /// <param name="value">String value</param>
        /// <param name="length">Number of characters</param>
        /// <returns>Left portion of a string</returns>
        public static string Left(this string value, int length)
        {
            string result = value;

            if (string.IsNullOrEmpty(value) == false)
            {
                if (value.Length >= length)
                {
                    result = value.Substring(0, length);
                }
            }

            return result;
        }

        /// <summary>
        /// Get the left characters of a string up to but not including the first instance of "marker".
        /// </summary>
        /// <param name="value">String value</param>
        /// <param name="marker">Delimitter to denote the cut off point</param>
        /// <returns>Left portion of a string</returns>
        public static string Left(this string value, string marker)
        {
            string result = value;

            if (string.IsNullOrEmpty(value) == false && string.IsNullOrEmpty(marker) == false)
            {
                if (value.Length >= marker.Length)
                {
                    if (value.IndexOf(marker) >= 0)
                    {
                        result = value.Substring(0, value.IndexOf(marker));
                    }
                }
            }

            return result;
        }

        /// <summary>
        /// Get the right "length" characters of a string.
        /// </summary>
        /// <param name="value">String value</param>
        /// <param name="length">Number of characters</param>
        /// <returns>Right portion of a string</returns>
        public static string Right(this string value, int length)
        {
            string result = value;

            if (string.IsNullOrEmpty(value) == false)
            {
                if (value.Length >= length)
                {
                    result = value.Substring(value.Length - length, length);
                }
            }

            return result;
        }

        /// <summary>
        /// Get the right characters of a string up to but not including the last instance of "marker" (right to left).
        /// </summary>
        /// <param name="value">String value</param>
        /// <param name="marker">Delimitter to denote the cut off point</param>
        /// <returns>Right portion of a string</returns>
        public static string Right(this string value, string marker)
        {
            string result = value;

            if (string.IsNullOrEmpty(value) == false && string.IsNullOrEmpty(marker) == false)
            {
                if (value.Length >= marker.Length)
                {
                    if (value.IndexOf(marker) >= 0)
                    {
                        result = value.Substring(value.LastIndexOf(marker) + marker.Length);
                    }
                }
            }

            return result;
        }

        /// <summary>
        /// Replace string occurrences within another string, ignoring case, using whole word or character based matching.
        /// </summary>
        /// <param name="value">String to search</param>
        /// <param name="substring">String to find</param>
        /// <param name="newstring">String replacement</param>
        /// <param name="wholeWords">If true, only match whole words</param>
        /// <returns>New string with replacements made</returns>
        public static string ReplaceWord(this string value, string substring, string newstring, bool wholeWords = true)
        {
            string pattern = (wholeWords ? @"\b" + substring + @"\b" : substring);
            Regex regEx = new Regex(pattern, RegexOptions.IgnoreCase | RegexOptions.Multiline);
            return regEx.Replace(value, newstring);
        }

        /// <summary>
        /// Replace the first instance of a string.
        /// </summary>
        /// <param name="value">String to search</param>
        /// <param name="substring">String to find</param>
        /// <param name="newstring">String replacement</param>
        /// <param name="wholeWords">If true, only match whole words</param>
        /// <returns>String with first occurrence replaced</returns>
        public static string ReplaceFirst(this string value, string substring, string newstring, bool wholeWords = true)
        {
            string pattern = (wholeWords ? @"\b" + substring + @"\b" : substring);
            Regex regEx = new Regex(pattern, RegexOptions.IgnoreCase | RegexOptions.Multiline);
            return regEx.Replace(value, newstring, 1);
        }

        /// <summary>
        /// Replace the last instance of a string.
        /// </summary>
        /// <param name="value">String to search</param>
        /// <param name="substring">String to find</param>
        /// <param name="newstring">String replacement</param>
        /// <param name="wholeWords">If true, only match whole words</param>
        /// <returns>String with last occurrence replaced</returns>
        public static string ReplaceLast(this string value, string substring, string newstring, bool wholeWords = true)
        {
            string pattern = (wholeWords ? @"\b" + substring + @"\b" : substring);
            Regex regEx = new Regex(pattern, RegexOptions.IgnoreCase | RegexOptions.Multiline | RegexOptions.RightToLeft);
            return regEx.Replace(value, newstring, 1);
        }

        /// <summary>
        /// Replace words in a string with mask characters, like asterisks. Useful for filtering profanity.
        /// </summary>
        /// <param name="value">String to search</param>
        /// <param name="stringMask">Mask character to use (e.g. "*")</param>
        /// <param name="filterWords">String array of words to mask</param>
        /// <returns>String with masked words</returns>
        public static string FilterWords(this string value, string stringMask, params string[] filterWords)
        {
            string result = value;
            string totalMask = stringMask;

            foreach (string s in filterWords)
            {
                Regex regEx = new Regex(s, RegexOptions.IgnoreCase | RegexOptions.Multiline);

                if (stringMask.Length > 0)
                {
                    for (int i = 1; i < s.Length; i++)
                    {
                        totalMask += stringMask;
                    }
                }

                result = regEx.Replace(result, totalMask);

                totalMask = stringMask;
            }

            return result;
        }

        /// <summary>
        /// Convert a string to AP style title case, which makes all words use an upper case first character,
        /// except a core set of small words, unless one of those small words is the first or last one in the string.
        /// </summary>
        /// <param name="value">String to make AP title case</param>
        /// <returns>String in AP title case</returns>
        public static string ApTitleCase(this string value)
        {
            string newTitle = value;

            if (string.IsNullOrEmpty(newTitle) == false)
            {
                char[] space = new char[] { ' ' };

                CultureInfo cultureInfo = Thread.CurrentThread.CurrentCulture;
                TextInfo textInfo = cultureInfo.TextInfo;

                newTitle = textInfo.ToTitleCase(value.ToLower());

                List<string> tokens = newTitle.Split(space, StringSplitOptions.RemoveEmptyEntries).ToList();

                if (tokens.Count > 2)
                {
                    var firstWord = tokens[0];
                    var lastWord = tokens[tokens.Count - 1];

                    tokens.RemoveAt(0);
                    tokens.RemoveAt(tokens.Count - 1);

                    newTitle = firstWord;

                    newTitle += tokens.Aggregate<String, String>(String.Empty, (String prev, String input)
                        => prev +
                            (Words.TitleCaseIgnoreWords.Contains(input.ToLower())
                                ? " " + input.ToLower()
                                : " " + input));

                    newTitle += " " + lastWord;
                }
            }

            return newTitle;
        }

        /// <summary>
        /// Makes two or more consecutive spaces in a string one single space.
        /// </summary>
        /// <param name="value">String to process</param>
        /// <returns>String with only single spaces</returns>
        public static string RemoveExtraSpaces(this string value)
        {
            Regex regEx = new Regex(@"[\s]+");
            return regEx.Replace(value, " ");
        }

        /// <summary>
        /// Return the current string cropped by number of words or characters.
        /// <para>
        /// Words: returns the first "count" of words in the string, including any intermediate punctuation, etc.
        /// Trailing punctuation is always removed.
        /// </para>
        /// <para>
        /// Characters: returns the first "count" of characters in the string, including any intermediate punctuation, etc.
        /// When it locates the last character, it scans ahead to make sure it's not breaking a word. If it is in the middle
        /// of a word, it will skip ahead to the next non-alpha-numeric chatacter and break on that, so your cropped string
        /// may be slightly larger than the number of characters you requested. Trailing punctuation is always removed.
        /// </para>
        /// </summary>
        /// <example>
        /// <code>
        /// result = result.Crop(3, StringCropType.Words, " .,;:!?", "...");
        /// </code>
        /// result would be "now is the...".
        /// </example>
        /// <param name="value">String to process.</param>
        /// <param name="count">Number of words or characters (as close as possible) to return.</param>
        /// <param name="cropType">Enum value: CropType.Characters or CropType.Words.</param>
        /// <param name="delimitters">Valid characters on which to break (defaults to space characters).</param>
        /// <param name="endingWhenCropped">String to append to the return value, only if the string had to be cropped.</param>
        /// <returns>A cropped string</returns>
        public static string Crop(this string value, int count, StringCropType cropType, string delimitters, string endingWhenCropped)
        {
            string outt = value;

            if (string.IsNullOrEmpty(value) == false)
            {
                if (count > 0)
                {
                    switch (cropType)
                    {
                        case StringCropType.Words:

                            Regex x = new Regex(@"((\w*?)(\W|\z)){0," + count + @"}", RegexOptions.Singleline);
                            MatchCollection mc = x.Matches(value);
                            outt = mc[0].ToString();

                            break;

                        case StringCropType.Characters:

                            string breakOn = delimitters;

                            if (String.IsNullOrEmpty(breakOn))
                            {
                                breakOn = " ";
                            }

                            int test = 0;
                            int index = outt.Length;

                            if (value.Length > count)
                            {
                                for (int X = 0; X < breakOn.Length; X++)
                                {
                                    test = outt.IndexOf(breakOn.Substring(X, 1), count);

                                    if (test < index && test >= count)
                                    {
                                        index = test;
                                    }
                                }

                                if (index < 1 || index >= outt.Length)
                                {
                                    index = count;
                                }

                                else
                                {
                                    index++;
                                }

                                outt = value.Substring(0, index);
                            }

                            break;
                    }

                    if (outt.Length < value.Length)
                    {
                        Regex regEx = new Regex(@"^[a-zA-Z0-9]+$");

                        while (outt.Length > 0 && !regEx.IsMatch(outt.Substring(outt.Length - 1, 1)))
                        {
                            outt = outt.Substring(0, outt.Length - 1);
                        }

                        outt += endingWhenCropped;
                    }
                }
            }

            return outt;
        }

        /// <summary>
        /// Number of times a substring appears in a string.
        /// </summary>
        /// <param name="value">String to evaluate</param>
        /// <param name="find">Substring to count</param>
        /// <param name="wholeWords">If true only match whole words</param>
        /// <returns>Number of times the substring is found</returns>
        public static int SubStringCount(this string value, string find, bool wholeWords = true)
        {
            string pattern = (wholeWords ? @"\b" + find + @"\b" : find);

            Regex regEx = new Regex(pattern, RegexOptions.IgnoreCase | RegexOptions.Multiline);
            MatchCollection matches = regEx.Matches(value);

            return matches.Count;
        }

        /// <summary>
        /// Convert a string to a byte array.
        /// </summary>
        /// <param name="value">String to evaluate</param>
        /// <returns>Byte array</returns>
        public static byte[] ToByteArray(this string value)
        {
            System.Text.ASCIIEncoding encoding = new System.Text.ASCIIEncoding();
            return encoding.GetBytes(value);
        }

        /// <summary>
        /// Format a number into a string representation based on a number format.
        /// Useful for friendly output of telephone numebrs, disk file sizes, etc.
        /// </summary>
        /// <typeparam name="T">Numeric type being evaluated</typeparam>
        /// <param name="val">Numeric variable to evaluate</param>
        /// <param name="format">Output format for the number</param>
        /// <returns>String with the formatted number</returns>
        public static string FormatNumber<T>(this T val, NumberFormats format)
        {
            string result = "";

            if (typeof(T) == typeof(string))
            {
                if (format == NumberFormats.TelephoneFull || format == NumberFormats.TelephoneDots || format == NumberFormats.TelephoneHyphens)
                {
                    if (string.IsNullOrEmpty(val.ToString()) == false)
                    {
                        var pattern = "";

                        if (val.ToString().Length > 0)
                        {
                            for (int x = 0; x < val.ToString().Length; x++)
                            {
                                char strChar = Convert.ToChar(val.ToString().Substring(x, 1));

                                if ((int)strChar > 47 && (int)strChar < 58) result += val.ToString().Substring(x, 1);
                            }
                        }

                        if (result.Length == 11 && result.StartsWith("1"))
                        {
                            result = result.TrimStart('1');
                        }

                        if (result.Length == 10)
                        {
                            switch (format)
                            {
                                case NumberFormats.TelephoneFull:
                                    pattern = "({0}) {1}-{2}";
                                    break;

                                case NumberFormats.TelephoneDots:
                                    pattern = "{0}.{1}.{2}";
                                    break;

                                case NumberFormats.TelephoneHyphens:
                                    pattern = "{0}-{1}-{2}";
                                    break;
                            }

                            result = string.Format(pattern, result.Substring(0, 3), result.Substring(3, 3), result.Substring(6));
                        }
                    }
                }
            }

            else
            {
                decimal value = Convert.ToDecimal(val);
                result = value.ToString();

                switch (format)
                {
                    case NumberFormats.TelephoneFull:

                        break;

                    case NumberFormats.TelephoneDots:

                        break;

                    case NumberFormats.TelephoneHyphens:

                        break;

                    case NumberFormats.Currency:

                        result = (value.ToString("#,##0.00"));
                        break;

                    case NumberFormats.DiskStorage:

                        // BYTES
                        if (value < 1024)
                        {
                            result = (value.ToString("#,##0")) + "bytes";
                        }

                        // KILOBYTE
                        if (value > 1023 && value < 1048576)
                        {
                            decimal newVal = (value / 1024);
                            result = (newVal.ToString("#,##0.#")) + "kb";
                        }

                        // MEGABYTES
                        if (value >= 1048576 && value < 1073741824)
                        {
                            decimal newVal = (value / 1024) / 1024;
                            result = (newVal.ToString("#,##0.#")) + "mb";
                        }

                        // GIGABYTES
                        if (value >= 1073741824 && value < 1099511627776)
                        {
                            decimal newVal = ((value / 1024) / 1024) / 1024;
                            result = (newVal.ToString("#,##0.#")) + "gb";
                        }

                        // TERABYTES
                        if (value >= 1099511627776 && value < 1125899906842624)
                        {
                            decimal newVal = (((value / 1024) / 1024) / 1024) / 1024;
                            result = (newVal.ToString("#,##0.#")) + "tb";
                        }

                        // PETABYTES
                        if (value >= 1125899906842624 && value < 1152921504606846976)
                        {
                            decimal newVal = ((((value / 1024) / 1024) / 1024) / 1024) / 1024;
                            result = (newVal.ToString("#,##0.#")) + "pb";
                        }

                        break;
                }
            }

            return result;
        }

        /// <summary>
        /// Calculate a percentage in string form for friendly output.
        /// Does the math for you.
        /// </summary>
        /// <example>
        /// <code>
        /// int value = 30;
        /// string result = value.MakePercentage(total: 200, places: 2) + "%";
        /// </code>
        /// result: 15.00%
        /// </example>
        /// <typeparam name="T">Numeric type being evaluated</typeparam>
        /// <param name="val">Number to evaluate against the total</param>
        /// <param name="total">Total value from which to derive a percentage for val</param>
        /// <param name="places">Number of decimal places to use in the final output</param>
        /// <returns>Percentage value output without the trailing "%"</returns>
        public static string MakePercentage<T>(this T val, decimal total, int places)
        {
            decimal value = Convert.ToDecimal(val);
            decimal percent = 0;
            string result = string.Empty;
            string strplaces = new string('0', places);

            if (value == 0 || total == 0)
            {
                percent = 0;
            }

            else
            {
                percent = decimal.Divide(value, total) * 100;

                if (places > 0)
                {
                    strplaces = "." + strplaces;
                }
            }

            result = percent.ToString("#,##0" + strplaces);

            return result;
        }

        /// <summary>
        /// Convert a string representation of a file size into a numeric number of bytes.
        /// (e.g. convert "1kb" to 1024).
        /// </summary>
        /// <typeparam name="T">Numeric type being returned</typeparam>
        /// <param name="fileSize">String representation of a file size</param>
        /// <returns>Number of bytes</returns>
        public static T FileSizeToBytes<T>(this string fileSize)
        {
            decimal result = 0;
            decimal multiplier = 1;
            string value = fileSize.ToLower().Replace(",", "").Trim();

            if (value.EndsWith("kb")) { value = value.Replace("kb", "").Trim(); multiplier = 1024; }
            else if (value.EndsWith("mb")) { value = value.Replace("mb", "").Trim(); multiplier = 1048576; }
            else if (value.EndsWith("gb")) { value = value.Replace("gb", "").Trim(); multiplier = 1073741824; }
            else if (value.EndsWith("tb")) { value = value.Replace("tb", "").Trim(); multiplier = 1099511627776; }
            else if (value.EndsWith("pb")) { value = value.Replace("pb", "").Trim(); multiplier = 1125899906842624; }

            if (!(Convert.ToDecimal(value) > 9 && multiplier == 1125899906842624))
            {
                result = Convert.ToDecimal(value) * multiplier;
            }

            return (T)Convert.ChangeType(result, typeof(T));
        }

        /// <summary>
        /// Convert a string into a URL-friendly slug, filtering out everything but alphanumeric characters
        /// and using hyphens for whitespace.
        /// </summary>
        /// <param name="input">String to evaluate</param>
        /// <returns>URL-friendly slug</returns>
        public static string MakeSlug(this string input)
        {
            string final = input.Trim().ToLower();

            final = final.Replace("'", "");

            Regex stripStuff = new Regex("([^a-zA-Z0-9])");
            final = stripStuff.Replace(final, "-");

            stripStuff = new Regex("_{1,}");
            final = stripStuff.Replace(final, "-");

            stripStuff = new Regex("_$");
            final = stripStuff.Replace(final, "");

            stripStuff = new Regex("^_");
            final = stripStuff.Replace(final, "");

            while (final.IndexOf("--") > 0)
            {
                final = final.Replace("--", "-");
            }

            final = final.Trim('-');

            return (final);
        }

        /// <summary>
        /// Trim leading and trailing whitespace, which includes space, non-breaking space, carriage returns, linefeeds, 
        /// tabs, en space, em space, and other ASCII and 16-bit Unicode whitrspace characters.
        /// </summary>
        /// <param name="value">String to evaluate</param>
        /// <returns>String with leading and trailing whitespade removed.</returns>
        public static string TrimWhitespace(this string value)
        {
            return value.Trim(Characters.Whitespace);
        }

        /// <summary>
        /// Convert fractions like "1/3" to single-character symbolic HTML encoded fractions.
        /// </summary>
        /// <param name="value">String to evaluate</param>
        /// <returns>String with HTML encoded fractions</returns>
        public static string ConvertFractions(this string value)
        {
            string result = value;

            result = Regex.Replace(result, @"([\s|\b|\-|>])1/2([\s|\b|\-|<])", "$1&#x000BD;$2");
            result = Regex.Replace(result, @"([\s|\b|\-|>])1/3([\s|\b|\-|<])", "$1&#x02153;$2");
            result = Regex.Replace(result, @"([\s|\b|\-|>])1/4([\s|\b|\-|<])", "$1&#x000BC;$2");
            result = Regex.Replace(result, @"([\s|\b|\-|>])1/5([\s|\b|\-|<])", "$1&#x02155;$2");
            result = Regex.Replace(result, @"([\s|\b|\-|>])1/6([\s|\b|\-|<])", "$1&#x02159;$2");
            result = Regex.Replace(result, @"([\s|\b|\-|>])1/8([\s|\b|\-|<])", "$1&#x0215B;$2");
            result = Regex.Replace(result, @"([\s|\b|\-|>])2/3([\s|\b|\-|<])", "$1&#x02154;$2");
            result = Regex.Replace(result, @"([\s|\b|\-|>])2/5([\s|\b|\-|<])", "$1&#x02156;$2");
            result = Regex.Replace(result, @"([\s|\b|\-|>])3/4([\s|\b|\-|<])", "$1&#x000BE;$2");
            result = Regex.Replace(result, @"([\s|\b|\-|>])3/5([\s|\b|\-|<])", "$1&#x02157;$2");
            result = Regex.Replace(result, @"([\s|\b|\-|>])3/8([\s|\b|\-|<])", "$1&#x0215C;$2");
            result = Regex.Replace(result, @"([\s|\b|\-|>])4/5([\s|\b|\-|<])", "$1&#x02158;$2");
            result = Regex.Replace(result, @"([\s|\b|\-|>])5/6([\s|\b|\-|<])", "$1&#x0215A;$2");
            result = Regex.Replace(result, @"([\s|\b|\-|>])5/8([\s|\b|\-|<])", "$1&#x0215D;$2");
            result = Regex.Replace(result, @"([\s|\b|\-|>])7/8([\s|\b|\-|<])", "$1&#x0215E;$2");

            return result;
        }

        #endregion

        #region Variables

        /// <summary>
        /// Perform a deep copy of an object.
        /// </summary>
        /// <typeparam name="T">The type of object being copied.</typeparam>
        /// <param name="source">The object instance to copy.</param>
        /// <returns>The copied object.</returns>
        public static T DeepCopy<T>(this T source)
        {
            if (!typeof(T).IsSerializable)
            {
                throw new ArgumentException("The type must be serializable.", "source");
            }

            if (source == null)
            {
                return default(T);
            }

            IFormatter formatter = new BinaryFormatter();
            Stream stream = new MemoryStream();

            using (stream)
            {
                formatter.Serialize(stream, source);
                stream.Seek(0, SeekOrigin.Begin);
                return (T)formatter.Deserialize(stream);
            }
        }

        /// <summary>
        /// Randomize the values in a given array.
        /// <example>
        /// <code>
        ///	Int32[] values = { 1, 2, 3, 4, 5 };
        /// Int32[] randomized = values.RandomizeArray();
        /// </code>
        /// </example>
        /// </summary>
        /// <typeparam name="T">Allows for randomizing arrays of different data types.</typeparam>
        /// <param name="array">Variable array to randomize.</param>
        /// <returns>Nothing. Passed array is randomized directly.</returns>
        public static T[] RandomizeArray<T>(this T[] array)
        {
            if (array.Length > 0)
            {
                Random rng = new Random((int)DateTime.Now.Ticks);
                T[] randomized = new T[array.Length];
                randomized = array.DeepCopy<T[]>();

                int n = array.Length;

                while (n > 1)
                {
                    int k = rng.Next(n--);
                    T temp = randomized[n];
                    randomized[n] = randomized[k];
                    randomized[k] = temp;
                }

                return randomized;
            }

            else
            {
                T[] randomized = new T[0];

                return randomized;
            }
        }

        #endregion
    }
}
