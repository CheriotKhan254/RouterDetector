using System;
using System.Collections.Generic;
using System.Linq;

namespace RouterDetector.CaptureConsole.ProtocolParsers
{
    public static class HttpPayloadParser
    {
        public static bool TryParse(string raw, out string method, out Dictionary<string, string> headers, out string body)
        {
            method = string.Empty;
            headers = new Dictionary<string, string>();
            body = string.Empty;

            try
            {
                var sections = raw.Split(new[] { "\r\n\r\n" }, 2, StringSplitOptions.None);
                if (sections.Length < 1) return false;

                var headerLines = sections[0].Split(new[] { "\r\n" }, StringSplitOptions.RemoveEmptyEntries);
                if (headerLines.Length == 0) return false;

                // Parse request line
                var requestParts = headerLines[0].Split(' ');
                if (requestParts.Length < 2) return false;
                method = requestParts[0].Trim().ToUpperInvariant();

                // Parse headers
                foreach (var line in headerLines.Skip(1))
                {
                    var kv = line.Split(new[] { ':' }, 2);
                    if (kv.Length == 2)
                        headers[kv[0].Trim()] = kv[1].Trim();
                }

                // Extract body
                if (sections.Length > 1)
                    body = sections[1].Trim();

                return true;
            }
            catch
            {
                return false;
            }
        }
    }
}