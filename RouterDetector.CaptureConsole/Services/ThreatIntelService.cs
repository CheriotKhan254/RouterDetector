using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace RouterDetector.CaptureConsole.Services
{
    public class ThreatIntelService
    {
        public HashSet<string> BlacklistedDomains { get; } = new HashSet<string>();

        public ThreatIntelService(string filePath = "Data/phishing-links-ACTIVE.txt")
        {
            if (File.Exists(filePath))
            {
                var lines = File.ReadAllLines(filePath);
                foreach (var line in lines)
                {
                    try
                    {
                        if (Uri.TryCreate(line, UriKind.Absolute, out var uri))
                        {
                            // Normalize the hostname, removing "www." if it exists
                            var host = uri.Host;
                            if (host.StartsWith("www.", StringComparison.OrdinalIgnoreCase))
                            {
                                host = host[4..];
                            }
                            BlacklistedDomains.Add(host);
                        }
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"Could not parse line '{line}': {ex.Message}");
                    }
                }
            }
            Console.WriteLine($"Loaded {BlacklistedDomains.Count} domains into the blacklist.");
        }

        public bool IsDomainBlacklisted(string domain)
        {
            if (string.IsNullOrEmpty(domain))
            {
                return false;
            }

            // Normalize the domain to check, removing "www."
            if (domain.StartsWith("www.", StringComparison.OrdinalIgnoreCase))
            {
                domain = domain[4..];
            }

            return BlacklistedDomains.Contains(domain);
        }
    }
}
