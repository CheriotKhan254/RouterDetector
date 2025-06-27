// ...existing code...
namespace RouterDetector.CaptureConsole.ProtocolParsers
{
    public class SmtpParser
    {
        public EmailMessage? Parse(string payload)
        {
            // TODO: Implement SMTP parsing logic (headers, DATA, attachments)
            return null;
        }
    }

    public class ImapParser
    {
        public EmailMessage? Parse(string payload)
        {
            // TODO: Implement IMAP parsing logic (FETCH, BODY, attachments)
            return null;
        }
    }

    public class Pop3Parser
    {
        public EmailMessage? Parse(string payload)
        {
            // TODO: Implement POP3 parsing logic (RETR, headers, attachments)
            return null;
        }
    }

    public class EmailMessage
    {
        public string? From { get; set; }
        public string? To { get; set; }
        public string? Subject { get; set; }
        public string? Body { get; set; }
        public List<EmailAttachment> Attachments { get; set; } = new();
    }

    public class EmailAttachment
    {
        public string? FileName { get; set; }
        public byte[]? Content { get; set; }
        public string? ContentType { get; set; }
    }
}
// ...existing code...