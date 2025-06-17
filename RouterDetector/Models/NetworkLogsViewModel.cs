namespace RouterDetector.Models
{
    public class NetworkLogsViewModel
    {
        public List<Networklogs> Logs { get; set; }
        public int PageNumber { get; set; }
        public int PageSize { get; set; }
        public int TotalRecords { get; set; }
        public int TotalPages => (int)Math.Ceiling((double)TotalRecords / PageSize);
        public string? FilterIpAddress { get; set; }
        public string? FilterProtocol { get; set; }
        public DateTime? FilterStartDate { get; set; }
        public DateTime? FilterEndDate { get; set; }
    }
}
