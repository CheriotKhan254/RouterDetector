using System.ComponentModel.DataAnnotations;

namespace RouterDetector.Models
{
    public class SystemConfiguration
    {

        [Key]
        public int Id { get; set; }
        public required string InstitutionName { get; set; }
        public required string StaffPosition { get; set; }
    }
}
