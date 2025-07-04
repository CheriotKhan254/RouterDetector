using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace RouterDetector.Migrations
{
    /// <inheritdoc />
    public partial class updatedname : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.RenameColumn(
                name: "StaffPostion",
                table: "SystemConfiguration",
                newName: "StaffPosition");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.RenameColumn(
                name: "StaffPosition",
                table: "SystemConfiguration",
                newName: "StaffPostion");
        }
    }
}
