using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace RouterDetector.Migrations
{
    /// <inheritdoc />
    public partial class nn : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "Detectionlogs");

            migrationBuilder.DropTable(
                name: "Networklogs");

            migrationBuilder.CreateTable(
                name: "EventLogs",
                columns: table => new
                {
                    Id = table.Column<int>(type: "int", nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    Timestamp = table.Column<DateTime>(type: "datetime2", nullable: false),
                    Institution = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    DeviceName = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    DeviceType = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    LogSource = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    EventType = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    Severity = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    Username = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    SrcIp = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    DstIp = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    SrcPort = table.Column<int>(type: "int", nullable: true),
                    DstPort = table.Column<int>(type: "int", nullable: true),
                    Protocol = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    ActionTaken = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    NatSrcIp = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    NatDstIp = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    Hostname = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    Notes = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    RuleType = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    LivePcap = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    Message = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    LogOccurrence = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    EventType2 = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    Severity2 = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    UserAccount = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    ActionTaken2 = table.Column<string>(type: "nvarchar(max)", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_EventLogs", x => x.Id);
                });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "EventLogs");

            migrationBuilder.CreateTable(
                name: "Detectionlogs",
                columns: table => new
                {
                    Id = table.Column<int>(type: "int", nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    ActionTaken = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    DeviceType = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    EventType = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    Institution = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    LogSource = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    Notes = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    Severty = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    SourceIP = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    Timestamp = table.Column<DateTime>(type: "datetime2", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Detectionlogs", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "Networklogs",
                columns: table => new
                {
                    Id = table.Column<int>(type: "int", nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    DstIp = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    DstPort = table.Column<int>(type: "int", nullable: false),
                    LivePcap = table.Column<bool>(type: "bit", nullable: true),
                    LogOccurrence = table.Column<DateTime>(type: "datetime2", nullable: true),
                    Message = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    Protocol = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    RuleType = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    SrcIp = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    SrcPort = table.Column<int>(type: "int", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Networklogs", x => x.Id);
                });
        }
    }
}
