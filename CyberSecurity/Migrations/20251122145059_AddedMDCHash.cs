using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace CyberSecurity.Migrations
{
    /// <inheritdoc />
    public partial class AddedMDCHash : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "MdcHash",
                table: "Blocks",
                type: "text",
                nullable: false,
                defaultValue: "");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "MdcHash",
                table: "Blocks");
        }
    }
}
