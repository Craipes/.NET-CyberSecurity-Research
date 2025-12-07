using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace CyberSecurity.Migrations
{
    /// <inheritdoc />
    public partial class AddedFullAccessRole : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<bool>(
                name: "HasFullAccess",
                table: "Users",
                type: "boolean",
                nullable: false,
                defaultValue: false);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "HasFullAccess",
                table: "Users");
        }
    }
}
