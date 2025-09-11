using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace CyberSecurity.Migrations
{
    /// <inheritdoc />
    public partial class AddedUserPasswordRestriction : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<bool>(
                name: "PasswordRestrictionsEnabled",
                table: "Users",
                type: "boolean",
                nullable: false,
                defaultValue: false);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "PasswordRestrictionsEnabled",
                table: "Users");
        }
    }
}
