namespace PassboxApp.Models
{
    public class PasswordEntry
    {
        public Guid Id { get; set; } = Guid.Empty;
        public string Title { get; set; }
        public string Username { get; set; }
        public string Password { get; set; }
        public string EncryptedPassword { get; set; }

        public string Alias { get; set; }

        public string Icon { get; set; } = "mdi-lock";
        public string IconClass { get; set; } = "blue";
        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
        public DateTime UpdatedAt { get; set; } = DateTime.UtcNow;
        public List<string> Tags { get; set; } = new();
    }
}
