namespace PassboxApp
{
    public class GlobalData
    {
        public static string DBName { get; set; } =  "pb.db";

        public static string DBAlias { get; set; } = "pbdb";

        public static string? DirPath { get; set; } = FileSystem.AppDataDirectory;

        public static string? DBPath { get; set; } = Path.Combine(DirPath, DBName);

        public static string GetDeviceId()
        {
            return $"{DeviceInfo.Platform}-{DeviceInfo.Idiom}-{DeviceInfo.DeviceType}-{Guid.NewGuid()}-{DateTime.UtcNow.Ticks}";
        }
    }
}
