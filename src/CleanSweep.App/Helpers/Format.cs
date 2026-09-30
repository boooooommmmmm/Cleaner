namespace CleanSweep.App.Helpers;

public static class Format
{
    private static readonly string[] Units = { "B", "KB", "MB", "GB", "TB" };

    public static string Bytes(long bytes)
    {
        if (bytes < 0) return "-";
        double v = bytes;
        int u = 0;
        while (v >= 1024 && u < Units.Length - 1)
        {
            v /= 1024;
            u++;
        }
        return u == 0 ? $"{bytes} B" : $"{v:0.##} {Units[u]}";
    }

    public static string Percent(long part, long total) =>
        total <= 0 ? "0%" : $"{100.0 * part / total:0.#}%";

    public static string LocalTime(DateTime utc) => utc.ToLocalTime().ToString("yyyy-MM-dd HH:mm");
}
