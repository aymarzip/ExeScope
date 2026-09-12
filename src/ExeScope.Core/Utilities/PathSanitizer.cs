using System.Text.RegularExpressions;

namespace ExeScope.Core.Utilities;

public static class PathSanitizer
{
    private static readonly HashSet<string> ReservedDeviceNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "CON", "PRN", "AUX", "NUL",
        "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
        "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9"
    };

    private static readonly char[] InvalidFileNameChars = Path.GetInvalidFileNameChars();

    /// <summary>
    /// Normalizes a Windows path to canonical form.
    /// Strips "\\?\" prefix, normalizes slashes, resolves relative components.
    /// </summary>
    public static string NormalizeCanonicalPath(string path)
    {
        if (string.IsNullOrWhiteSpace(path))
            return string.Empty;

        string trimmed = path.Trim();

        // Strip \\?\ or \??\ prefix if present
        if (trimmed.StartsWith(@"\\?\", StringComparison.Ordinal))
            trimmed = trimmed[4..];
        else if (trimmed.StartsWith(@"\??\", StringComparison.Ordinal))
            trimmed = trimmed[4..];

        try
        {
            return Path.GetFullPath(trimmed);
        }
        catch
        {
            return trimmed.Replace('/', '\\');
        }
    }

    /// <summary>
    /// Checks whether two file paths refer to the same canonical file.
    /// </summary>
    public static bool ArePathsEquivalent(string path1, string path2)
    {
        if (string.IsNullOrWhiteSpace(path1) || string.IsNullOrWhiteSpace(path2))
            return false;

        string norm1 = NormalizeCanonicalPath(path1);
        string norm2 = NormalizeCanonicalPath(path2);

        return string.Equals(norm1, norm2, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Sanitizes an arbitrary file name or path component into a safe single file name.
    /// Strips path traversal sequences, illegal chars, ADS, and reserved names.
    /// </summary>
    public static string SanitizeFileName(string input)
    {
        if (string.IsNullOrWhiteSpace(input))
            return "unnamed_artifact";

        // Take only file name part if path was passed
        string fileName = Path.GetFileName(input);
        if (string.IsNullOrWhiteSpace(fileName))
            fileName = input;

        // Strip alternate data stream colon if present
        int colonIdx = fileName.IndexOf(':');
        if (colonIdx >= 0)
        {
            fileName = fileName[..colonIdx];
        }

        // Replace invalid characters with underscore
        char[] chars = fileName.ToCharArray();
        for (int i = 0; i < chars.Length; i++)
        {
            if (InvalidFileNameChars.Contains(chars[i]) || char.IsControl(chars[i]))
            {
                chars[i] = '_';
            }
        }

        string result = new string(chars).Trim(' ', '.');

        // Prevent path traversal sequences
        result = result.Replace("..", "_");

        if (string.IsNullOrWhiteSpace(result))
            result = "unnamed_artifact";

        // Check against reserved Windows names
        string nameWithoutExt = Path.GetFileNameWithoutExtension(result);
        int firstDot = result.IndexOf('.');
        string firstStem = firstDot >= 0 ? result[..firstDot] : result;
        if (ReservedDeviceNames.Contains(nameWithoutExt) || ReservedDeviceNames.Contains(firstStem))
        {
            result = "_" + result;
        }

        // Limit length to avoid path length overflows
        if (result.Length > 120)
        {
            string ext = Path.GetExtension(result);
            result = result.Substring(0, 100) + ext;
        }

        return result;
    }

    /// <summary>
    /// Generates a unique, strictly safe destination file path inside the designated artifacts directory.
    /// Enforces that the result never escapes the base artifacts directory.
    /// </summary>
    public static string CreateSafeArtifactDestination(string artifactsBaseDirectory, long artifactIndex, string originalPath, string sha256)
    {
        string fullBase = Path.GetFullPath(artifactsBaseDirectory);
        if (!fullBase.EndsWith(Path.DirectorySeparatorChar.ToString(), StringComparison.Ordinal))
        {
            fullBase += Path.DirectorySeparatorChar;
        }

        string safeName = SanitizeFileName(originalPath);
        string shortHash = sha256.Length >= 8 ? sha256[..8] : "00000000";
        string finalFileName = $"artifact_{artifactIndex:D4}_{shortHash}_{safeName}";

        string destination = Path.GetFullPath(Path.Combine(fullBase, finalFileName));

        if (!destination.StartsWith(fullBase, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException($"Security violation: path traversal detected! '{destination}' escapes '{fullBase}'");
        }

        return destination;
    }

    /// <summary>
    /// Checks if a file path is located within any of the specified allowed directories.
    /// </summary>
    public static bool IsPathWithinMonitoredDirectories(string filePath, IEnumerable<string> monitoredDirectories)
    {
        if (string.IsNullOrWhiteSpace(filePath))
            return false;

        string normTarget;
        try
        {
            normTarget = NormalizeCanonicalPath(filePath);
        }
        catch
        {
            return false;
        }

        foreach (var dir in monitoredDirectories)
        {
            if (string.IsNullOrWhiteSpace(dir))
                continue;

            try
            {
                string normDir = NormalizeCanonicalPath(dir);
                if (!normDir.EndsWith(Path.DirectorySeparatorChar.ToString(), StringComparison.Ordinal))
                    normDir += Path.DirectorySeparatorChar;

                if (normTarget.StartsWith(normDir, StringComparison.OrdinalIgnoreCase))
                    return true;
            }
            catch
            {
                // Ignore invalid dir paths
            }
        }

        return false;
    }
}
