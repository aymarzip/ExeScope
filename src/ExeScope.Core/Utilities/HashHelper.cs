using System.Security.Cryptography;

namespace ExeScope.Core.Utilities;

public static class HashHelper
{
    public static string ComputeSha256(string filePath)
    {
        if (!File.Exists(filePath))
            return string.Empty;

        // Open with FileShare.ReadWrite to not block other processes that may have the file open
        using var stream = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
        return ComputeSha256(stream);
    }

    public static string ComputeSha256(Stream stream)
    {
        using var sha256 = SHA256.Create();
        byte[] hash = sha256.ComputeHash(stream);
        return Convert.ToHexString(hash).ToLowerInvariant();
    }

    public static string ComputeSha256(byte[] data)
    {
        using var sha256 = SHA256.Create();
        byte[] hash = sha256.ComputeHash(data);
        return Convert.ToHexString(hash).ToLowerInvariant();
    }
}
