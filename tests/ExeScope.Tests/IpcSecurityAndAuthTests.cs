using ExeScope.Contracts.Security;
using Xunit;

namespace ExeScope.Tests;

public class IpcSecurityAndAuthTests
{
    [Fact]
    public void IpcAuthToken_GenerateToken_ProducesValidHexToken()
    {
        string token = IpcAuthToken.GenerateToken();

        Assert.NotNull(token);
        Assert.Equal(64, token.Length); // 32 bytes in hex = 64 characters
        Assert.Matches("^[0-9a-f]{64}$", token);
    }

    [Fact]
    public void IpcAuthToken_ValidateToken_ValidatesCorrectly()
    {
        string token1 = IpcAuthToken.GenerateToken();
        string token2 = IpcAuthToken.GenerateToken();

        Assert.True(IpcAuthToken.ValidateToken(token1, token1));
        Assert.False(IpcAuthToken.ValidateToken(token1, token2));
        Assert.False(IpcAuthToken.ValidateToken("", token1));
        Assert.False(IpcAuthToken.ValidateToken(null, token1));
        Assert.False(IpcAuthToken.ValidateToken(token1, null));
    }

    [Fact]
    public void IpcAuthToken_LoadOrCreateToken_PersistsToDisk()
    {
        string tempDir = Path.Combine(Path.GetTempPath(), $"exescope_test_{Guid.NewGuid():N}");
        Directory.CreateDirectory(tempDir);
        string tokenPath = Path.Combine(tempDir, "agent.token");

        try
        {
            string token = IpcAuthToken.LoadOrCreateToken(tokenPath);
            Assert.True(File.Exists(tokenPath));
            string read = File.ReadAllText(tokenPath).Trim();
            Assert.Equal(token, read);

            string secondLoad = IpcAuthToken.LoadOrCreateToken(tokenPath);
            Assert.Equal(token, secondLoad);
        }
        finally
        {
            try { Directory.Delete(tempDir, true); } catch { }
        }
    }
}
