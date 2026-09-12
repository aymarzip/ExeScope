using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using ExeScope.Core.Models;

namespace ExeScope.Core.Utilities;

public static class AuthenticodeHelper
{
    #region WinVerifyTrust P/Invoke Definitions

    private static readonly IntPtr INVALID_HANDLE_VALUE = new IntPtr(-1);
    private const string WINTRUST_ACTION_GENERIC_VERIFY_V2 = "{00AAC56B-CD44-11d0-8CC2-00C04FC295EE}";

    private const uint WTD_CHOICE_FILE = 1;
    private const uint WTD_STATEACTION_IGNORE = 0;
    private const uint WTD_UI_NONE = 2;
    private const uint WTD_REVOKE_NONE = 0;

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WINTRUST_FILE_INFO
    {
        public uint cbStruct;
        [MarshalAs(UnmanagedType.LPWStr)]
        public string pcwszFilePath;
        public IntPtr hFile;
        public IntPtr pgKnownSubject;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WINTRUST_DATA
    {
        public uint cbStruct;
        public IntPtr pPolicyCallbackData;
        public IntPtr pSIPClientData;
        public uint dwUIChoice;
        public uint fdwRevocationChecks;
        public uint dwUnionChoice;
        public IntPtr pFile;
        public uint dwStateAction;
        public IntPtr hWVTStateData;
        [MarshalAs(UnmanagedType.LPWStr)]
        public string? pwszURLReference;
        public uint dwProvFlags;
        public uint dwUIContext;
    }

    [DllImport("wintrust.dll", ExactSpelling = true, SetLastError = false, CharSet = CharSet.Unicode)]
    private static extern int WinVerifyTrust(
        [In] IntPtr hwnd,
        [In] [MarshalAs(UnmanagedType.LPStruct)] Guid pgActionID,
        [In] IntPtr pWVTData);

    #endregion

    public static TargetExeInfo InspectExecutable(string filePath)
    {
        var fileInfo = new FileInfo(filePath);
        var exeInfo = new TargetExeInfo
        {
            OriginalPath = filePath,
            CanonicalPath = PathSanitizer.NormalizeCanonicalPath(filePath),
            FileName = fileInfo.Name,
            FileSizeBytes = fileInfo.Exists ? fileInfo.Length : 0,
            CreationTimeUtc = fileInfo.Exists ? fileInfo.CreationTimeUtc : DateTime.UtcNow,
            LastWriteTimeUtc = fileInfo.Exists ? fileInfo.LastWriteTimeUtc : DateTime.UtcNow,
            SnapshotTimeUtc = DateTime.UtcNow
        };

        if (fileInfo.Exists)
        {
            try
            {
                exeInfo.Sha256 = HashHelper.ComputeSha256(filePath);
            }
            catch
            {
                exeInfo.Sha256 = "ERROR_COMPUTING_HASH";
            }

            // Inspect digital signature via .NET X509Certificate
            try
            {
#pragma warning disable SYSLIB0057 // Type or member is obsolete
                using var cert = new X509Certificate2(X509Certificate.CreateFromSignedFile(filePath));
#pragma warning restore SYSLIB0057
                exeInfo.IsSigned = true;
                exeInfo.SignerSubject = cert.Subject;
                exeInfo.SignerIssuer = cert.Issuer;
                exeInfo.CertificateThumbprint = cert.Thumbprint;

                // WinVerifyTrust check for trust chain validity
                int trustResult = VerifyTrustWin32(filePath);
                exeInfo.SignatureStatus = trustResult switch
                {
                    0 => "Valid (Trusted)",
                    unchecked((int)0x800B0109) => "Signed (Untrusted Root / Self-Signed)",
                    unchecked((int)0x800B0101) => "Signed (Expired Certificate)",
                    unchecked((int)0x800B0100) => "Signed (No Signature / Corrupted)",
                    _ => $"Signed (Code: 0x{trustResult:X8})"
                };
            }
            catch
            {
                exeInfo.IsSigned = false;
                exeInfo.SignatureStatus = "Unsigned / No Authenticode signature";
            }
        }
        else
        {
            exeInfo.SignatureStatus = "File not found";
        }

        return exeInfo;
    }

    private static int VerifyTrustWin32(string filePath)
    {
        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            return -1;

        try
        {
            var fileInfo = new WINTRUST_FILE_INFO
            {
                cbStruct = (uint)Marshal.SizeOf<WINTRUST_FILE_INFO>(),
                pcwszFilePath = filePath,
                hFile = IntPtr.Zero,
                pgKnownSubject = IntPtr.Zero
            };

            IntPtr pFileInfo = Marshal.AllocHGlobal(Marshal.SizeOf(fileInfo));
            try
            {
                Marshal.StructureToPtr(fileInfo, pFileInfo, false);

                var wvtData = new WINTRUST_DATA
                {
                    cbStruct = (uint)Marshal.SizeOf<WINTRUST_DATA>(),
                    pPolicyCallbackData = IntPtr.Zero,
                    pSIPClientData = IntPtr.Zero,
                    dwUIChoice = WTD_UI_NONE,
                    fdwRevocationChecks = WTD_REVOKE_NONE,
                    dwUnionChoice = WTD_CHOICE_FILE,
                    pFile = pFileInfo,
                    dwStateAction = WTD_STATEACTION_IGNORE,
                    hWVTStateData = IntPtr.Zero,
                    pwszURLReference = null,
                    dwProvFlags = 0x00000080, // WTD_CACHE_ONLY_URL_RETRIEVAL
                    dwUIContext = 0
                };

                IntPtr pWvtData = Marshal.AllocHGlobal(Marshal.SizeOf(wvtData));
                try
                {
                    Marshal.StructureToPtr(wvtData, pWvtData, false);
                    Guid actionGuid = new Guid(WINTRUST_ACTION_GENERIC_VERIFY_V2);
                    return WinVerifyTrust(INVALID_HANDLE_VALUE, actionGuid, pWvtData);
                }
                finally
                {
                    Marshal.FreeHGlobal(pWvtData);
                }
            }
            finally
            {
                Marshal.FreeHGlobal(pFileInfo);
            }
        }
        catch
        {
            return -1;
        }
    }
}
