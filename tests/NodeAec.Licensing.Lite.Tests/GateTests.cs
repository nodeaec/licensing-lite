using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using NodeAec.Licensing.Models;
using NodeAec.Licensing.Storage;
using Xunit;

namespace NodeAec.Licensing.Lite.Tests;

/// <summary>
/// Gate de ponta a ponta: cada caso instala exatamente um lease e afirma a decisão.
/// Estratégia anti-DPAPI (SSH Session 0 não tem DPAPI de usuário — <c>Protect</c> devolve
/// win32 5): tenta o round-trip real em arquivo (produção fiel); se proteger ou reler
/// falhar, injeta o JWT em memória via <c>UseTestLeaseForTests</c> e segue — a decisão
/// do <c>Gate</c> é idêntica nos dois caminhos, só muda o transporte.
/// </summary>
public class GateTests : IDisposable
{
    private readonly string _tempDir;
    private readonly IDisposable _anchor;
    private readonly IDisposable _machineGuid;

    public GateTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), "NodeAecLiteGateTests_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_tempDir);
        LeaseStorage.SetCustomBasePath(_tempDir);
        _anchor = TestHelpers.WithTestAnchor();
        _machineGuid = TestHelpers.WithMachineGuid(TestHelpers.TestMachineGuid);
    }

    public void Dispose()
    {
        _machineGuid.Dispose();
        _anchor.Dispose();
        LeaseStorage.ClearTestLeaseOverride();
        LeaseStorage.SetCustomBasePath(null);
        if (Directory.Exists(_tempDir))
        {
            try { Directory.Delete(_tempDir, true); } catch { }
        }
    }

    /// <summary>
    /// Instala o lease: prefere arquivo DPAPI real; cai para override em memória quando
    /// o DPAPI está indisponível (SSH Session 0 / CI sem logon).
    /// </summary>
    private static void InstallLease(string jwt)
    {
        try
        {
            byte[] blob = ProtectedData.Protect(
                Encoding.UTF8.GetBytes(jwt), null, DataProtectionScope.CurrentUser);
            LeaseStorage.WriteAllBytesAtomic(LeaseStorage.GetLeaseFilePath(), blob);
            if (LeaseStorage.LoadMasterLease() != null)
            {
                return; // round-trip DPAPI OK: caminho fiel ao de produção.
            }
        }
        catch (Exception)
        {
            // Protect indisponível (Session 0, não-Windows): cai para memória abaixo.
        }

        LeaseStorage.UseTestLeaseForTests(jwt);
    }

    private static List<EntitlementItem> EntitlementsWith(Action<EntitlementItem> mutate)
    {
        var list = TestHelpers.DefaultEntitlements();
        mutate(list[0]);
        return list;
    }

    [Fact]
    public void ValidLease_Releases()
    {
        InstallLease(TestHelpers.CreateMasterLeaseJwt());

        var snapshot = Gate.Validate(TestHelpers.TestSlug);

        Assert.True(snapshot.IsLicensed);
        Assert.Equal("Revit Automator", snapshot.ProductName);
        Assert.Equal("perpetual", snapshot.LicenseType);
        Assert.Equal("NAEC-TEST-1", snapshot.LicenseKey);
        Assert.Null(snapshot.ExpiresAt); // sem claim expiresAt no item = perpétuo.
        Assert.Equal(GateReason.Licensed, snapshot.Reason);
        Assert.Equal("Licença ativa e verificada.", snapshot.Message);
        Assert.Equal("License active and verified.", snapshot.GetMessage(MessageLanguage.English));
    }

    [Fact]
    public void ValidLease_SlugMatchingIsTrimmedCaseInsensitive()
    {
        InstallLease(TestHelpers.CreateMasterLeaseJwt());

        Assert.True(Gate.Validate("  REVIT-AUTOMATOR ").IsLicensed);
    }

    [Fact]
    public void WrongSignature_Denies()
    {
        string jwt = TestHelpers.CreateMasterLeaseJwt(
            privateKey: TestHelpers.AttackerPrivateKey("attacker-seed"));
        InstallLease(jwt);

        var snapshot = Gate.Validate(TestHelpers.TestSlug);

        Assert.False(snapshot.IsLicensed);
        Assert.Contains("verificação de segurança", snapshot.Message);
        Assert.Equal(GateReason.SignatureInvalid, snapshot.Reason);
    }

    [Fact]
    public void TamperedPayload_Denies()
    {
        string jwt = TestHelpers.CreateMasterLeaseJwt();
        string[] parts = jwt.Split('.');
        char first = parts[1][0];
        string tamperedPayload = (first == 'A' ? 'B' : 'A') + parts[1].Substring(1);
        InstallLease($"{parts[0]}.{tamperedPayload}.{parts[2]}");

        var snapshot = Gate.Validate(TestHelpers.TestSlug);

        Assert.False(snapshot.IsLicensed);
        // Depending on the flipped byte the payload stops being JSON (read before the
        // signature) or stays JSON and fails the signature check.
        Assert.Contains(snapshot.Reason, new[] { GateReason.CorruptLease, GateReason.SignatureInvalid });
    }

    [Fact]
    public void WrongIss_Denies()
    {
        InstallLease(TestHelpers.CreateMasterLeaseJwt(iss: "evil-issuer"));

        var snapshot = Gate.Validate(TestHelpers.TestSlug);

        Assert.False(snapshot.IsLicensed);
        Assert.Contains("Origem", snapshot.Message);
        Assert.Equal(GateReason.UnknownIssuer, snapshot.Reason);
    }

    [Fact]
    public void WrongScope_Denies()
    {
        InstallLease(TestHelpers.CreateMasterLeaseJwt(scope: "user-session"));

        var snapshot = Gate.Validate(TestHelpers.TestSlug);

        Assert.False(snapshot.IsLicensed);
        Assert.Contains("formato não suportado", snapshot.Message);
        Assert.Equal(GateReason.UnsupportedFormat, snapshot.Reason);
    }

    [Theory]
    [InlineData("node-aec-api")]
    [InlineData("outro-produto")]
    public void WrongAud_Denies(string aud)
    {
        InstallLease(TestHelpers.CreateMasterLeaseJwt(aud: aud));

        var snapshot = Gate.Validate(TestHelpers.TestSlug);

        Assert.False(snapshot.IsLicensed);
        Assert.Contains("não foi emitida para este add-in", snapshot.Message);
        Assert.Equal(GateReason.WrongAudience, snapshot.Reason);
    }

    [Fact]
    public void MissingAud_Denies()
    {
        InstallLease(TestHelpers.CreateMasterLeaseJwt(omitAud: true));

        var snapshot = Gate.Validate(TestHelpers.TestSlug);

        Assert.False(snapshot.IsLicensed);
        Assert.Equal(GateReason.WrongAudience, snapshot.Reason);
    }

    [Fact]
    public void FutureIat_BeyondSkew_Denies()
    {
        long iat = DateTimeOffset.UtcNow.ToUnixTimeSeconds() + 600;
        InstallLease(TestHelpers.CreateMasterLeaseJwt(iatOverride: iat));

        var snapshot = Gate.Validate(TestHelpers.TestSlug);

        Assert.False(snapshot.IsLicensed);
        Assert.Contains("data da licença", snapshot.Message);
        Assert.Equal(GateReason.ClockInvalid, snapshot.Reason);
    }

    [Fact]
    public void WrongMid_Denies()
    {
        InstallLease(TestHelpers.CreateMasterLeaseJwt(mid: TestHelpers.Sha256HexLower("outra-maquina")));

        var snapshot = Gate.Validate(TestHelpers.TestSlug);

        Assert.False(snapshot.IsLicensed);
        Assert.Contains("outra estação", snapshot.Message);
        Assert.Equal(GateReason.MachineMismatch, snapshot.Reason);
    }

    [Fact]
    public void PastExp_Denies()
    {
        InstallLease(TestHelpers.CreateMasterLeaseJwt(expiresAt: DateTimeOffset.UtcNow.AddDays(-1)));

        var snapshot = Gate.Validate(TestHelpers.TestSlug);

        Assert.False(snapshot.IsLicensed);
        Assert.Contains("expirou em", snapshot.Message);
        Assert.Equal(GateReason.OfflineGraceExpired, snapshot.Reason);
    }

    [Fact]
    public void UnreadableExp_Denies()
    {
        // exp=0 (ausente): IsExpired é true e ExpiresAt é null → mensagem de prazo ilegível.
        InstallLease(TestHelpers.CreateMasterLeaseJwt(expOverride: 0));

        var snapshot = Gate.Validate(TestHelpers.TestSlug);

        Assert.False(snapshot.IsLicensed);
        Assert.Contains("não pôde ser lido", snapshot.Message);
        Assert.Equal(GateReason.LeaseExpiryUnreadable, snapshot.Reason);
    }

    [Fact]
    public void MissingSlug_Denies()
    {
        InstallLease(TestHelpers.CreateMasterLeaseJwt(entitlements: new List<EntitlementItem>
        {
            new() { Slug = "outro-produto", Name = "Outro", Status = "active" },
        }));

        var snapshot = Gate.Validate(TestHelpers.TestSlug);

        Assert.False(snapshot.IsLicensed);
        Assert.Contains("não consta", snapshot.Message);
        Assert.Equal(GateReason.ProductNotFound, snapshot.Reason);
    }

    [Fact]
    public void GrantedFalse_Denies()
    {
        InstallLease(TestHelpers.CreateMasterLeaseJwt(
            entitlements: EntitlementsWith(e => e.Granted = false)));

        var snapshot = Gate.Validate(TestHelpers.TestSlug);

        Assert.False(snapshot.IsLicensed);
        Assert.Null(snapshot.ProductName);
        Assert.Contains("licença de", snapshot.Message);
        Assert.Equal(GateReason.LicenseInactive, snapshot.Reason);
    }

    [Theory]
    [InlineData("suspended")]
    [InlineData("revoked")]
    [InlineData("expired")]
    public void InactiveStatus_Denies(string status)
    {
        InstallLease(TestHelpers.CreateMasterLeaseJwt(
            entitlements: EntitlementsWith(e => e.Status = status)));

        var snapshot = Gate.Validate(TestHelpers.TestSlug);

        Assert.False(snapshot.IsLicensed);
        Assert.Null(snapshot.ProductName);
        Assert.Equal(GateReason.LicenseInactive, snapshot.Reason);
        Assert.Contains($"'{status}'", snapshot.GetMessage(MessageLanguage.English));
    }

    [Fact]
    public void SeatLimitReached_DeniesWithDedicatedMessage()
    {
        InstallLease(TestHelpers.CreateMasterLeaseJwt(
            entitlements: EntitlementsWith(e => e.Status = "seat_limit_reached")));

        var snapshot = Gate.Validate(TestHelpers.TestSlug);

        Assert.False(snapshot.IsLicensed);
        Assert.Contains("limite de computadores", snapshot.Message);
        Assert.Equal(GateReason.SeatLimitReached, snapshot.Reason);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void EmptySlug_Denies(string? slug)
    {
        InstallLease(TestHelpers.CreateMasterLeaseJwt());

        var snapshot = Gate.Validate(slug!);

        Assert.False(snapshot.IsLicensed);
        Assert.Contains("Slug do produto", snapshot.Message);
        Assert.Equal(GateReason.MissingProductSlug, snapshot.Reason);
    }

    [Fact]
    public void NoLease_Denies()
    {
        var snapshot = Gate.Validate(TestHelpers.TestSlug);

        Assert.False(snapshot.IsLicensed);
        Assert.Contains("Nenhuma credencial", snapshot.Message);
        Assert.Equal(GateReason.NoLease, snapshot.Reason);
    }

    [Fact]
    public void InMemoryLeaseOverride_BypassesFileAndDpapi()
    {
        // Caminho SSH Session 0: sem arquivo e sem DPAPI, o override em memória decide.
        // Nenhum InstallLease aqui — o diretório temp está vazio de propósito.
        LeaseStorage.UseTestLeaseForTests(TestHelpers.CreateMasterLeaseJwt());
        try
        {
            var snapshot = Gate.Validate(TestHelpers.TestSlug);

            Assert.True(snapshot.IsLicensed);
        }
        finally
        {
            LeaseStorage.ClearTestLeaseOverride();
        }
    }

    [Fact]
    public void ExpiredLicense_NamesProductAndDateInBothLanguages()
    {
        var expired = new DateTimeOffset(2026, 3, 5, 12, 0, 0, TimeSpan.Zero);
        InstallLease(TestHelpers.CreateMasterLeaseJwt(
            entitlements: EntitlementsWith(e =>
            {
                e.Status = "expired";
                e.ExpiresAtString = expired.ToString("o");
            })));

        var snapshot = Gate.Validate(TestHelpers.TestSlug);

        Assert.Equal(GateReason.LicenseExpired, snapshot.Reason);
        Assert.Equal("A licença ou período de teste de 'Revit Automator' expirou em 05/03/2026.", snapshot.Message);
        Assert.Equal("The license or trial of 'Revit Automator' expired on Mar 5, 2026.", snapshot.GetMessage(MessageLanguage.English));
    }

    [Fact]
    public void ProductNotFound_EnglishNamesTheRequestedSlug()
    {
        InstallLease(TestHelpers.CreateMasterLeaseJwt(entitlements: new List<EntitlementItem>
        {
            new() { Slug = "outro-produto", Name = "Outro", Status = "active" },
        }));

        var snapshot = Gate.Validate(TestHelpers.TestSlug);

        Assert.Equal(
            $"The product '{TestHelpers.TestSlug}' is not among this account's active licenses. Buy or activate it in the Node.aec catalog.",
            snapshot.GetMessage(MessageLanguage.English));
    }

    [Fact]
    public void EveryReason_HasAPortugueseAndAnEnglishMessage()
    {
        foreach (GateReason reason in Enum.GetValues(typeof(GateReason)))
        {
            string pt = GateMessages.Format(reason, MessageLanguage.Portuguese, "x", "y", DateTimeOffset.UtcNow);
            string en = GateMessages.Format(reason, MessageLanguage.English, "x", "y", DateTimeOffset.UtcNow);

            Assert.False(string.IsNullOrWhiteSpace(pt), reason.ToString());
            Assert.False(string.IsNullOrWhiteSpace(en), reason.ToString());
            Assert.NotEqual(pt, en);
            if (reason != GateReason.VerificationError)
            {
                // Only the unexpected-error case may fall through to the default text.
                Assert.NotEqual(GateMessages.Format(GateReason.VerificationError, MessageLanguage.English, "x", "y", null), en);
            }
        }
    }

    [Fact]
    public void ReasonValues_AreStable()
    {
        // The numbers are contract: plugins may persist or log them.
        Assert.Equal(0, (int)GateReason.Licensed);
        Assert.Equal(2, (int)GateReason.NoLease);
        Assert.Equal(11, (int)GateReason.OfflineGraceExpired);
        Assert.Equal(13, (int)GateReason.ProductNotFound);
        Assert.Equal(17, (int)GateReason.VerificationError);
        Assert.Equal(18, Enum.GetValues(typeof(GateReason)).Length);
    }

    [Fact]
    public void LegacyFactories_KeepTheirFixedText()
    {
        var failure = Snapshot.Failure("texto fixo");
        Assert.False(failure.IsLicensed);
        Assert.Equal(GateReason.VerificationError, failure.Reason);
        Assert.Equal("texto fixo", failure.GetMessage(MessageLanguage.English));

        var success = Snapshot.Success("perpetual", null, "P", null);
        Assert.True(success.IsLicensed);
        Assert.Equal("License active and verified.", success.GetMessage(MessageLanguage.English));
    }
}
