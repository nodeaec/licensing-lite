using System;
using NodeAec.Licensing.Cryptography;
using Xunit;

namespace NodeAec.Licensing.Lite.Tests;

/// <summary>
/// Âncora de teste: prova que o hook <c>UseTestAnchorForTests</c> troca a âncora sem
/// tocar na âncora real de release (que permanece compilada e nunca é privada aqui).
/// </summary>
public class VerifierAnchorTests : IDisposable
{
    private readonly IDisposable _anchor;

    public VerifierAnchorTests()
    {
        _anchor = TestHelpers.WithTestAnchor();
    }

    public void Dispose() => _anchor.Dispose();

    [Fact]
    public void TestAnchor_VerifiesTestSignedToken()
    {
        string jwt = TestHelpers.CreateMasterLeaseJwt();

        Assert.True(LeaseSignatureVerifier.TryVerify(jwt, out string? reason), reason);
    }

    [Fact]
    public void TestAnchor_RejectsUnknownKey()
    {
        string jwt = TestHelpers.CreateMasterLeaseJwt(
            privateKey: TestHelpers.AttackerPrivateKey("attacker-seed"));

        Assert.Equal(
            LeaseSignatureVerifier.VerificationOutcome.Rejected,
            LeaseSignatureVerifier.Evaluate(jwt, out _));
    }

    [Fact]
    public void InvalidAnchorOverride_FailsClosedWithNoKeysAvailable()
    {
        LeaseSignatureVerifier.UseTestAnchorForTests("não-é-base64!!");
        try
        {
            string jwt = TestHelpers.CreateMasterLeaseJwt();

            Assert.Equal(
                LeaseSignatureVerifier.VerificationOutcome.NoKeysAvailable,
                LeaseSignatureVerifier.Evaluate(jwt, out string? reason));
            Assert.Contains("âncora", reason);
        }
        finally
        {
            LeaseSignatureVerifier.UseTestAnchorForTests(TestHelpers.TestAnchorSpkiBase64);
        }
    }

    [Fact]
    public void RealCompiledAnchor_RejectsTestSignedToken()
    {
        // Guarda de direção: sem o hook, a âncora real de release NÃO confirma tokens de
        // teste — o override é o único caminho pelo qual eles verificam.
        LeaseSignatureVerifier.ClearTestAnchorOverride();
        try
        {
            Assert.False(LeaseSignatureVerifier.TryVerify(
                TestHelpers.CreateMasterLeaseJwt(), out _));
        }
        finally
        {
            LeaseSignatureVerifier.UseTestAnchorForTests(TestHelpers.TestAnchorSpkiBase64);
        }
    }
}
