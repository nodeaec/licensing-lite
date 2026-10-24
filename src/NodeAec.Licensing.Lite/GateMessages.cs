using System;
using System.Globalization;

namespace NodeAec.Licensing;

/// <summary>
/// End-user text for each <see cref="GateReason"/>, in Portuguese and English. Each message
/// names the one specific reason and, where it applies, the next step. The Portuguese text
/// is the same as in earlier versions, because plugins may already show or compare it.
/// </summary>
internal static class GateMessages
{
    /// <summary>
    /// Builds the message for <paramref name="reason"/>.
    /// </summary>
    /// <param name="reason">Outcome of the gate.</param>
    /// <param name="language">Language of the text.</param>
    /// <param name="subject">Product slug (<see cref="GateReason.ProductNotFound"/>) or product name (license-level reasons).</param>
    /// <param name="status">Entitlement status (<see cref="GateReason.LicenseInactive"/>).</param>
    /// <param name="date">Deadline that passed (<see cref="GateReason.OfflineGraceExpired"/>, <see cref="GateReason.LicenseExpired"/>).</param>
    internal static string Format(GateReason reason, MessageLanguage language, string? subject, string? status, DateTimeOffset? date)
    {
        return language == MessageLanguage.English
            ? English(reason, subject, status, FormatDate(date, "MMM d, yyyy"))
            : Portuguese(reason, subject, status, FormatDate(date, "dd/MM/yyyy"));
    }

    private static string Portuguese(GateReason reason, string? subject, string? status, string date)
    {
        switch (reason)
        {
            case GateReason.Licensed: return "Licença ativa e verificada.";
            case GateReason.MissingProductSlug: return "Slug do produto não informado para validação.";
            case GateReason.NoLease: return "Nenhuma credencial do Node.aec encontrada nesta estação. Abra o Node.aec Connector na Ribbon para entrar com sua conta ou ativar sua licença.";
            case GateReason.CorruptLease: return "Concessão corrompida ou estrutura inválida. Abra o Node.aec Connector para ressincronizar.";
            case GateReason.SignatureInvalid: return "A licença local não passou na verificação de segurança. Conecte-se à internet e clique em atualizar no Node.aec Connector.";
            case GateReason.UnknownIssuer: return "Origem da licença local desconhecida. Conecte-se à internet e clique em atualizar no Node.aec Connector.";
            case GateReason.UnsupportedFormat: return "A licença local está em formato não suportado. Conecte-se à internet e clique em atualizar no Node.aec Connector.";
            case GateReason.WrongAudience: return "A licença local não foi emitida para este add-in. Conecte-se à internet e clique em atualizar no Node.aec Connector.";
            case GateReason.ClockInvalid: return "A data da licença local é inválida. Confira a data e hora deste computador e tente novamente.";
            case GateReason.MachineIdUnavailable: return "Não foi possível identificar esta máquina (MachineGuid do Windows indisponível). Contate o suporte Node.aec.";
            case GateReason.MachineMismatch: return "A concessão de licenças foi emitida para outra estação de trabalho (Hardware ID divergente).";
            case GateReason.OfflineGraceExpired: return $"O prazo de tolerância offline expirou em {date}. Conecte-se à internet para sincronizar.";
            case GateReason.LeaseExpiryUnreadable: return "O prazo da licença local não pôde ser lido. Conecte-se à internet e clique em atualizar no Node.aec Connector.";
            case GateReason.ProductNotFound: return $"O produto '{subject}' não consta nas licenças ativas desta conta. Adquira ou ative no catálogo Node.aec.";
            case GateReason.SeatLimitReached: return $"O limite de computadores simultâneos para '{subject}' foi atingido.";
            case GateReason.LicenseExpired: return $"A licença ou período de teste de '{subject}' expirou em {date}.";
            case GateReason.LicenseInactive: return $"A licença de '{subject}' está com status '{status}'.";
            default: return "Não foi possível verificar a licença local. Abra o Node.aec Connector para ressincronizar.";
        }
    }

    private static string English(GateReason reason, string? subject, string? status, string date)
    {
        switch (reason)
        {
            case GateReason.Licensed: return "License active and verified.";
            case GateReason.MissingProductSlug: return "No product slug was given for validation.";
            case GateReason.NoLease: return "No Node.aec credentials were found on this computer. Open the Node.aec Connector on the Ribbon to sign in or activate your license.";
            case GateReason.CorruptLease: return "The local license is corrupted or invalid. Open the Node.aec Connector to synchronize again.";
            case GateReason.SignatureInvalid: return "The local license failed the security check. Connect to the internet and click refresh in the Node.aec Connector.";
            case GateReason.UnknownIssuer: return "The local license comes from an unknown issuer. Connect to the internet and click refresh in the Node.aec Connector.";
            case GateReason.UnsupportedFormat: return "The local license is in an unsupported format. Connect to the internet and click refresh in the Node.aec Connector.";
            case GateReason.WrongAudience: return "The local license was not issued for this add-in. Connect to the internet and click refresh in the Node.aec Connector.";
            case GateReason.ClockInvalid: return "The local license date is invalid. Check this computer's date and time and try again.";
            case GateReason.MachineIdUnavailable: return "This computer could not be identified (Windows MachineGuid unavailable). Contact Node.aec support.";
            case GateReason.MachineMismatch: return "The licenses were issued for another computer (Hardware ID mismatch).";
            case GateReason.OfflineGraceExpired: return $"The offline grace period expired on {date}. Connect to the internet to synchronize.";
            case GateReason.LeaseExpiryUnreadable: return "The local license deadline could not be read. Connect to the internet and click refresh in the Node.aec Connector.";
            case GateReason.ProductNotFound: return $"The product '{subject}' is not among this account's active licenses. Buy or activate it in the Node.aec catalog.";
            case GateReason.SeatLimitReached: return $"All computers allowed for '{subject}' are already in use.";
            case GateReason.LicenseExpired: return $"The license or trial of '{subject}' expired on {date}.";
            case GateReason.LicenseInactive: return $"The license of '{subject}' has status '{status}'.";
            default: return "The local license could not be verified. Open the Node.aec Connector to synchronize again.";
        }
    }

    /// <summary>Invariant culture keeps the text identical on every Windows locale.</summary>
    private static string FormatDate(DateTimeOffset? date, string format) =>
        date?.ToString(format, CultureInfo.InvariantCulture) ?? string.Empty;
}
