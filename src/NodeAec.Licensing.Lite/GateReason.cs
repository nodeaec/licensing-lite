namespace NodeAec.Licensing;

/// <summary>
/// Why <see cref="Gate.Validate(string)"/> reached its decision. Exactly one value per
/// outcome, so a plugin can react to a specific case (for example, log it or pick its own
/// text) without parsing <see cref="Snapshot.Message"/>.
/// <para>
/// The numeric values are part of the contract: they never change and are never reused.
/// New reasons may be added in later versions, so a <c>switch</c> over this enum needs a
/// <c>default</c> branch. Branch the licensing decision on <see cref="Snapshot.IsLicensed"/>
/// only, never on this value.
/// </para>
/// </summary>
public enum GateReason
{
    /// <summary>The product holds an active, verified license on this computer.</summary>
    Licensed = 0,

    /// <summary>The plugin called the gate with an empty slug (a plugin bug, not a user problem).</summary>
    MissingProductSlug = 1,

    /// <summary>No lease on this computer: the user never signed in with the Connector here.</summary>
    NoLease = 2,

    /// <summary>The lease file exists but cannot be read as a lease.</summary>
    CorruptLease = 3,

    /// <summary>The lease signature does not check out against the compiled anchors (tampered or forged).</summary>
    SignatureInvalid = 4,

    /// <summary>The lease was not issued by the Node.aec platform (<c>iss</c>).</summary>
    UnknownIssuer = 5,

    /// <summary>The token is not a master lease (<c>scope</c>).</summary>
    UnsupportedFormat = 6,

    /// <summary>The token was not issued for plugins (<c>aud</c>).</summary>
    WrongAudience = 7,

    /// <summary>The lease was issued in the future: this computer's clock is wrong or was moved back.</summary>
    ClockInvalid = 8,

    /// <summary>The Windows <c>MachineGuid</c> cannot be read, so the machine binding cannot be checked.</summary>
    MachineIdUnavailable = 9,

    /// <summary>The lease belongs to another computer (<c>mid</c>).</summary>
    MachineMismatch = 10,

    /// <summary>The 30-day offline period ended: the Connector has not synchronized since.</summary>
    OfflineGraceExpired = 11,

    /// <summary>The lease has no readable deadline (<c>exp</c>).</summary>
    LeaseExpiryUnreadable = 12,

    /// <summary>The account has no license for this product.</summary>
    ProductNotFound = 13,

    /// <summary>The license is valid, but all of its computers (seats) are in use.</summary>
    SeatLimitReached = 14,

    /// <summary>The license or trial for this product ended.</summary>
    LicenseExpired = 15,

    /// <summary>The license exists but is not active (revoked, suspended, not granted, or another status).</summary>
    LicenseInactive = 16,

    /// <summary>An unexpected error happened while checking the lease.</summary>
    VerificationError = 17,
}

/// <summary>Language of the end-user text returned by <see cref="Snapshot.GetMessage(MessageLanguage)"/>.</summary>
public enum MessageLanguage
{
    /// <summary>Brazilian Portuguese, the language of <see cref="Snapshot.Message"/>.</summary>
    Portuguese = 0,

    /// <summary>English.</summary>
    English = 1,
}
