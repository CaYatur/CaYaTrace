using System.Security.Cryptography;
using System.Text;

namespace CaYaTrace.Fleet;

/// <summary>
/// The one-time code that pairs an agent with a host.
/// </summary>
/// <remarks>
/// <para>
/// The code is the whole of the authentication, so its entropy is the security of the
/// channel. Twelve characters from a 32-symbol alphabet is 60 bits — far beyond
/// guessing across a lab network, and still short enough to read aloud or type into a
/// VM console.
/// </para>
/// <para>
/// The alphabet excludes the characters people mistype when transcribing between
/// machines: I, L, O, U, 0, and 1. A pairing failure caused by a misread character
/// looks exactly like an attack, and that is a bad thing to make routine.
/// </para>
/// </remarks>
public static class PairingCode
{
    private const string Alphabet = "23456789ABCDEFGHJKMNPQRSTVWXYZ";

    private const int Length = 12;

    public static string Generate()
    {
        var code = new StringBuilder(Length + 2);
        for (int i = 0; i < Length; i++)
        {
            if (i > 0 && i % 4 == 0) code.Append('-');
            code.Append(Alphabet[RandomNumberGenerator.GetInt32(Alphabet.Length)]);
        }
        return code.ToString();
    }

    /// <summary>True when a string could be a pairing code, ignoring formatting.</summary>
    public static bool LooksValid(string? code)
    {
        if (code is null) return false;
        string normalized = SecureChannel.Normalize(code);
        return normalized.Length == Length && normalized.All(static c => Alphabet.Contains(c));
    }

    /// <summary>
    /// Estimated guessing difficulty, shown to the operator so the number is not just
    /// asserted.
    /// </summary>
    public static double EntropyBits => Length * Math.Log2(Alphabet.Length);
}
