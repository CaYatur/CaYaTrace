using CaYaTrace.Analysis.Persistence;
using CaYaTrace.Core.Model;
using Xunit;

namespace CaYaTrace.Tests;

/// <summary>
/// The recovery-action decoder, checked against what Windows itself reports.
/// </summary>
/// <remarks>
/// Every case here is a real value read from this machine's registry, paired with what
/// <c>sc qfailure</c> printed for the same service. The layout is easy to get wrong by one
/// header field and the failure mode is a plausible-looking wrong number, so the test is
/// written against measured pairs rather than against the documentation.
/// </remarks>
public sealed class ServiceFailureActionsTests
{
    /// <summary>
    /// <c>sc qfailure Spooler</c>: reset 3600 s, RESTART at 5000 ms, RESTART at 5000 ms.
    /// </summary>
    [Fact]
    public void DecodesTheSpoolerRecoveryPlan()
    {
        ServiceRecovery? recovery = ServiceFailureActions.DecodeHex(
            "100e000000000000000000000300000014000000010000008813000001000000881300000000000000000000");

        Assert.NotNull(recovery);
        Assert.Equal(3600, recovery!.ResetPeriodSeconds);
        Assert.Equal(2, recovery.Actions.Count);
        Assert.All(recovery.Actions, a => Assert.Equal(ServiceRecoveryActionType.Restart, a.Type));
        Assert.All(recovery.Actions, a => Assert.Equal(5000, a.DelayMilliseconds));
        Assert.True(recovery.RestartsOnFailure);
    }

    /// <summary>
    /// <c>sc qfailure WSearch</c>: reset 86400 s, five restarts at 30000 ms.
    /// </summary>
    /// <remarks>
    /// The count field says six. The sixth entry is of type None, which is padding — and
    /// dropping it is what <c>sc</c> does too. A decoder that trusted the count would report
    /// a sixth action that does not exist.
    /// </remarks>
    [Fact]
    public void DropsThePaddingActionsWindowsLeavesBehind()
    {
        ServiceRecovery? recovery = ServiceFailureActions.DecodeHex(
            "8051010000000000000000000600000014000000010000003075000001000000307500000100000030750000"
            + "010000003075000001000000307500000000000000000000");

        Assert.NotNull(recovery);
        Assert.Equal(86400, recovery!.ResetPeriodSeconds);
        Assert.Equal(5, recovery.Actions.Count);
        Assert.All(recovery.Actions, a => Assert.Equal(30000, a.DelayMilliseconds));
    }

    /// <summary>
    /// <c>sc qfailure BITS</c>: one restart at 60 s, then one at 120 s.
    /// </summary>
    [Fact]
    public void KeepsTheOrderAndTheDifferentDelays()
    {
        ServiceRecovery? recovery = ServiceFailureActions.DecodeHex(
            "80510100000000000000000003000000140000000100000060ea000001000000c0d401000000000000000000");

        Assert.NotNull(recovery);
        Assert.Equal(2, recovery!.Actions.Count);
        Assert.Equal(60000, recovery.Actions[0].DelayMilliseconds);
        Assert.Equal(120000, recovery.Actions[1].DelayMilliseconds);
        Assert.Contains("60", ServiceFailureActions.Describe(recovery));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("00")]
    [InlineData("zzzz")]
    [InlineData("100e00000000000000000000ff00000014000000")]   // action count past the buffer
    public void RefusesRatherThanGuessing(string? blob)
    {
        // A wrong restart delay in a report is worse than an honest gap, and the removal
        // planner uses this value to decide what it has to disarm first.
        Assert.Null(ServiceFailureActions.DecodeHex(blob));
    }
}

/// <summary>
/// Finding the ways a program arranged to run again.
/// </summary>
/// <remarks>
/// Measured starting point: a session holding 33,467 registry observations produced zero
/// registry findings, while a comparison tool on the same machine reported the two
/// services the subject installed with their full configuration.
/// </remarks>
public sealed class PersistenceAnalyzerTests
{
    private static Observation Registry(string key, string? value, string? data, long seq = 1) => new()
    {
        Seq = seq,
        Timestamp = new DateTimeOffset(2026, 8, 12, 14, 20, 0, TimeSpan.Zero),
        Category = EventCategory.Registry,
        Action = EventAction.ValueSet,
        Actor = new ProcessKey(4321, 0xBEEF, 0),
        Target = key,
        Target2 = value,
        NewValue = data,
        Source = EvidenceSource.KernelEtw,
        Confidence = AttributionConfidence.Direct,
    };

    /// <summary>
    /// A service installation is one entry carrying its values, not eight entries.
    /// </summary>
    /// <remarks>
    /// Values taken from the real sample: a service named with sixteen hex characters,
    /// a display name that is also sixteen hex characters, running as LocalSystem from a
    /// generated filename inside the Windows directory.
    /// </remarks>
    [Fact]
    public void AServiceInstallationIsOneRecordWithItsValues()
    {
        const string Key = @"HKLM\SYSTEM\ControlSet001\Services\bf6e56533c2749ec";

        var observations = new[]
        {
            Registry(Key, "Type", "16", 1),
            Registry(Key, "Start", "2", 2),
            Registry(Key, "ErrorControl", "0", 3),
            Registry(Key, "ImagePath", @"C:\WINDOWS\SysWOW64\7487\04efe9c6e3eb023f.exe", 4),
            Registry(Key, "DisplayName", "63918fc1c9ecbbd4", 5),
            Registry(Key, "ObjectName", "LocalSystem", 6),
        };

        PersistenceRecord record = Assert.Single(new PersistenceAnalyzer().Analyze(observations));

        Assert.Equal(PersistenceKind.Service, record.Kind);
        Assert.Equal("bf6e56533c2749ec", record.Identity);
        Assert.Equal(@"C:\WINDOWS\SysWOW64\7487\04efe9c6e3eb023f.exe", record.Command);
        Assert.Equal("63918fc1c9ecbbd4", record.DisplayName);
        Assert.Equal(6, record.Values.Count);

        // The decoded configuration, in words, is the thing the comparison tool gave the
        // analyst and we did not.
        Assert.Contains(record.Traits, t => t.Contains("starts automatically"));
        Assert.Contains(record.Traits, t => t.Contains("LocalSystem"));
        Assert.Contains(record.Reasons, r => r.Contains("generated string"));
    }

    /// <summary>
    /// The control set the kernel reports and the one rules are written against.
    /// </summary>
    /// <remarks>
    /// Kernel events say <c>ControlSet001</c>; every rule anyone writes says
    /// <c>CurrentControlSet</c>. This exact mismatch already caused the removal policy's
    /// protected-service list to match nothing at all.
    /// </remarks>
    [Theory]
    [InlineData(@"HKLM\SYSTEM\ControlSet001\Services\WinDelay")]
    [InlineData(@"HKLM\SYSTEM\ControlSet002\Services\WinDelay")]
    [InlineData(@"HKLM\SYSTEM\CurrentControlSet\Services\WinDelay")]
    public void FindsAServiceWhicheverControlSetItWasReportedUnder(string key)
    {
        PersistenceRecord record = Assert.Single(new PersistenceAnalyzer()
            .Analyze(new[] { Registry(key, "ImagePath", @"C:\WINDOWS\system32\windelayer.exe") }));

        Assert.Equal(PersistenceKind.Service, record.Kind);
        Assert.Equal("WinDelay", record.Identity);
    }

    /// <summary>
    /// The Background Activity Moderator is not a service someone installed.
    /// </summary>
    /// <remarks>
    /// It is where Windows records that a program ran, it lives under <c>\Services\</c>, and
    /// it was the single busiest registry path in a real capture. A rule that merely
    /// contains "\Services\" reports a service called "bam" on every machine it ever sees
    /// — and the removal policy already had to learn this lesson once.
    /// </remarks>
    [Fact]
    public void ActivityRecordsAreNotPersistence()
    {
        var observations = new[]
        {
            Registry(
                @"HKLM\SYSTEM\ControlSet001\Services\bam\State\UserSettings\S-1-5-21-3023131402-199173579-3080135376-1000",
                @"\Device\HarddiskVolume3\Users\PC\Desktop\e-Kilit Kurulum (Windows).exe",
                "0c1136b3502add01"),
        };

        Assert.Empty(new PersistenceAnalyzer().Analyze(observations));
    }

    /// <summary>
    /// A delayed automatic service that restarts itself is worth saying so about.
    /// </summary>
    /// <remarks>
    /// Both properties come from the real sample. Delayed start is how something arranges
    /// to come up after whatever would have noticed it, and the recovery actions are why
    /// stopping it by hand does not work — which is exactly what the removal planner needs
    /// to be told before it starts.
    /// </remarks>
    [Fact]
    public void ReadsDelayedStartAndSelfRestart()
    {
        const string Key = @"HKLM\SYSTEM\CurrentControlSet\Services\WinDelay";

        var observations = new[]
        {
            Registry(Key, "Start", "2", 1),
            Registry(Key, "DelayedAutostart", "1", 2),
            Registry(Key, "ImagePath", @"C:\WINDOWS\system32\windelayer.exe", 3),
            Registry(Key, "FailureActions",
                "100e000000000000000000000300000014000000010000008813000001000000881300000000000000000000", 4),
        };

        PersistenceRecord record = Assert.Single(new PersistenceAnalyzer().Analyze(observations));

        Assert.True(record.RestartsItself);
        Assert.Contains(record.Traits, t => t.Contains("a little after boot"));
        Assert.Contains(record.Traits, t => t.Contains("restart after 5s"));
        Assert.Contains(record.Reasons, r => r.Contains("restarts itself"));
    }

    /// <summary>
    /// One installation is one record, however many ways it was observed.
    /// </summary>
    /// <remarks>
    /// Measured on a real capture of one service and one task: the service appeared twice
    /// and the task three times. The kernel reports whatever case the writer used, the
    /// inventory reports the bare name, the task's registry key is a GUID, its tree entry
    /// is the name shouted, and its on-disk record is the path. Four spellings, one thing.
    /// </remarks>
    [Fact]
    public void TheSameServiceSeenTwoWaysIsOneRecord()
    {
        IReadOnlyList<PersistenceRecord> records = new PersistenceAnalyzer().Analyze(new[]
        {
            // As the kernel reported it: shouted, under its registry key.
            Registry(@"HKLM\SYSTEM\ControlSet001\Services\CAYATRACEPROBESVC", "Start", "2", 1),
            Registry(@"HKLM\SYSTEM\ControlSet001\Services\CAYATRACEPROBESVC", "ImagePath",
                @"C:\ProgramData\Probe\a1b2c3d4.exe", 2),

            // As the before/after inventory reported it: the bare name, whole record.
            new Observation
            {
                Seq = 3,
                Timestamp = new DateTimeOffset(2026, 8, 12, 14, 20, 1, TimeSpan.Zero),
                Category = EventCategory.Service,
                Action = EventAction.ServiceInstall,
                Target = "CaYaTraceProbeSvc",
                Target2 = "service",
                Details = """{"Name":"CaYaTraceProbeSvc","DisplayName":"9f8e7d6c","ObjectName":"LocalSystem"}""",
                Source = EvidenceSource.SnapshotDiff,
                Confidence = AttributionConfidence.None,
            },
        });

        PersistenceRecord record = Assert.Single(records);

        // The readable spelling wins — it is what an operator will search for.
        Assert.Equal("CaYaTraceProbeSvc", record.Identity);

        // And both halves of the story survive the merge.
        Assert.Equal(@"C:\ProgramData\Probe\a1b2c3d4.exe", record.Command);
        Assert.Equal("9f8e7d6c", record.DisplayName);
        Assert.Contains(record.Traits, t => t.Contains("LocalSystem"));
    }

    /// <summary>
    /// A startup entry names the program it starts, not the key it lives in.
    /// </summary>
    /// <remarks>
    /// The inventory writes an autorun as one <c>key::value</c> string and the kernel
    /// reports the key and value separately. Measured: the same Run entry appeared twice,
    /// once called <c>CaYaTraceProbe</c> and once called
    /// <c>HKCU\…\Run::CaYaTraceProbe</c>, and neither said what it ran.
    /// </remarks>
    [Fact]
    public void AStartupEntryIsOneRecordThatNamesWhatItRuns()
    {
        const string Key = @"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run";

        IReadOnlyList<PersistenceRecord> records = new PersistenceAnalyzer().Analyze(new[]
        {
            Registry(Key, "CaYaTraceProbe", @"C:\ProgramData\Probe\rollcall.exe", 1),
            new Observation
            {
                Seq = 2,
                Timestamp = new DateTimeOffset(2026, 8, 12, 14, 20, 1, TimeSpan.Zero),
                Category = EventCategory.Autorun,
                Action = EventAction.AutorunAdd,
                Target = Key + "::CaYaTraceProbe",
                Target2 = "autorun",
                NewValue = @"C:\ProgramData\Probe\rollcall.exe",
                Source = EvidenceSource.SnapshotDiff,
                Confidence = AttributionConfidence.None,
            },
        });

        PersistenceRecord record = Assert.Single(records);
        Assert.Equal("CaYaTraceProbe", record.Identity);
        Assert.Equal(@"C:\ProgramData\Probe\rollcall.exe", record.Command);
    }

    /// <summary>
    /// A task says what it runs in exactly one place, and it is not the registry.
    /// </summary>
    [Fact]
    public void ATaskReportsTheProgramItRunsNotItsOwnName()
    {
        PersistenceRecord record = Assert.Single(new PersistenceAnalyzer().Analyze(new[]
        {
            new Observation
            {
                Seq = 1,
                Timestamp = new DateTimeOffset(2026, 8, 12, 14, 20, 0, TimeSpan.Zero),
                Category = EventCategory.ScheduledTask,
                Action = EventAction.TaskRegister,
                Target = @"\CaYaTraceProbeTask",
                Target2 = "task",
                Details = """
                    {"Path":"\\CaYaTraceProbeTask","Definition":"<?xml version=\"1.0\"?><Task><Actions><Exec><Command>C:\\ProgramData\\Probe\\rollcall.exe</Command><Arguments>-quiet</Arguments></Exec></Actions></Task>"}
                    """,
                Source = EvidenceSource.SnapshotDiff,
                Confidence = AttributionConfidence.None,
            },
        }));

        Assert.Equal(PersistenceKind.ScheduledTask, record.Kind);
        Assert.Equal(@"C:\ProgramData\Probe\rollcall.exe -quiet", record.Command);
    }

    /// <summary>
    /// A key that was created and left empty is not an installation.
    /// </summary>
    /// <remarks>
    /// Measured: an idle capture of a machine doing nothing produced four persistence
    /// entries — Explorer touching three CLSID keys and a service host touching the
    /// TCP/IP service — every one of them with no values and no command.
    /// </remarks>
    [Fact]
    public void AnEmptyKeyIsNotPersistence()
    {
        var observations = new[]
        {
            new Observation
            {
                Seq = 1,
                Timestamp = DateTimeOffset.UtcNow,
                Category = EventCategory.Registry,
                Action = EventAction.KeyCreate,
                Actor = new ProcessKey(999, 0xAAAA, 0),
                Target = @"HKLM\SOFTWARE\Classes\CLSID\{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}",
                Source = EvidenceSource.KernelEtw,
                Confidence = AttributionConfidence.Direct,
            },
        };

        Assert.Empty(new PersistenceAnalyzer().Analyze(observations));
    }

    /// <summary>Each value under a run key is its own entry; the key is not the subject.</summary>
    [Fact]
    public void RunKeyValuesAreSeparateEntries()
    {
        const string Key = @"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run";

        IReadOnlyList<PersistenceRecord> records = new PersistenceAnalyzer().Analyze(new[]
        {
            Registry(Key, "Updater", @"C:\Users\x\AppData\Roaming\u.exe", 1),
            Registry(Key, "Helper", @"C:\Users\x\AppData\Roaming\h.exe", 2),
        });

        Assert.Equal(2, records.Count);
        Assert.All(records, r => Assert.Equal(PersistenceKind.RunKey, r.Kind));
        Assert.Contains(records, r => r.Identity == "Updater");
        Assert.Contains(records, r => r.Identity == "Helper");
    }

    /// <summary>Windows stamping a counter into a key is not a configuration change.</summary>
    [Fact]
    public void CountersAndTimestampsAreNotConfiguration()
    {
        IReadOnlyList<PersistenceRecord> records = new PersistenceAnalyzer().Analyze(new[]
        {
            Registry(
                @"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{2CB3B1AF-907E-49EF-99E9-CFFEF6FB4BBE}",
                "DynamicInfo", "30006", 1),
        });

        Assert.Empty(records);
    }

    /// <summary>
    /// The scheduled task the subject registered, with what it actually runs.
    /// </summary>
    /// <remarks>
    /// The measured session reported four Windows Defender task <em>modifications</em> and
    /// missed the tasks the subject created. Actions is the value that answers "what does
    /// this task run", which is the only question worth asking of a task entry.
    /// </remarks>
    [Fact]
    public void FindsARegisteredTaskAndWhatItRuns()
    {
        const string Key =
            @"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{2CB3B1AF-907E-49EF-99E9-CFFEF6FB4BBE}";

        PersistenceRecord record = Assert.Single(new PersistenceAnalyzer().Analyze(new[]
        {
            Registry(Key, "Path", @"\e-Kilit\Informer", 1),
            Registry(Key, "Actions", @"C:\WINDOWS\SysWOW64\7669\Informer.exe", 2),
            Registry(Key, "DynamicInfo", "30006", 3),
        }));

        Assert.Equal(PersistenceKind.ScheduledTask, record.Kind);
        Assert.Equal(@"\e-Kilit\Informer", record.Command);

        // The churn value is dropped, the two real ones are kept.
        Assert.Equal(2, record.Values.Count);
        Assert.DoesNotContain(record.Values, v => v.Name == "DynamicInfo");
    }
}
