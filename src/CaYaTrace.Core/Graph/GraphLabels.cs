using CaYaTrace.Core.Model;

namespace CaYaTrace.Core.Graph;

/// <summary>
/// Stable, language-neutral labels for action groups in the causal tree.
/// </summary>
/// <remarks>
/// These are intentionally not translated. They are terse operation names an analyst
/// recognises across tools (Procmon, Sysmon, Wireshark) and they appear verbatim in
/// exports, so keeping them fixed makes reports diffable and searchable regardless of
/// the UI language. Surrounding prose is localized; these tokens are not.
/// </remarks>
public static class GraphLabels
{
    public static string Describe(EventCategory category, EventAction action) => action switch
    {
        EventAction.Start => "PROCESS CREATE",
        EventAction.Stop => "PROCESS EXIT",
        EventAction.ImageLoad => "MODULE LOAD",
        EventAction.RemoteThread => "REMOTE THREAD",
        EventAction.MemoryWrite => "MEMORY WRITE",
        EventAction.TokenChange => "TOKEN CHANGE",

        EventAction.FileCreate => "FILE CREATE",
        EventAction.FileWrite => "FILE WRITE",
        EventAction.FileRead => "FILE READ",
        EventAction.FileDelete => "FILE DELETE",
        EventAction.FileRename => "FILE RENAME",
        EventAction.FileSetInfo => "FILE MODIFY",
        EventAction.FileSetSecurity => "FILE ACL CHANGE",
        EventAction.DirectoryCreate => "DIRECTORY CREATE",
        EventAction.DirectoryDelete => "DIRECTORY DELETE",
        EventAction.HardLinkCreate => "HARDLINK CREATE",
        EventAction.FileOpen => "FILE OPEN",

        EventAction.KeyCreate => "REGISTRY KEY CREATE",
        EventAction.KeyOpen => "REGISTRY KEY OPEN",
        EventAction.KeyDelete => "REGISTRY KEY DELETE",
        EventAction.KeyRename => "REGISTRY KEY RENAME",
        EventAction.ValueSet => "REGISTRY SET",
        EventAction.ValueDelete => "REGISTRY VALUE DELETE",
        EventAction.KeySetSecurity => "REGISTRY ACL CHANGE",

        EventAction.ServiceInstall => "SERVICE CREATE",
        EventAction.ServiceModify => "SERVICE MODIFY",
        EventAction.ServiceDelete => "SERVICE DELETE",
        EventAction.ServiceStart => "SERVICE START",
        EventAction.ServiceStop => "SERVICE STOP",

        EventAction.TaskRegister => "SCHEDULED TASK CREATE",
        EventAction.TaskModify => "SCHEDULED TASK MODIFY",
        EventAction.TaskDelete => "SCHEDULED TASK DELETE",

        EventAction.AutorunAdd => "AUTORUN ADD",
        EventAction.AutorunModify => "AUTORUN MODIFY",
        EventAction.AutorunRemove => "AUTORUN REMOVE",

        EventAction.DriverLoad => "DRIVER LOAD",
        EventAction.FirewallRuleAdd => "FIREWALL RULE ADD",
        EventAction.FirewallRuleRemove => "FIREWALL RULE REMOVE",
        EventAction.WmiConsumerCreate => "WMI CONSUMER CREATE",
        EventAction.WmiFilterCreate => "WMI FILTER CREATE",

        EventAction.Connect => "CONNECT",
        EventAction.Accept => "ACCEPT",
        EventAction.Listen => "LISTEN",
        EventAction.Disconnect => "DISCONNECT",
        EventAction.Send => "SEND",
        EventAction.Receive => "RECEIVE",

        EventAction.DnsQuery => "DNS",
        EventAction.DnsResponse => "DNS RESPONSE",

        EventAction.TlsClientHello => "TLS CLIENT HELLO",
        EventAction.TlsServerHello => "TLS SERVER HELLO",
        EventAction.TlsHandshakeComplete => "TLS",
        EventAction.TlsAlert => "TLS ALERT",

        EventAction.HttpRequest => category == EventCategory.Http ? "HTTP(S)" : "HTTP",
        EventAction.HttpResponse => "HTTP RESPONSE",
        EventAction.WebSocketMessage => "WEBSOCKET",

        EventAction.SessionStart => "SESSION START",
        EventAction.SessionStop => "SESSION STOP",
        EventAction.SnapshotTaken => "SNAPSHOT",
        EventAction.CollectorFault => "COLLECTOR FAULT",
        EventAction.DataLoss => "DATA LOSS",
        EventAction.UserAnnotation => "NOTE",

        _ => category.ToString().ToUpperInvariant(),
    };
}
