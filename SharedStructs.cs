// ============================================================================
// SharedStructs.cs - Shared.h의 C# 재정의
// ============================================================================
using System.Runtime.InteropServices;

namespace WfpControlApp.Models
{
    public static class IoctlCodes
    {
        private const uint FILE_DEVICE_UNKNOWN = 0x00000022;
        private const uint METHOD_BUFFERED = 0;
        private const uint FILE_ANY_ACCESS = 0;

        private static uint CTL_CODE(uint deviceType, uint function, uint method, uint access)
            => (deviceType << 16) | (access << 14) | (function << 2) | method;

        public static readonly uint IOCTL_WFP_SET_BLOCK_PID = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS);
        public static readonly uint IOCTL_WFP_TOGGLE_CAPTURE = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS);
        public static readonly uint IOCTL_WFP_GET_PACKET_BATCH = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS);
        public static readonly uint IOCTL_WFP_GET_CAPTURE_STATUS = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x804, METHOD_BUFFERED, FILE_ANY_ACCESS);
        public static readonly uint IOCTL_WFP_CLEAR_PACKET_QUEUE = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x805, METHOD_BUFFERED, FILE_ANY_ACCESS);
        public static readonly uint IOCTL_WFP_RESET_BLOCK_PID = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x806, METHOD_BUFFERED, FILE_ANY_ACCESS);

        public static readonly uint IOCTL_WFP_SNI_BLOCK_URL = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x810, METHOD_BUFFERED, FILE_ANY_ACCESS);
        public static readonly uint IOCTL_WFP_SNI_GET_BLOCK_LIST = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x811, METHOD_BUFFERED, FILE_ANY_ACCESS);
        public static readonly uint IOCTL_WFP_SNI_CLEAR_BLOCK_LIST = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x812, METHOD_BUFFERED, FILE_ANY_ACCESS);
        public static readonly uint IOCTL_WFP_SNI_TOGGLE_BLOCKING = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x813, METHOD_BUFFERED, FILE_ANY_ACCESS);

        public static readonly uint IOCTL_WFP_DNS_SINKHOLE_TOGGLE = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x830, METHOD_BUFFERED, FILE_ANY_ACCESS);
        public static readonly uint IOCTL_WFP_DNS_SINKHOLE_SET_IP = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x831, METHOD_BUFFERED, FILE_ANY_ACCESS);
        public static readonly uint IOCTL_WFP_DNS_SINKHOLE_GET_STATUS = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x832, METHOD_BUFFERED, FILE_ANY_ACCESS);

        public static readonly uint IOCTL_WFP_UPLOAD_TOGGLE_BLOCKING = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x843, METHOD_BUFFERED, FILE_ANY_ACCESS);
        public static readonly uint IOCTL_WFP_UPLOAD_GET_STATUS = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x845, METHOD_BUFFERED, FILE_ANY_ACCESS);
        public static readonly uint IOCTL_WFP_UPLOAD_SET_THRESHOLD = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x846, METHOD_BUFFERED, FILE_ANY_ACCESS);

        public static readonly uint IOCTL_WFP_UPLOAD_ADD_APP = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x850, METHOD_BUFFERED, FILE_ANY_ACCESS);
        public static readonly uint IOCTL_WFP_UPLOAD_REMOVE_APP = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x851, METHOD_BUFFERED, FILE_ANY_ACCESS);
        public static readonly uint IOCTL_WFP_UPLOAD_GET_APP_LIST = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x852, METHOD_BUFFERED, FILE_ANY_ACCESS);
        public static readonly uint IOCTL_WFP_UPLOAD_CLEAR_APP_LIST = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x853, METHOD_BUFFERED, FILE_ANY_ACCESS);
        public static readonly uint IOCTL_WFP_UPLOAD_ADD_APP_PRESET = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x854, METHOD_BUFFERED, FILE_ANY_ACCESS);

        // Anti-Tampering IOCTL
        public static readonly uint IOCTL_WFP_SELF_PROTECT_SET_PROCESS = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x870, METHOD_BUFFERED, FILE_ANY_ACCESS);
        public static readonly uint IOCTL_WFP_SELF_PROTECT_CLEAR_PROCESS = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x871, METHOD_BUFFERED, FILE_ANY_ACCESS);
        public static readonly uint IOCTL_WFP_SELF_PROTECT_GET_STATUS = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x872, METHOD_BUFFERED, FILE_ANY_ACCESS);
    }

    public static class SharedConsts
    {
        public const int MAX_SNI_LENGTH = 256;
        public const int MAX_BLOCKED_URLS = 128;
        public const int SNI_BLOCK_LIST_SIZE = 32;
        public const int MAX_PACKETS_PER_BATCH = 64;
        public const int MAX_MONITORED_APPS = 32;
        public const int MAX_APP_NAME_LENGTH = 64;

        public const int SNI_ACTION_TOGGLE = 0;
        public const int SNI_ACTION_ADD = 1;
        public const int SNI_ACTION_REMOVE = 2;

        public const byte PROTO_ICMP = 1;
        public const byte PROTO_TCP = 6;
        public const byte PROTO_UDP = 17;

        public const byte PACKET_DIR_OUTBOUND = 0;
        public const byte PACKET_DIR_INBOUND = 1;

        public const byte PACKET_ACTION_PERMIT = 0;
        public const byte PACKET_ACTION_BLOCK = 1;

        // Anti-Tampering flags
        public const uint SELF_PROTECT_FLAG_TERMINATE = 0x00000001;
        public const uint SELF_PROTECT_FLAG_VM_READ = 0x00000002;
        public const uint SELF_PROTECT_FLAG_VM_WRITE = 0x00000004;
        public const uint SELF_PROTECT_FLAG_VM_OPERATION = 0x00000008;
        public const uint SELF_PROTECT_FLAG_CREATE_THREAD = 0x00000010;
        public const uint SELF_PROTECT_FLAG_DUP_HANDLE = 0x00000020;
        public const uint SELF_PROTECT_FLAG_SUSPEND_RESUME = 0x00000040;
        public const uint SELF_PROTECT_FLAG_MEMORY_ACCESS =
            SELF_PROTECT_FLAG_VM_READ |
            SELF_PROTECT_FLAG_VM_WRITE |
            SELF_PROTECT_FLAG_VM_OPERATION |
            SELF_PROTECT_FLAG_CREATE_THREAD |
            SELF_PROTECT_FLAG_DUP_HANDLE |
            SELF_PROTECT_FLAG_SUSPEND_RESUME;
        public const uint SELF_PROTECT_FLAG_ALL =
            SELF_PROTECT_FLAG_TERMINATE |
            SELF_PROTECT_FLAG_MEMORY_ACCESS;
    }

    // ========================================================================
    // 기존 구조체
    // ========================================================================

    [StructLayout(LayoutKind.Sequential, Pack = 8)]
    public struct BLOCK_CONFIG { public uint ProcessId; public uint Reserved; }

    [StructLayout(LayoutKind.Sequential, Pack = 8)]
    public struct CAPTURE_TOGGLE { public uint Enable; public uint Reserved; }

    [StructLayout(LayoutKind.Sequential, Pack = 8)]
    public struct CAPTURE_STATUS
    {
        public uint IsCapturing; public uint BlockedPid; public uint QueuedPackets;
        public uint TotalCaptured; public uint TotalBlocked; public uint DroppedPackets;
        public uint SniBlockingEnabled; public uint SniBlockedUrls; public uint SniTotalBlocked;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 8)]
    public struct PACKET_INFO
    {
        public ulong Timestamp; public uint ProcessId;
        public uint LocalAddress; public uint RemoteAddress;
        public ushort LocalPort; public ushort RemotePort;
        public byte Protocol; public byte Direction; public byte Action; public byte Reserved;
        public uint PacketSize; public uint Reserved2;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 8)]
    public struct SNI_BLOCK_RESPONSE { public uint Success; public uint IsBlocked; public uint TotalBlockedUrls; public uint Reserved; }

    [StructLayout(LayoutKind.Sequential, Pack = 8)]
    public struct SNI_TOGGLE { public uint Enable; public uint Reserved; }

    [StructLayout(LayoutKind.Sequential, Pack = 8)]
    public struct DNS_SINKHOLE_TOGGLE { public uint Enable; public uint Reserved; }

    [StructLayout(LayoutKind.Sequential, Pack = 8)]
    public struct DNS_SINKHOLE_CONFIG { public uint SinkholeIp; public ushort HttpPort; public ushort HttpsPort; public uint Reserved; }

    [StructLayout(LayoutKind.Sequential, Pack = 8)]
    public struct DNS_SINKHOLE_STATUS
    {
        public uint Enabled; public uint SinkholeIp; public ushort HttpPort; public ushort HttpsPort;
        public ulong TotalRedirected; public ulong TotalDnsModified; public uint Reserved1; public uint Reserved2;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 8)]
    public struct UPLOAD_TOGGLE { public uint Enable; public uint Reserved; }

    [StructLayout(LayoutKind.Sequential, Pack = 8)]
    public struct UPLOAD_BLOCK_STATUS
    {
        public uint Enabled; public uint Reserved1; public ulong TotalBlocked;
        public uint ThresholdBytes; public uint WindowSeconds;
        public uint ActiveFlows; public uint MonitoredApps; public uint Reserved;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 8)]
    public struct UPLOAD_THRESHOLD_CONFIG { public uint ThresholdBytes; public uint WindowSeconds; public uint Reserved1; public uint Reserved2; }

    [StructLayout(LayoutKind.Sequential, Pack = 8)]
    public struct MONITORED_APP_RESPONSE { public uint Success; public uint TotalApps; public uint Reserved1; public uint Reserved2; }

    [StructLayout(LayoutKind.Sequential, Pack = 8)]
    public struct APP_PRESET_REQUEST { public uint PresetType; public uint Reserved; }

    [StructLayout(LayoutKind.Sequential, Pack = 8)]
    public struct APP_PRESET_RESPONSE { public uint Success; public uint AddedCount; public uint TotalApps; public uint Reserved; }

    [StructLayout(LayoutKind.Sequential, Pack = 8)]
    public struct SELF_PROTECT_CONFIG
    {
        public uint ProcessId;
        public uint ProtectionFlags;
        public uint Reserved1;
        public uint Reserved2;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 8)]
    public struct SELF_PROTECT_STATUS
    {
        public uint Enabled;
        public uint ProtectedPid;
        public uint ProtectionFlags;
        public uint CallbackReady;
        public ulong BlockedOpenAttempts;
        public ulong BlockedTerminateAttempts;
    }

    // ========================================================================
    // UI용 뷰 모델 (기존)
    // ========================================================================
    public class UrlInfoItem { public int Index { get; set; } public string Url { get; set; } = ""; public uint BlockCount { get; set; } }
    public class AppInfoItem { public int Index { get; set; } public string AppName { get; set; } = ""; public uint ActiveFlows { get; set; } }

    public class PacketInfoItem
    {
        public string Timestamp { get; set; } = ""; public string Action { get; set; } = "";
        public string Direction { get; set; } = ""; public string Protocol { get; set; } = "";
        public uint ProcessId { get; set; }
        public string LocalAddress { get; set; } = "";
        public ushort LocalPort { get; set; }
        public string RemoteAddress { get; set; } = "";
        public ushort RemotePort { get; set; }
        public uint PacketSize { get; set; }
        public bool IsBlocked { get; set; }
    }
}