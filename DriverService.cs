// ============================================================================
// DriverService.cs - WFP 드라이버 통신 서비스
// ============================================================================
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;
using WfpControlApp.Models;

namespace WfpControlApp.Services
{
    public class DriverService : IDisposable
    {
        private const string DEVICE_NAME = @"\\.\WfpExampleLink";
        private SafeFileHandle? _hDevice;
        private bool _disposed;

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern SafeFileHandle CreateFile(
            string lpFileName, uint dwDesiredAccess, uint dwShareMode,
            IntPtr lpSecurityAttributes, uint dwCreationDisposition,
            uint dwFlagsAndAttributes, IntPtr hTemplateFile);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool DeviceIoControl(
            SafeFileHandle hDevice, uint dwIoControlCode,
            IntPtr lpInBuffer, uint nInBufferSize,
            IntPtr lpOutBuffer, uint nOutBufferSize,
            out uint lpBytesReturned, IntPtr lpOverlapped);

        private const uint GENERIC_READ = 0x80000000;
        private const uint GENERIC_WRITE = 0x40000000;
        private const uint OPEN_EXISTING = 3;
        private const uint FILE_ATTRIBUTE_NORMAL = 0x80;

        public bool IsConnected => _hDevice != null && !_hDevice.IsInvalid && !_hDevice.IsClosed;

        public bool Connect()
        {
            _hDevice = CreateFile(DEVICE_NAME, GENERIC_READ | GENERIC_WRITE,
                0, IntPtr.Zero, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, IntPtr.Zero);
            return IsConnected;
        }

        public void Disconnect() { _hDevice?.Close(); _hDevice = null; }

        // ====================================================================
        // 헬퍼
        // ====================================================================
        private bool Ioctl<TIn>(uint code, ref TIn input) where TIn : struct
        {
            if (!IsConnected) return false;
            int size = Marshal.SizeOf<TIn>();
            IntPtr buf = Marshal.AllocHGlobal(size);
            try { Marshal.StructureToPtr(input, buf, false); return DeviceIoControl(_hDevice!, code, buf, (uint)size, IntPtr.Zero, 0, out _, IntPtr.Zero); }
            finally { Marshal.FreeHGlobal(buf); }
        }

        private bool Ioctl(uint code)
        {
            if (!IsConnected) return false;
            return DeviceIoControl(_hDevice!, code, IntPtr.Zero, 0, IntPtr.Zero, 0, out _, IntPtr.Zero);
        }

        private bool IoctlOut<TOut>(uint code, out TOut output) where TOut : struct
        {
            output = default;
            if (!IsConnected) return false;
            int size = Marshal.SizeOf<TOut>();
            IntPtr buf = Marshal.AllocHGlobal(size);
            try { ZeroMemory(buf, size); bool ok = DeviceIoControl(_hDevice!, code, IntPtr.Zero, 0, buf, (uint)size, out _, IntPtr.Zero); if (ok) output = Marshal.PtrToStructure<TOut>(buf); return ok; }
            finally { Marshal.FreeHGlobal(buf); }
        }

        private bool IoctlInOut<TIn, TOut>(uint code, ref TIn input, out TOut output) where TIn : struct where TOut : struct
        {
            output = default;
            if (!IsConnected) return false;
            int inSize = Marshal.SizeOf<TIn>(); int outSize = Marshal.SizeOf<TOut>();
            IntPtr inBuf = Marshal.AllocHGlobal(inSize); IntPtr outBuf = Marshal.AllocHGlobal(outSize);
            try { Marshal.StructureToPtr(input, inBuf, false); ZeroMemory(outBuf, outSize); bool ok = DeviceIoControl(_hDevice!, code, inBuf, (uint)inSize, outBuf, (uint)outSize, out _, IntPtr.Zero); if (ok) output = Marshal.PtrToStructure<TOut>(outBuf); return ok; }
            finally { Marshal.FreeHGlobal(inBuf); Marshal.FreeHGlobal(outBuf); }
        }

        private bool IoctlRaw(uint code, IntPtr inBuf, uint inSize, IntPtr outBuf, uint outSize)
        {
            if (!IsConnected) return false;
            return DeviceIoControl(_hDevice!, code, inBuf, inSize, outBuf, outSize, out _, IntPtr.Zero);
        }

        private static void ZeroMemory(IntPtr ptr, int size) { byte[] z = new byte[size]; Marshal.Copy(z, 0, ptr, size); }

        // ====================================================================
        // PID 차단
        // ====================================================================
        public bool SetBlockPid(uint pid) { var c = new BLOCK_CONFIG { ProcessId = pid }; return Ioctl(IoctlCodes.IOCTL_WFP_SET_BLOCK_PID, ref c); }
        public bool ResetBlockPid() => Ioctl(IoctlCodes.IOCTL_WFP_RESET_BLOCK_PID);

        // ====================================================================
        // 패킷 캡처
        // ====================================================================
        public bool ToggleCapture(bool enable) { var t = new CAPTURE_TOGGLE { Enable = enable ? 1u : 0u }; return Ioctl(IoctlCodes.IOCTL_WFP_TOGGLE_CAPTURE, ref t); }
        public bool GetCaptureStatus(out CAPTURE_STATUS status) => IoctlOut(IoctlCodes.IOCTL_WFP_GET_CAPTURE_STATUS, out status);
        public bool ClearPacketQueue() => Ioctl(IoctlCodes.IOCTL_WFP_CLEAR_PACKET_QUEUE);

        public List<PacketInfoItem> GetPacketBatch()
        {
            var list = new List<PacketInfoItem>();
            if (!IsConnected) return list;
            int size = 16 + 40 * SharedConsts.MAX_PACKETS_PER_BATCH;
            IntPtr buf = Marshal.AllocHGlobal(size);
            try
            {
                ZeroMemory(buf, size);
                bool ok = DeviceIoControl(_hDevice!, IoctlCodes.IOCTL_WFP_GET_PACKET_BATCH, IntPtr.Zero, 0, buf, (uint)size, out _, IntPtr.Zero);
                if (!ok) return list;
                uint cnt = (uint)Marshal.ReadInt32(buf, 0);
                int ps = Marshal.SizeOf<PACKET_INFO>();
                for (int i = 0; i < cnt && i < SharedConsts.MAX_PACKETS_PER_BATCH; i++)
                    list.Add(ConvertPacket(Marshal.PtrToStructure<PACKET_INFO>(IntPtr.Add(buf, 16 + i * ps))));
            }
            finally { Marshal.FreeHGlobal(buf); }
            return list;
        }

        private PacketInfoItem ConvertPacket(PACKET_INFO p) => new()
        {
            Timestamp = FileTimeToString(p.Timestamp),
            Action = p.Action == SharedConsts.PACKET_ACTION_BLOCK ? "BLOCK" : "PERMIT",
            Direction = p.Direction == SharedConsts.PACKET_DIR_OUTBOUND ? "OUT" : "IN",
            Protocol = p.Protocol switch { SharedConsts.PROTO_TCP => "TCP", SharedConsts.PROTO_UDP => "UDP", SharedConsts.PROTO_ICMP => "ICMP", _ => "OTHER" },
            ProcessId = p.ProcessId,
            LocalAddress = IpToString(p.LocalAddress),
            LocalPort = p.LocalPort,
            RemoteAddress = IpToString(p.RemoteAddress),
            RemotePort = p.RemotePort,
            PacketSize = p.PacketSize,
            IsBlocked = p.Action == SharedConsts.PACKET_ACTION_BLOCK
        };

        // ====================================================================
        // SNI URL 차단
        // ====================================================================
        public bool ToggleSniUrl(string url, out bool isNowBlocked)
        {
            isNowBlocked = false;
            if (!IsConnected) return false;
            int inSize = SharedConsts.MAX_SNI_LENGTH + 8; int outSize = 16;
            IntPtr inBuf = Marshal.AllocHGlobal(inSize); IntPtr outBuf = Marshal.AllocHGlobal(outSize);
            try
            {
                ZeroMemory(inBuf, inSize); ZeroMemory(outBuf, outSize);
                WriteAnsiString(inBuf, NormalizeUrl(url), SharedConsts.MAX_SNI_LENGTH);
                Marshal.WriteInt32(inBuf, SharedConsts.MAX_SNI_LENGTH, SharedConsts.SNI_ACTION_TOGGLE);
                bool ok = IoctlRaw(IoctlCodes.IOCTL_WFP_SNI_BLOCK_URL, inBuf, (uint)inSize, outBuf, (uint)outSize);
                if (ok) { uint s = (uint)Marshal.ReadInt32(outBuf, 0); if (s != 0) isNowBlocked = (uint)Marshal.ReadInt32(outBuf, 4) != 0; return s != 0; }
                return false;
            }
            finally { Marshal.FreeHGlobal(inBuf); Marshal.FreeHGlobal(outBuf); }
        }

        public bool SetSniBlockingEnabled(bool enable) { var t = new SNI_TOGGLE { Enable = enable ? 1u : 0u }; return Ioctl(IoctlCodes.IOCTL_WFP_SNI_TOGGLE_BLOCKING, ref t); }

        public List<UrlInfoItem> GetSniBlockList()
        {
            var result = new List<UrlInfoItem>();
            uint startIndex = 0; int retry = 0; bool hasMore = true;
            int reqSize = 8; int respSize = 16 + 264 * SharedConsts.SNI_BLOCK_LIST_SIZE;
            IntPtr reqBuf = Marshal.AllocHGlobal(reqSize); IntPtr respBuf = Marshal.AllocHGlobal(respSize);
            try
            {
                while (hasMore && retry < 10)
                {
                    ZeroMemory(reqBuf, reqSize); ZeroMemory(respBuf, respSize);
                    Marshal.WriteInt32(reqBuf, 0, (int)startIndex); Marshal.WriteInt32(reqBuf, 4, SharedConsts.SNI_BLOCK_LIST_SIZE);
                    bool ok = IoctlRaw(IoctlCodes.IOCTL_WFP_SNI_GET_BLOCK_LIST, reqBuf, (uint)reqSize, respBuf, (uint)respSize);
                    if (!ok) break;
                    uint total = (uint)Marshal.ReadInt32(respBuf, 0); uint rc = (uint)Marshal.ReadInt32(respBuf, 4);
                    for (uint i = 0; i < rc; i++)
                    {
                        IntPtr ep = IntPtr.Add(respBuf, 16 + (int)i * 264);
                        string u = ReadAnsiString(ep, SharedConsts.MAX_SNI_LENGTH);
                        uint bc = (uint)Marshal.ReadInt32(ep, SharedConsts.MAX_SNI_LENGTH);
                        if (!string.IsNullOrEmpty(u) && u.Length >= 3) result.Add(new UrlInfoItem { Index = result.Count + 1, Url = u, BlockCount = bc });
                    }
                    if (rc == 0) hasMore = false; else { startIndex += rc; hasMore = startIndex < total; }
                    retry++;
                }
            }
            finally { Marshal.FreeHGlobal(reqBuf); Marshal.FreeHGlobal(respBuf); }
            return result;
        }

        public bool ClearSniBlockList() => Ioctl(IoctlCodes.IOCTL_WFP_SNI_CLEAR_BLOCK_LIST);

        // ====================================================================
        // DNS 싱크홀
        // ====================================================================
        public bool SetDnsSinkholeEnabled(bool e) { var t = new DNS_SINKHOLE_TOGGLE { Enable = e ? 1u : 0u }; return Ioctl(IoctlCodes.IOCTL_WFP_DNS_SINKHOLE_TOGGLE, ref t); }
        public bool SetDnsSinkholeIp(uint ip, ushort hp, ushort hsp) { var c = new DNS_SINKHOLE_CONFIG { SinkholeIp = ip, HttpPort = hp, HttpsPort = hsp }; return Ioctl(IoctlCodes.IOCTL_WFP_DNS_SINKHOLE_SET_IP, ref c); }
        public bool GetDnsSinkholeStatus(out DNS_SINKHOLE_STATUS s) => IoctlOut(IoctlCodes.IOCTL_WFP_DNS_SINKHOLE_GET_STATUS, out s);

        // ====================================================================
        // 업로드 DLP
        // ====================================================================
        public bool SetUploadBlockingEnabled(bool e) { var t = new UPLOAD_TOGGLE { Enable = e ? 1u : 0u }; return Ioctl(IoctlCodes.IOCTL_WFP_UPLOAD_TOGGLE_BLOCKING, ref t); }
        public bool GetUploadBlockStatus(out UPLOAD_BLOCK_STATUS s) => IoctlOut(IoctlCodes.IOCTL_WFP_UPLOAD_GET_STATUS, out s);
        public bool SetUploadThreshold(uint tb, uint ws) { var c = new UPLOAD_THRESHOLD_CONFIG { ThresholdBytes = tb, WindowSeconds = ws }; return Ioctl(IoctlCodes.IOCTL_WFP_UPLOAD_SET_THRESHOLD, ref c); }

        // ====================================================================
        // 모니터링 앱 관리
        // ====================================================================
        public bool AddMonitoredApp(string appName)
        {
            if (!IsConnected) return false;
            int inSize = SharedConsts.MAX_APP_NAME_LENGTH + 8; int outSize = 16;
            IntPtr inBuf = Marshal.AllocHGlobal(inSize); IntPtr outBuf = Marshal.AllocHGlobal(outSize);
            try { ZeroMemory(inBuf, inSize); ZeroMemory(outBuf, outSize); WriteAnsiString(inBuf, appName, SharedConsts.MAX_APP_NAME_LENGTH); Marshal.WriteInt32(inBuf, SharedConsts.MAX_APP_NAME_LENGTH, 1); bool ok = IoctlRaw(IoctlCodes.IOCTL_WFP_UPLOAD_ADD_APP, inBuf, (uint)inSize, outBuf, (uint)outSize); return ok && (uint)Marshal.ReadInt32(outBuf, 0) != 0; }
            finally { Marshal.FreeHGlobal(inBuf); Marshal.FreeHGlobal(outBuf); }
        }

        public bool RemoveMonitoredApp(string appName)
        {
            if (!IsConnected) return false;
            int inSize = SharedConsts.MAX_APP_NAME_LENGTH + 8; int outSize = 16;
            IntPtr inBuf = Marshal.AllocHGlobal(inSize); IntPtr outBuf = Marshal.AllocHGlobal(outSize);
            try { ZeroMemory(inBuf, inSize); ZeroMemory(outBuf, outSize); WriteAnsiString(inBuf, appName, SharedConsts.MAX_APP_NAME_LENGTH); Marshal.WriteInt32(inBuf, SharedConsts.MAX_APP_NAME_LENGTH, 2); bool ok = IoctlRaw(IoctlCodes.IOCTL_WFP_UPLOAD_REMOVE_APP, inBuf, (uint)inSize, outBuf, (uint)outSize); return ok && (uint)Marshal.ReadInt32(outBuf, 0) != 0; }
            finally { Marshal.FreeHGlobal(inBuf); Marshal.FreeHGlobal(outBuf); }
        }

        public List<AppInfoItem> GetMonitoredAppList()
        {
            var result = new List<AppInfoItem>();
            if (!IsConnected) return result;
            int respSize = 16 + 72 * SharedConsts.MAX_MONITORED_APPS;
            IntPtr respBuf = Marshal.AllocHGlobal(respSize);
            try
            {
                ZeroMemory(respBuf, respSize);
                bool ok = DeviceIoControl(_hDevice!, IoctlCodes.IOCTL_WFP_UPLOAD_GET_APP_LIST, IntPtr.Zero, 0, respBuf, (uint)respSize, out _, IntPtr.Zero);
                if (!ok) return result;
                uint rc = (uint)Marshal.ReadInt32(respBuf, 4);
                for (uint i = 0; i < rc && i < SharedConsts.MAX_MONITORED_APPS; i++)
                {
                    IntPtr ep = IntPtr.Add(respBuf, 16 + (int)i * 72);
                    string name = ReadAnsiString(ep, SharedConsts.MAX_APP_NAME_LENGTH);
                    uint flows = (uint)Marshal.ReadInt32(ep, SharedConsts.MAX_APP_NAME_LENGTH);
                    if (!string.IsNullOrEmpty(name)) result.Add(new AppInfoItem { Index = result.Count + 1, AppName = name, ActiveFlows = flows });
                }
            }
            finally { Marshal.FreeHGlobal(respBuf); }
            return result;
        }

        public bool ClearMonitoredAppList() => Ioctl(IoctlCodes.IOCTL_WFP_UPLOAD_CLEAR_APP_LIST);
        public bool AddAppPreset(uint pt) { var r = new APP_PRESET_REQUEST { PresetType = pt }; bool ok = IoctlInOut(IoctlCodes.IOCTL_WFP_UPLOAD_ADD_APP_PRESET, ref r, out APP_PRESET_RESPONSE resp); return ok && resp.Success != 0; }

        // ====================================================================
        // Anti-Tampering
        // ====================================================================
        public bool SetSelfProtection(uint pid, uint protectionFlags = SharedConsts.SELF_PROTECT_FLAG_ALL)
        {
            var config = new SELF_PROTECT_CONFIG
            {
                ProcessId = pid,
                ProtectionFlags = protectionFlags == 0 ? SharedConsts.SELF_PROTECT_FLAG_ALL : protectionFlags
            };

            return Ioctl(IoctlCodes.IOCTL_WFP_SELF_PROTECT_SET_PROCESS, ref config);
        }

        public bool ClearSelfProtection() => Ioctl(IoctlCodes.IOCTL_WFP_SELF_PROTECT_CLEAR_PROCESS);

        public bool GetSelfProtectionStatus(out SELF_PROTECT_STATUS status) =>
            IoctlOut(IoctlCodes.IOCTL_WFP_SELF_PROTECT_GET_STATUS, out status);

        // ====================================================================
        // 유틸리티
        // ====================================================================
        public static string NormalizeUrl(string url)
        {
            if (string.IsNullOrWhiteSpace(url)) return "";
            string r = url.Trim().ToLowerInvariant();
            if (r.StartsWith("https://")) r = r.Substring(8); else if (r.StartsWith("http://")) r = r.Substring(7);
            if (r.StartsWith("www.")) r = r.Substring(4);
            int s = r.IndexOf('/'); if (s >= 0) r = r.Substring(0, s);
            int c = r.IndexOf(':'); if (c >= 0) r = r.Substring(0, c);
            return r;
        }

        public static string IpToString(uint ip) => $"{(ip >> 24) & 0xFF}.{(ip >> 16) & 0xFF}.{(ip >> 8) & 0xFF}.{ip & 0xFF}";

        public static bool StringToIp(string s, out uint ip)
        {
            ip = 0; var p = s.Split('.'); if (p.Length != 4) return false;
            if (!byte.TryParse(p[0], out byte a) || !byte.TryParse(p[1], out byte b) || !byte.TryParse(p[2], out byte c) || !byte.TryParse(p[3], out byte d)) return false;
            ip = ((uint)a << 24) | ((uint)b << 16) | ((uint)c << 8) | d; return true;
        }

        private static string FileTimeToString(ulong ts) { if (ts == 0) return ""; try { return DateTime.FromFileTime((long)ts).ToString("yyyy-MM-dd HH:mm:ss.fff"); } catch { return ""; } }
        private static void WriteAnsiString(IntPtr dest, string value, int maxLen) { byte[] b = Encoding.ASCII.GetBytes(value ?? ""); int cl = Math.Min(b.Length, maxLen - 1); Marshal.Copy(b, 0, dest, cl); Marshal.WriteByte(dest, cl, 0); }
        private static string ReadAnsiString(IntPtr src, int maxLen) { byte[] b = new byte[maxLen]; Marshal.Copy(src, b, 0, maxLen); int l = Array.IndexOf(b, (byte)0); if (l < 0) l = maxLen; return l > 0 ? Encoding.ASCII.GetString(b, 0, l) : ""; }

        public void Dispose() { if (!_disposed) { Disconnect(); _disposed = true; } GC.SuppressFinalize(this); }
        ~DriverService() => Dispose();
    }
}