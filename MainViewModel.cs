// ============================================================================
// MainViewModel.cs - WFP Network Security Controller
// ============================================================================
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Input;
using System.Windows.Threading;
using WfpControlApp.Models;
using WfpControlApp.Services;

namespace WfpControlApp.ViewModels
{
    public class MainViewModel : BaseViewModel, IDisposable
    {
        private readonly DriverService _driver = new();
        private CancellationTokenSource? _captureCts;
        private StreamWriter? _logWriter;
        private readonly Dispatcher _dispatcher;
        private readonly uint _currentProcessId = (uint)Environment.ProcessId;

        public MainViewModel()
        {
            _dispatcher = Application.Current.Dispatcher;
            InitializeCommands();
        }

        // ================================================================
        // 상태 프로퍼티 (기존)
        // ================================================================
        private bool _isConnected;
        public bool IsConnected { get => _isConnected; set => SetField(ref _isConnected, value); }

        private bool _isCapturing;
        public bool IsCapturing { get => _isCapturing; set => SetField(ref _isCapturing, value); }

        private bool _sniBlockingEnabled = true;
        public bool SniBlockingEnabled { get => _sniBlockingEnabled; set => SetField(ref _sniBlockingEnabled, value); }

        private bool _uploadBlockingEnabled;
        public bool UploadBlockingEnabled { get => _uploadBlockingEnabled; set => SetField(ref _uploadBlockingEnabled, value); }

        private bool _dnsSinkholeEnabled;
        public bool DnsSinkholeEnabled { get => _dnsSinkholeEnabled; set => SetField(ref _dnsSinkholeEnabled, value); }

        private uint _blockedPid;
        public uint BlockedPid { get => _blockedPid; set => SetField(ref _blockedPid, value); }

        private string _pidInput = "";
        public string PidInput { get => _pidInput; set => SetField(ref _pidInput, value); }

        private string _sniUrlInput = "";
        public string SniUrlInput { get => _sniUrlInput; set => SetField(ref _sniUrlInput, value); }

        private string _appNameInput = "";
        public string AppNameInput { get => _appNameInput; set => SetField(ref _appNameInput, value); }

        private string _sinkholeIpInput = "127.0.0.1";
        public string SinkholeIpInput { get => _sinkholeIpInput; set => SetField(ref _sinkholeIpInput, value); }

        private string _thresholdInput = "100";
        public string ThresholdInput { get => _thresholdInput; set => SetField(ref _thresholdInput, value); }

        private string _windowInput = "30";
        public string WindowInput { get => _windowInput; set => SetField(ref _windowInput, value); }

        // 통계
        private ulong _totalCaptured; public ulong TotalCaptured { get => _totalCaptured; set => SetField(ref _totalCaptured, value); }
        private ulong _totalBlocked; public ulong TotalBlocked { get => _totalBlocked; set => SetField(ref _totalBlocked, value); }
        private ulong _sniBlocked; public ulong SniBlocked { get => _sniBlocked; set => SetField(ref _sniBlocked, value); }
        private ulong _uploadBlocked; public ulong UploadBlocked { get => _uploadBlocked; set => SetField(ref _uploadBlocked, value); }
        private uint _activeFlows; public uint ActiveFlows { get => _activeFlows; set => SetField(ref _activeFlows, value); }
        private uint _monitoredAppsCount; public uint MonitoredAppsCount { get => _monitoredAppsCount; set => SetField(ref _monitoredAppsCount, value); }
        private uint _thresholdBytes; public uint ThresholdBytes { get => _thresholdBytes; set => SetField(ref _thresholdBytes, value); }
        private uint _windowSeconds; public uint WindowSeconds { get => _windowSeconds; set => SetField(ref _windowSeconds, value); }

        private string _statusMessage = "드라이버 연결 대기 중...";
        public string StatusMessage { get => _statusMessage; set => SetField(ref _statusMessage, value); }

        private string _selectedTab = "Dashboard";
        public string SelectedTab { get => _selectedTab; set => SetField(ref _selectedTab, value); }

        // Anti-Tampering
        public uint AgentProcessId => _currentProcessId;

        private bool _selfProtectionEnabled;
        public bool SelfProtectionEnabled { get => _selfProtectionEnabled; set => SetField(ref _selfProtectionEnabled, value); }

        private bool _selfProtectionReady;
        public bool SelfProtectionReady { get => _selfProtectionReady; set => SetField(ref _selfProtectionReady, value); }

        private uint _selfProtectionPid;
        public uint SelfProtectionPid { get => _selfProtectionPid; set => SetField(ref _selfProtectionPid, value); }

        private ulong _selfProtectionBlockedOpens;
        public ulong SelfProtectionBlockedOpens { get => _selfProtectionBlockedOpens; set => SetField(ref _selfProtectionBlockedOpens, value); }

        private ulong _selfProtectionBlockedTerminates;
        public ulong SelfProtectionBlockedTerminates { get => _selfProtectionBlockedTerminates; set => SetField(ref _selfProtectionBlockedTerminates, value); }

        private uint _selfProtectionFlags;
        public uint SelfProtectionFlags { get => _selfProtectionFlags; set => SetField(ref _selfProtectionFlags, value); }

        private string _selfProtectionFlagsHex = "0x00000000";
        public string SelfProtectionFlagsHex { get => _selfProtectionFlagsHex; set => SetField(ref _selfProtectionFlagsHex, value); }

        private bool _selfProtectBlockTerminate = true;
        public bool SelfProtectBlockTerminate { get => _selfProtectBlockTerminate; set => SetField(ref _selfProtectBlockTerminate, value); }

        private bool _selfProtectBlockMemoryAccess = true;
        public bool SelfProtectBlockMemoryAccess { get => _selfProtectBlockMemoryAccess; set => SetField(ref _selfProtectBlockMemoryAccess, value); }

        // WM_CLOSE 방어용 — 사용자가 명시적으로 종료를 요청했는지 여부
        public bool UserRequestedExit { get; private set; }

        // Window.Close() 호출을 View에 요청하는 이벤트
        public event EventHandler? CloseWindowRequested;

        // 컬렉션
        public ObservableCollection<PacketInfoItem> PacketLog { get; } = new();
        public ObservableCollection<UrlInfoItem> SniBlockList { get; } = new();
        public ObservableCollection<AppInfoItem> MonitoredAppList { get; } = new();
        public ObservableCollection<string> EventLog { get; } = new();

        // ================================================================
        // Commands
        // ================================================================
        public ICommand ConnectCommand { get; private set; } = null!;
        public ICommand DisconnectCommand { get; private set; } = null!;
        public ICommand SetBlockPidCommand { get; private set; } = null!;
        public ICommand ResetBlockPidCommand { get; private set; } = null!;
        public ICommand ToggleCaptureCommand { get; private set; } = null!;
        public ICommand ClearQueueCommand { get; private set; } = null!;
        public ICommand RefreshStatusCommand { get; private set; } = null!;
        public ICommand ToggleSniUrlCommand { get; private set; } = null!;
        public ICommand RefreshSniListCommand { get; private set; } = null!;
        public ICommand ClearSniListCommand { get; private set; } = null!;
        public ICommand ToggleSniBlockingCommand { get; private set; } = null!;
        public ICommand ToggleDnsSinkholeCommand { get; private set; } = null!;
        public ICommand SetSinkholeIpCommand { get; private set; } = null!;
        public ICommand ToggleUploadBlockingCommand { get; private set; } = null!;
        public ICommand SetThresholdCommand { get; private set; } = null!;
        public ICommand AddAppPresetCommand { get; private set; } = null!;
        public ICommand AddMonitoredAppCommand { get; private set; } = null!;
        public ICommand RemoveMonitoredAppCommand { get; private set; } = null!;
        public ICommand RefreshAppListCommand { get; private set; } = null!;
        public ICommand ClearAppListCommand { get; private set; } = null!;
        public ICommand NavigateCommand { get; private set; } = null!;
        public ICommand ClearPacketLogCommand { get; private set; } = null!;
        public ICommand ToggleSelfProtectionCommand { get; private set; } = null!;
        public ICommand RefreshSelfProtectionCommand { get; private set; } = null!;
        public ICommand ExitApplicationCommand { get; private set; } = null!;

        private void InitializeCommands()
        {
            ConnectCommand = new RelayCommand(DoConnect);
            DisconnectCommand = new RelayCommand(DoDisconnect);
            SetBlockPidCommand = new RelayCommand(DoSetBlockPid);
            ResetBlockPidCommand = new RelayCommand(DoResetBlockPid);
            ToggleCaptureCommand = new RelayCommand(DoToggleCapture);
            ClearQueueCommand = new RelayCommand(DoClearQueue);
            RefreshStatusCommand = new RelayCommand(DoRefreshStatus);
            ToggleSniUrlCommand = new RelayCommand(DoToggleSniUrl);
            RefreshSniListCommand = new RelayCommand(DoRefreshSniList);
            ClearSniListCommand = new RelayCommand(DoClearSniList);
            ToggleSniBlockingCommand = new RelayCommand(DoToggleSniBlocking);
            ToggleDnsSinkholeCommand = new RelayCommand(DoToggleDnsSinkhole);
            SetSinkholeIpCommand = new RelayCommand(DoSetSinkholeIp);
            ToggleUploadBlockingCommand = new RelayCommand(DoToggleUploadBlocking);
            SetThresholdCommand = new RelayCommand(DoSetThreshold);
            AddAppPresetCommand = new RelayCommand(p => DoAddAppPreset(p));
            AddMonitoredAppCommand = new RelayCommand(DoAddMonitoredApp);
            RemoveMonitoredAppCommand = new RelayCommand(p => DoRemoveMonitoredApp(p));
            RefreshAppListCommand = new RelayCommand(DoRefreshAppList);
            ClearAppListCommand = new RelayCommand(DoClearAppList);
            NavigateCommand = new RelayCommand(p => { if (p is string tab) SelectedTab = tab; });
            ClearPacketLogCommand = new RelayCommand(() => PacketLog.Clear());
            ToggleSelfProtectionCommand = new RelayCommand(DoToggleSelfProtection);
            RefreshSelfProtectionCommand = new RelayCommand(DoRefreshSelfProtection);
            ExitApplicationCommand = new RelayCommand(DoExitApplication);
        }

        // ================================================================
        // Command 구현 (기존)
        // ================================================================
        private void DoConnect()
        {
            if (_driver.Connect())
            {
                IsConnected = true;
                Log("[+] 드라이버 연결 성공");
                StatusMessage = "드라이버 연결됨";
                _driver.SetSniBlockingEnabled(true);
                SniBlockingEnabled = true;
                OpenLogFile();
                EnableSelfProtection(logFailure: true);
                DoRefreshStatus(); DoRefreshSniList(); DoRefreshAppList();
            }
            else { Log("[-] 드라이버 연결 실패 — 관리자 권한으로 실행하세요"); StatusMessage = "연결 실패"; }
        }

        private void DoDisconnect()
        {
            StopCapture();
            DisableSelfProtection(logSuccess: false);
            _driver.Disconnect();
            IsConnected = false;
            StatusMessage = "연결 해제됨";
            ResetSelfProtectionState();
            Log("[*] 드라이버 연결 해제");
        }
        private void DoSetBlockPid() { if (uint.TryParse(PidInput, out uint pid) && pid > 0) { if (_driver.SetBlockPid(pid)) { BlockedPid = pid; Log($"[+] PID {pid} 차단 설정"); } } }
        private void DoResetBlockPid() { if (_driver.ResetBlockPid()) { BlockedPid = 0; Log("[+] PID 차단 해제"); } }

        private void DoToggleCapture()
        {
            bool ns = !IsCapturing;
            if (_driver.ToggleCapture(ns)) { IsCapturing = ns; if (ns) StartCapture(); else StopCapture(); Log($"[+] 패킷 캡처 {(ns ? "ON" : "OFF")}"); }
        }

        private void DoClearQueue() { if (_driver.ClearPacketQueue()) Log("[+] 패킷 큐 초기화"); }

        private void DoRefreshStatus()
        {
            if (_driver.GetCaptureStatus(out var s)) { IsCapturing = s.IsCapturing != 0; BlockedPid = s.BlockedPid; TotalCaptured = s.TotalCaptured; TotalBlocked = s.TotalBlocked; SniBlocked = s.SniTotalBlocked; SniBlockingEnabled = s.SniBlockingEnabled != 0; }
            if (_driver.GetDnsSinkholeStatus(out var ds)) DnsSinkholeEnabled = ds.Enabled != 0;
            if (_driver.GetUploadBlockStatus(out var us)) { UploadBlockingEnabled = us.Enabled != 0; UploadBlocked = us.TotalBlocked; ActiveFlows = us.ActiveFlows; MonitoredAppsCount = us.MonitoredApps; ThresholdBytes = us.ThresholdBytes; WindowSeconds = us.WindowSeconds; }
            DoRefreshSelfProtection();
        }

        private void DoToggleSniUrl() { if (string.IsNullOrWhiteSpace(SniUrlInput)) return; if (_driver.ToggleSniUrl(SniUrlInput, out bool b)) { Log(b ? $"[+] URL 차단: {SniUrlInput}" : $"[+] URL 해제: {SniUrlInput}"); SniUrlInput = ""; DoRefreshSniList(); } }
        private void DoRefreshSniList() { var l = _driver.GetSniBlockList(); _dispatcher.Invoke(() => { SniBlockList.Clear(); foreach (var i in l) SniBlockList.Add(i); }); }
        private void DoClearSniList() { if (_driver.ClearSniBlockList()) { SniBlockList.Clear(); Log("[+] SNI 리스트 초기화"); } }
        private void DoToggleSniBlocking() { bool n = !SniBlockingEnabled; if (_driver.SetSniBlockingEnabled(n)) { SniBlockingEnabled = n; Log($"[+] SNI/QUIC/DNS {(n ? "ON" : "OFF")}"); } }
        private void DoToggleDnsSinkhole() { bool n = !DnsSinkholeEnabled; if (_driver.SetDnsSinkholeEnabled(n)) { DnsSinkholeEnabled = n; Log($"[+] DNS 싱크홀 {(n ? "ON" : "OFF")}"); } }
        private void DoSetSinkholeIp() { if (DriverService.StringToIp(SinkholeIpInput, out uint ip)) { if (_driver.SetDnsSinkholeIp(ip, 80, 443)) Log($"[+] 싱크홀 IP: {SinkholeIpInput}"); } }
        private void DoToggleUploadBlocking() { bool n = !UploadBlockingEnabled; if (_driver.SetUploadBlockingEnabled(n)) { UploadBlockingEnabled = n; Log($"[+] 업로드 DLP {(n ? "ON" : "OFF")}"); } }

        private void DoSetThreshold()
        {
            if (uint.TryParse(ThresholdInput, out uint kb) && uint.TryParse(WindowInput, out uint ws))
            { uint bytes = kb * 1024; if (_driver.SetUploadThreshold(bytes, ws)) { ThresholdBytes = bytes; WindowSeconds = ws; Log($"[+] 임계값: {kb}KB / 윈도우: {ws}초"); } }
        }

        private void DoAddAppPreset(object? p) { if (p is string s && uint.TryParse(s, out uint pt)) { if (_driver.AddAppPreset(pt)) { Log($"[+] 앱 프리셋 {pt} 등록"); DoRefreshAppList(); DoRefreshStatus(); } } }
        private void DoAddMonitoredApp() { if (string.IsNullOrWhiteSpace(AppNameInput)) return; if (_driver.AddMonitoredApp(AppNameInput)) { Log($"[+] 모니터링 앱: {AppNameInput}"); AppNameInput = ""; DoRefreshAppList(); } }
        private void DoRemoveMonitoredApp(object? p) { if (p is string name && _driver.RemoveMonitoredApp(name)) { Log($"[+] 앱 제거: {name}"); DoRefreshAppList(); } }
        private void DoRefreshAppList() { var l = _driver.GetMonitoredAppList(); _dispatcher.Invoke(() => { MonitoredAppList.Clear(); foreach (var i in l) MonitoredAppList.Add(i); }); MonitoredAppsCount = (uint)l.Count; }
        private void DoClearAppList() { if (_driver.ClearMonitoredAppList()) { MonitoredAppList.Clear(); MonitoredAppsCount = 0; Log("[+] 앱 목록 초기화"); } }

        // ================================================================
        // Anti-Tampering
        // ================================================================
        private void DoToggleSelfProtection()
        {
            if (!IsConnected) return;

            if (SelfProtectionEnabled)
                DisableSelfProtection(logSuccess: true);
            else
                EnableSelfProtection(logFailure: true);

            DoRefreshSelfProtection();
        }

        private void DoRefreshSelfProtection()
        {
            if (!_driver.GetSelfProtectionStatus(out var status)) return;

            SelfProtectionEnabled = status.Enabled != 0;
            SelfProtectionReady = status.CallbackReady != 0;
            SelfProtectionPid = status.ProtectedPid;
            SelfProtectionFlags = status.ProtectionFlags;
            SelfProtectionFlagsHex = $"0x{status.ProtectionFlags:X8}";
            SelfProtectionBlockedOpens = status.BlockedOpenAttempts;
            SelfProtectionBlockedTerminates = status.BlockedTerminateAttempts;
            SelfProtectBlockTerminate = (status.ProtectionFlags & SharedConsts.SELF_PROTECT_FLAG_TERMINATE) != 0;
            SelfProtectBlockMemoryAccess = (status.ProtectionFlags & SharedConsts.SELF_PROTECT_FLAG_MEMORY_ACCESS) != 0;
        }

        private void EnableSelfProtection(bool logFailure)
        {
            uint protectionFlags = 0;
            if (SelfProtectBlockTerminate) protectionFlags |= SharedConsts.SELF_PROTECT_FLAG_TERMINATE;
            if (SelfProtectBlockMemoryAccess) protectionFlags |= SharedConsts.SELF_PROTECT_FLAG_MEMORY_ACCESS;
            if (protectionFlags == 0) protectionFlags = SharedConsts.SELF_PROTECT_FLAG_ALL;

            if (!_driver.SetSelfProtection(_currentProcessId, protectionFlags))
            {
                if (logFailure)
                    Log($"[-] 자가 보호 활성화 실패 (PID={_currentProcessId})");
                return;
            }

            Log($"[+] 자가 보호 ON (PID={_currentProcessId}, Flags=0x{protectionFlags:X8})");

            // ObRegisterCallbacks 실패 시 부분 보호 상태 확인
            DoRefreshSelfProtection();
            if (SelfProtectionEnabled && !SelfProtectionReady)
            {
                Log("[!] 주의: ObRegisterCallbacks 미등록 — 프로세스 종료 감지만 활성");
                Log("[!] 완전 보호에는 /integritycheck 링커 플래그 + EV/테스트 서명 필요");
            }
        }

        private void DisableSelfProtection(bool logSuccess)
        {
            if (!IsConnected || !SelfProtectionEnabled) return;
            if (!_driver.ClearSelfProtection()) return;
            if (logSuccess) Log("[+] 자가 보호 OFF");
        }

        private void ResetSelfProtectionState()
        {
            SelfProtectionEnabled = false;
            SelfProtectionReady = false;
            SelfProtectionPid = 0;
            SelfProtectionFlags = 0;
            SelfProtectionFlagsHex = "0x00000000";
            SelfProtectionBlockedOpens = 0;
            SelfProtectionBlockedTerminates = 0;
            SelfProtectBlockTerminate = true;
            SelfProtectBlockMemoryAccess = true;
        }

        private void DoExitApplication()
        {
            // 보호 해제 후 정상 종료 — 사용자가 명시적으로 "종료" 버튼을 누른 경우에만
            DisableSelfProtection(logSuccess: false);
            UserRequestedExit = true;
            CloseWindowRequested?.Invoke(this, EventArgs.Empty);
        }

        // ================================================================
        // 캡처 스레드 (기존)
        // ================================================================
        private void StartCapture()
        {
            _captureCts?.Cancel();
            _captureCts = new CancellationTokenSource();
            var token = _captureCts.Token;
            Task.Run(async () =>
            {
                while (!token.IsCancellationRequested)
                {
                    try
                    {
                        var packets = _driver.GetPacketBatch();
                        if (packets.Count > 0)
                            _dispatcher.Invoke(() => { foreach (var p in packets) { PacketLog.Insert(0, p); if (PacketLog.Count > 500) PacketLog.RemoveAt(PacketLog.Count - 1); LogPacketToFile(p); } });
                    }
                    catch { }
                    await Task.Delay(100, token).ConfigureAwait(false);
                }
            }, token);
        }

        private void StopCapture() { _captureCts?.Cancel(); _captureCts = null; }

        // ================================================================
        // 로그
        // ================================================================
        private void Log(string msg)
        {
            string entry = $"[{DateTime.Now:HH:mm:ss}] {msg}";
            _dispatcher.Invoke(() => { EventLog.Insert(0, entry); if (EventLog.Count > 200) EventLog.RemoveAt(EventLog.Count - 1); });
        }

        private void OpenLogFile() { try { _logWriter = new StreamWriter("packet_capture.log", true) { AutoFlush = true }; } catch { } }
        private void LogPacketToFile(PacketInfoItem p) => _logWriter?.WriteLine($"{p.Timestamp},{p.Action},{p.Direction},{p.Protocol},{p.ProcessId},{p.LocalAddress},{p.LocalPort},{p.RemoteAddress},{p.RemotePort},{p.PacketSize}");

        // ================================================================
        // IDisposable
        // ================================================================
        public void Dispose()
        {
            StopCapture();
            // 자가 보호 해제는 여기서 하지 않음!
            // 드라이버의 SelfProtectProcessNotify (PsSetCreateProcessNotifyRoutine)가
            // 프로세스 종료 시 자동으로 보호를 해제함.
            // Dispose에서 해제하면 WM_CLOSE(작업 관리자 "작업 끝내기")로
            // 보호가 무력화되는 취약점이 발생함.
            _logWriter?.Dispose();
            _driver.Dispose();
            GC.SuppressFinalize(this);
        }
    }
}