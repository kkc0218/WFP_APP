using System.ComponentModel;
using System.Windows;
using WfpControlApp.ViewModels;

namespace WfpControlApp.Views
{
    public partial class MainWindow : Window
    {
        private readonly MainViewModel _vm;

        public MainWindow()
        {
            InitializeComponent();
            _vm = new MainViewModel();
            DataContext = _vm;
            Closing += MainWindow_Closing;

            // ViewModel에서 종료 요청 시 Window.Close() 호출
            _vm.CloseWindowRequested += (_, _) => Close();
        }

        private void MainWindow_Closing(object? sender, CancelEventArgs e)
        {
            // 자가 보호가 활성화된 상태에서 사용자가 명시적으로 종료를 요청하지 않았다면
            // WM_CLOSE를 차단 (작업 관리자 "작업 끝내기" 방어)
            if (_vm.SelfProtectionEnabled && !_vm.UserRequestedExit)
            {
                e.Cancel = true;
                return;
            }

            _vm.Dispose();
        }
    }
}