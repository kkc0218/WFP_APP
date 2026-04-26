using System;
using System.Globalization;
using System.Windows;
using System.Windows.Data;
using System.Windows.Media;

namespace WfpControlApp.Converters
{
    public class BoolToVisibilityConverter : IValueConverter
    {
        public object Convert(object value, Type t, object p, CultureInfo c) =>
            value is bool b && b ? Visibility.Visible : Visibility.Collapsed;
        public object ConvertBack(object value, Type t, object p, CultureInfo c) => throw new NotImplementedException();
    }

    public class InverseBoolToVisibilityConverter : IValueConverter
    {
        public object Convert(object value, Type t, object p, CultureInfo c) =>
            value is bool b && b ? Visibility.Collapsed : Visibility.Visible;
        public object ConvertBack(object value, Type t, object p, CultureInfo c) => throw new NotImplementedException();
    }

    public class InverseBoolConverter : IValueConverter
    {
        public object Convert(object value, Type t, object p, CultureInfo c) => !(value is bool b && b);
        public object ConvertBack(object value, Type t, object p, CultureInfo c) => !(value is bool b && b);
    }

    public class BoolToOnOffConverter : IValueConverter
    {
        public object Convert(object value, Type t, object p, CultureInfo c) =>
            value is bool b && b ? "ON" : "OFF";
        public object ConvertBack(object value, Type t, object p, CultureInfo c) => throw new NotImplementedException();
    }

    public class BoolToBrushConverter : IValueConverter
    {
        public object Convert(object value, Type t, object p, CultureInfo c) =>
            value is bool b && b
                ? new SolidColorBrush(Color.FromRgb(0x00, 0xC8, 0x53))
                : new SolidColorBrush(Color.FromRgb(0xFF, 0x3D, 0x3D));
        public object ConvertBack(object value, Type t, object p, CultureInfo c) => throw new NotImplementedException();
    }

    public class TabEqualsConverter : IValueConverter
    {
        public object Convert(object value, Type t, object parameter, CultureInfo c) =>
            value is string s && parameter is string p && s == p ? Visibility.Visible : Visibility.Collapsed;
        public object ConvertBack(object value, Type t, object p, CultureInfo c) => throw new NotImplementedException();
    }

    public class TabEqualsBoolConverter : IValueConverter
    {
        public object Convert(object value, Type t, object parameter, CultureInfo c) =>
            value is string s && parameter is string p && s == p;
        public object ConvertBack(object value, Type t, object p, CultureInfo c) => throw new NotImplementedException();
    }

    public class ActionToBrushConverter : IValueConverter
    {
        public object Convert(object value, Type t, object p, CultureInfo c) =>
            value is string s && s == "BLOCK"
                ? new SolidColorBrush(Color.FromRgb(0xFF, 0x3D, 0x3D))
                : new SolidColorBrush(Color.FromRgb(0x00, 0xC8, 0x53));
        public object ConvertBack(object value, Type t, object p, CultureInfo c) => throw new NotImplementedException();
    }

    public class BytesToDisplayConverter : IValueConverter
    {
        public object Convert(object value, Type t, object p, CultureInfo c)
        {
            if (value is uint bytes)
            {
                if (bytes >= 1048576) return $"{bytes / 1048576} MB";
                if (bytes >= 1024) return $"{bytes / 1024} KB";
                return $"{bytes} B";
            }
            return "N/A";
        }
        public object ConvertBack(object value, Type t, object p, CultureInfo c) => throw new NotImplementedException();
    }

}