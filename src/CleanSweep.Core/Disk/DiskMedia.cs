using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace CleanSweep.Core.Disk;

/// <summary>
/// 介质识别：通过 IOCTL_STORAGE_QUERY_PROPERTY 询问卷所在设备是否有寻道开销（StorageDeviceSeekPenaltyProperty）。
/// 没有寻道开销即固态盘。不需要管理员权限。查询失败返回 null（不可判定）。
/// </summary>
public static class DiskMedia
{
    private const uint IoctlStorageQueryProperty = 0x002D1400;
    private const int StorageDeviceSeekPenaltyProperty = 7;
    private const int StorageDeviceTrimProperty = 8;

    [StructLayout(LayoutKind.Sequential)]
    private struct StoragePropertyQuery
    {
        public int PropertyId;
        public int QueryType;
        public byte AdditionalParameters;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct DeviceSeekPenaltyDescriptor
    {
        public uint Version;
        public uint Size;
        [MarshalAs(UnmanagedType.U1)] public bool IncursSeekPenalty;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct DeviceTrimDescriptor
    {
        public uint Version;
        public uint Size;
        [MarshalAs(UnmanagedType.U1)] public bool TrimEnabled;
    }

    /// <summary>测试可替换。</summary>
    public static Func<string, bool?> SolidStateProbe { get; set; } = QuerySolidState;

    /// <summary>path 所在卷是否为固态盘。true = SSD / NVMe，false = 机械盘，null = 无法判定（网络盘、虚拟盘、无权限）。</summary>
    public static bool? IsSolidState(string path)
    {
        try
        {
            var root = Path.GetPathRoot(Path.GetFullPath(path));
            if (string.IsNullOrEmpty(root) || root.StartsWith(@"\\")) return null;
            return SolidStateProbe(root);
        }
        catch
        {
            return null;
        }
    }

    private static bool? QuerySolidState(string root)
    {
        var penalty = QueryBool(root, StorageDeviceSeekPenaltyProperty, isTrim: false);
        if (penalty is not null) return !penalty.Value;
        // 退路：支持 TRIM 的基本都是固态
        var trim = QueryBool(root, StorageDeviceTrimProperty, isTrim: true);
        return trim;
    }

    private static bool? QueryBool(string root, int propertyId, bool isTrim)
    {
        var volume = @"\\.\" + root.TrimEnd('\\');
        using var h = CreateFileW(volume, 0, FileShare.ReadWrite, IntPtr.Zero, FileMode.Open, 0, IntPtr.Zero);
        if (h.IsInvalid) return null;

        var query = new StoragePropertyQuery { PropertyId = propertyId, QueryType = 0 };
        var inSize = Marshal.SizeOf<StoragePropertyQuery>();
        var inPtr = Marshal.AllocHGlobal(inSize);
        var outSize = Math.Max(Marshal.SizeOf<DeviceSeekPenaltyDescriptor>(), Marshal.SizeOf<DeviceTrimDescriptor>());
        var outPtr = Marshal.AllocHGlobal(outSize);
        try
        {
            Marshal.StructureToPtr(query, inPtr, false);
            if (!DeviceIoControl(h, IoctlStorageQueryProperty, inPtr, (uint)inSize, outPtr, (uint)outSize, out _, IntPtr.Zero)) return null;
            return isTrim ? Marshal.PtrToStructure<DeviceTrimDescriptor>(outPtr).TrimEnabled : Marshal.PtrToStructure<DeviceSeekPenaltyDescriptor>(outPtr).IncursSeekPenalty;
        }
        finally
        {
            Marshal.FreeHGlobal(inPtr);
            Marshal.FreeHGlobal(outPtr);
        }
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeFileHandle CreateFileW(string lpFileName, uint dwDesiredAccess, FileShare dwShareMode, IntPtr lpSecurityAttributes,
        FileMode dwCreationDisposition, uint dwFlagsAndAttributes, IntPtr hTemplateFile);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool DeviceIoControl(SafeFileHandle hDevice, uint dwIoControlCode, IntPtr lpInBuffer, uint nInBufferSize, IntPtr lpOutBuffer,
        uint nOutBufferSize, out uint lpBytesReturned, IntPtr lpOverlapped);
}
