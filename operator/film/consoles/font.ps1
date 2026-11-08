# Set-ConsoleFont: a larger Consolas for this console window only, so the 1080p cut stays readable.
# SetCurrentConsoleFontEx changes the font of the calling console session; the user's registry and
# global console defaults are not touched.
Add-Type -Namespace FilmConsole -Name Font -MemberDefinition @'
[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
public struct Info {
  public uint Size; public uint Index; public short Width; public short Height;
  public int Family; public int Weight;
  [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 32)] public string Face;
}
[DllImport("kernel32.dll", SetLastError = true)] public static extern IntPtr GetStdHandle(int handle);
[DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
public static extern bool SetCurrentConsoleFontEx(IntPtr output, bool maximumWindow, ref Info info);
'@

function Set-ConsoleFont([int]$Height) {
  $info = New-Object FilmConsole.Font+Info
  $info.Size = [Runtime.InteropServices.Marshal]::SizeOf($info)
  $info.Height = $Height; $info.Family = 54; $info.Weight = 400; $info.Face = 'Consolas'
  [void][FilmConsole.Font]::SetCurrentConsoleFontEx([FilmConsole.Font]::GetStdHandle(-11), $false, [ref]$info)
}
