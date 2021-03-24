# DebuggerVMDetectionCPlusPlus
Example of dll in C++ for detecting if your application is running in VM or Debugger environment.
You can use if for example to detect if someone is trying to crack your application or debug the flow. 

Example on how to call it from .NET windows APP would be:

[DllImport("detect.dll", CharSet = CharSet.Auto, SetLastError = true,CallingConvention =CallingConvention.StdCall)] // relative path; just give the DLL's name
public static extern bool IsUnderAnyVM();

[DllImport("detect.dll", CharSet = CharSet.Auto, SetLastError = true, CallingConvention = CallingConvention.StdCall)] // relative path; just give the DLL's name
public static extern bool IsAnyDebuggerFound();
[DllImport("detect.dll", CharSet = CharSet.Auto, SetLastError = true, CallingConvention = CallingConvention.StdCall)] // relative path; just give the DLL's name
public static extern void NotifyVMPresence();

private void button1_Click(object sender, EventArgs e)
{
    NotifyVMPresence();

}

private void button2_Click(object sender, EventArgs e)
{
    if (IsAnyDebuggerFound())
        MessageBox.Show("Debugger found");
    else
        MessageBox.Show("Debugger not found");
}
