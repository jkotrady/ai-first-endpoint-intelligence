Option Explicit
' Lab-only inventory. No remote connection, process launch, or WMI mutation.
' Run with cscript //B //NoLogo //T:60. Windows runtime is not yet verified.
Dim fso, root, folder, output, svc, failures
On Error Resume Next
Set fso = CreateObject("Scripting.FileSystemObject")
If Err.Number <> 0 Then WScript.Quit 3
If LCase(fso.GetFileName(WScript.FullName)) <> "cscript.exe" Then WScript.Quit 3
root = fso.GetParentFolderName(WScript.ScriptFullName)
If Left(root, 2) = "\\" Then WScript.Quit 3
If fso.GetDrive(fso.GetDriveName(root)).DriveType <> 2 Then WScript.Quit 3
folder = fso.BuildPath(root, "result")
If fso.FolderExists(folder) Or fso.FileExists(folder) Then WScript.Quit 3
Err.Clear
fso.CreateFolder folder
If Err.Number <> 0 Then WScript.Quit 3
Set output = fso.CreateTextFile(fso.BuildPath(folder, "observations.txt"), False, True)
If Err.Number <> 0 Then WScript.Quit 3
On Error GoTo 0
failures = 0
Emit "schema", "legacy-intake-1"
Emit "kit_version", "0.1.0"
Emit "scope", "local_wmi_observations_only"

On Error Resume Next
Set svc = GetObject("winmgmts:{impersonationLevel=impersonate}!\\.\root\cimv2")
If Err.Number <> 0 Then
    Emit "error.connection", Hex(Err.Number)
    Emit "end", "partial"
    output.Close
    WScript.Quit 2
End If
On Error GoTo 0

Capture "os", "Win32_OperatingSystem", "Caption,Version,BuildNumber,ServicePackMajorVersion,ServicePackMinorVersion,ProductType,TotalVisibleMemorySize,FreePhysicalMemory,Locale,CurrentTimeZone", "", 1
Capture "cpu", "Win32_Processor", "AddressWidth,DataWidth,Architecture", "", 16
Capture "disk", "Win32_LogicalDisk", "DeviceID,Size,FreeSpace,FileSystem", " WHERE DriveType=3", 26
If failures = 0 Then
    Emit "end", "complete"
Else
    Emit "end", "partial"
End If
output.Close
If failures <> 0 Then WScript.Quit 2
WScript.Quit 0

Sub Emit(key, value)
    Dim textValue
    textValue = CStr(value)
    textValue = Replace(Replace(Replace(textValue, vbCr, " "), vbLf, " "), vbTab, " ")
    If Len(textValue) > 1024 Then
        textValue = Left(textValue, 1024)
        failures = failures + 1
    End If
    On Error Resume Next
    Err.Clear
    output.WriteLine key & "=" & textValue
    If Err.Number <> 0 Then WScript.Quit 3
    On Error GoTo 0
End Sub

Sub Capture(prefix, className, properties, condition, maxRows)
    Dim rows, item, prop, fields, value, rowIndex, code
    fields = Split(properties, ",")
    rowIndex = 0
    On Error Resume Next
    Err.Clear
    Set rows = svc.ExecQuery("SELECT " & properties & " FROM " & className & condition, "WQL", 48)
    If Err.Number <> 0 Then
        code = Hex(Err.Number)
        failures = failures + 1
        Emit "error." & prefix, code
        Emit prefix & ".count", 0
        Exit Sub
    End If
    For Each item In rows
        If Err.Number <> 0 Then Exit For
        If rowIndex >= maxRows Then
            failures = failures + 1
            Emit "error." & prefix & ".limit", "row_limit"
            Exit For
        End If
        For Each prop In fields
            Err.Clear
            value = item.Properties_(prop).Value
            If Err.Number <> 0 Then
                code = Hex(Err.Number)
                failures = failures + 1
                Emit "error." & prefix & "." & rowIndex & "." & prop, code
            ElseIf IsNull(value) Or IsEmpty(value) Then
                failures = failures + 1
                Emit "error." & prefix & "." & rowIndex & "." & prop, "null"
            Else
                Emit prefix & "." & rowIndex & "." & prop, value
            End If
        Next
        rowIndex = rowIndex + 1
        Err.Clear
    Next
    If Err.Number <> 0 Then
        code = Hex(Err.Number)
        failures = failures + 1
        Emit "error." & prefix & ".enumeration", code
    End If
    If rowIndex = 0 Then
        failures = failures + 1
        Emit "error." & prefix & ".empty", "no_rows"
    End If
    Emit prefix & ".count", rowIndex
    On Error GoTo 0
End Sub
