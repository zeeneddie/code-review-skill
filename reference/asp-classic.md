# ASP Classic / VBScript Code Review Guide

> Review guide for ASP Classic (VBScript) codebases. Covers SQL injection, XSS, session security, COM lifecycle, error handling, and database patterns common in legacy healthcare (EPD) and enterprise applications.

## Table of Contents

- [SQL Injection](#sql-injection)
- [Cross-Site Scripting (XSS)](#cross-site-scripting-xss)
- [Session Security](#session-security)
- [File System Operations](#file-system-operations)
- [COM Object Lifecycle](#com-object-lifecycle)
- [Include Directive Security](#include-directive-security)
- [Error Handling](#error-handling)
- [Database Access (ADODB)](#database-access-adodb)
- [Authentication & Authorization](#authentication--authorization)
- [Performance](#performance)
- [Code Organization](#code-organization)
- [Review Checklist](#review-checklist)

---

## SQL Injection

The single most critical vulnerability in ASP Classic codebases. String-concatenated SQL is the default pattern — every instance must be flagged.

### Parameterized Queries vs String Concatenation

```vbscript
' ❌ SQL injection via string concatenation [blocking]
Dim sSQL
sSQL = "SELECT * FROM Patients WHERE PatientID = " & Request("id")
Set rs = conn.Execute(sSQL)

' ❌ Quoting does NOT prevent injection — trivially bypassed
sSQL = "SELECT * FROM Patients WHERE LastName = '" & Request("name") & "'"

' ❌ Replace-based "sanitization" is incomplete and fragile
sInput = Replace(Request("name"), "'", "''")
sSQL = "SELECT * FROM Patients WHERE LastName = '" & sInput & "'"

' ✅ ADODB.Command with parameterized queries
Dim cmd
Set cmd = Server.CreateObject("ADODB.Command")
Set cmd.ActiveConnection = conn
cmd.CommandText = "SELECT * FROM Patients WHERE PatientID = ?"
cmd.Parameters.Append cmd.CreateParameter("@id", adInteger, adParamInput, , CLng(Request("id")))
Set rs = cmd.Execute
```

### Stored Procedures

```vbscript
' ❌ Stored procedure called via string concatenation — still injectable
conn.Execute "EXEC sp_GetPatient '" & Request("id") & "'"

' ✅ Stored procedure with ADODB.Command parameters
Dim cmd
Set cmd = Server.CreateObject("ADODB.Command")
Set cmd.ActiveConnection = conn
cmd.CommandType = adCmdStoredProc
cmd.CommandText = "sp_GetPatient"
cmd.Parameters.Append cmd.CreateParameter("@PatientID", adInteger, adParamInput, , CLng(Request("id")))
Set rs = cmd.Execute
```

### Dynamic ORDER BY / Table Names

```vbscript
' ❌ Dynamic column names from user input — cannot be parameterized
sSQL = "SELECT * FROM Patients ORDER BY " & Request("sort")

' ✅ Whitelist valid column names
Dim allowedColumns
allowedColumns = Array("LastName", "DateOfBirth", "PatientID")
Dim sortCol
sortCol = "PatientID" ' default
Dim i
For i = 0 To UBound(allowedColumns)
    If LCase(Request("sort")) = LCase(allowedColumns(i)) Then
        sortCol = allowedColumns(i)
        Exit For
    End If
Next
sSQL = "SELECT * FROM Patients ORDER BY " & sortCol
```

---

## Cross-Site Scripting (XSS)

### Response.Write Without Encoding

```vbscript
' ❌ Reflected XSS — user input rendered directly [blocking]
Response.Write "Welcome, " & Request("username")

' ❌ Stored XSS — database value rendered without encoding
Response.Write "<td>" & rs("PatientName") & "</td>"

' ✅ Always encode output with Server.HTMLEncode
Response.Write "Welcome, " & Server.HTMLEncode(Request("username"))

' ✅ Encode database-sourced values too
Response.Write "<td>" & Server.HTMLEncode(rs("PatientName")) & "</td>"
```

### Inline HTML Attribute Injection

```vbscript
' ❌ Attribute injection — user can break out of attribute
Response.Write "<input value=""" & Request("q") & """>"

' ✅ Encode within attributes
Response.Write "<input value=""" & Server.HTMLEncode(Request("q")) & """>"

' ❌ JavaScript context — HTMLEncode is NOT sufficient
Response.Write "<script>var name = '" & Request("name") & "';</script>"

' ✅ Avoid inline JavaScript with user input entirely
' Pass data via hidden fields or data-attributes, then read with JS
Response.Write "<div id=""userData"" data-name=""" & Server.HTMLEncode(Request("name")) & """></div>"
```

### URL Encoding

```vbscript
' ❌ Unencoded value in URL — open redirect / injection
Response.Write "<a href=""page.asp?id=" & Request("id") & """>"

' ✅ URL-encode dynamic values in hrefs
Response.Write "<a href=""page.asp?id=" & Server.URLEncode(Request("id")) & """>"
```

---

## Session Security

### Session Fixation & Hijacking

```vbscript
' ❌ No session regeneration after login [important]
If ValidateLogin(username, password) Then
    Session("IsAuthenticated") = True
    Session("UserID") = userID
    Response.Redirect "dashboard.asp"
End If

' ✅ Abandon and recreate session after authentication
If ValidateLogin(username, password) Then
    Session.Abandon
    ' Force new session ID on next request
    Response.Cookies(COOKIE_NAME).Path = "/"
    Response.Cookies(COOKIE_NAME).Expires = DateAdd("h", -1, Now())
    ' Store auth token for pickup on next request
    Application.Lock
    Application("PendingAuth_" & newToken) = userID
    Application.UnLock
    Response.Redirect "post-login.asp?token=" & newToken
End If
```

### Session Cookie Configuration

```vbscript
' ❌ Session cookie without security flags [important]
' (Default ASP session cookies lack HttpOnly and Secure flags)

' ✅ Set secure cookie flags in IIS or via Response headers
' In web.config / IIS:
' <httpCookies httpOnlyCookies="true" requireSSL="true" />
' Or programmatically:
Response.AddHeader "Set-Cookie", "ASPSESSIONID=" & sessionID & "; HttpOnly; Secure; SameSite=Strict"
```

### Session Timeout

```vbscript
' ❌ Excessively long session timeout (default 20 min may be too long for healthcare)
Session.Timeout = 120 ' 2 hours — unacceptable for PHI access

' ✅ Healthcare-appropriate timeout (NEN 7510 recommends 15 min for PHI)
Session.Timeout = 15

' ✅ Check session validity on every protected page
If Session("IsAuthenticated") <> True Then
    Response.Redirect "login.asp"
    Response.End
End If
```

---

## File System Operations

### FileSystemObject Risks

```vbscript
' ❌ Path traversal via user input [blocking]
Dim fso
Set fso = Server.CreateObject("Scripting.FileSystemObject")
Dim filePath
filePath = Server.MapPath("/uploads/" & Request("filename"))
Set f = fso.OpenTextFile(filePath)

' ❌ No validation — attacker uses ../../web.config
' Request("filename") = "../../web.config"

' ✅ Validate filename — strip path separators, whitelist extensions
Dim rawName, safeName
rawName = Request("filename")
' Remove path traversal characters
safeName = Replace(rawName, "..", "")
safeName = Replace(safeName, "/", "")
safeName = Replace(safeName, "\", "")

' Whitelist allowed extensions
Dim ext
ext = LCase(fso.GetExtensionName(safeName))
If ext <> "pdf" And ext <> "txt" And ext <> "csv" Then
    Response.Write "Invalid file type"
    Response.End
End If

filePath = Server.MapPath("/uploads/") & "\" & safeName
' Verify resolved path is within allowed directory
If Left(filePath, Len(Server.MapPath("/uploads/"))) <> Server.MapPath("/uploads/") Then
    Response.Write "Access denied"
    Response.End
End If
Set f = fso.OpenTextFile(filePath)
```

### Cleanup After File Operations

```vbscript
' ❌ File handle left open on error [important]
Set f = fso.OpenTextFile(filePath)
content = f.ReadAll
' If error occurs before Close, handle leaks

' ✅ Always close in cleanup block
On Error Resume Next
Set f = fso.OpenTextFile(filePath)
If Err.Number = 0 Then
    content = f.ReadAll
    f.Close
Else
    ' Log error, do not expose to user
End If
On Error GoTo 0
Set f = Nothing
Set fso = Nothing
```

---

## COM Object Lifecycle

### Proper Cleanup

```vbscript
' ❌ COM objects not released — memory leak [important]
Set conn = Server.CreateObject("ADODB.Connection")
conn.Open connString
Set rs = conn.Execute("SELECT * FROM Patients")
' Page ends without cleanup — objects may persist

' ✅ Always close and release COM objects in reverse order
Set rs = conn.Execute("SELECT * FROM Patients")
' ... process results ...
rs.Close
Set rs = Nothing
conn.Close
Set conn = Nothing
```

### Recordset Handling

```vbscript
' ❌ Accessing closed or BOF/EOF recordset [important]
Set rs = cmd.Execute
value = rs("ColumnName") ' Crashes if recordset is empty

' ✅ Check BOF/EOF before access
Set rs = cmd.Execute
If Not rs.EOF Then
    value = rs("ColumnName")
Else
    value = ""
End If

' ✅ Check for Nothing and closed state
If Not rs Is Nothing Then
    If rs.State = adStateOpen Then
        rs.Close
    End If
    Set rs = Nothing
End If
```

### Connection Pooling Awareness

```vbscript
' ❌ Holding connections open across pages or long operations
' (Prevents connection pool reuse)
Application("GlobalConn") = connString
Set conn = Application("GlobalConn") ' Sharing connection object = thread-unsafe

' ✅ Open late, close early — let connection pooling work
Dim conn
Set conn = Server.CreateObject("ADODB.Connection")
conn.Open Application("ConnString") ' Store connection STRING, not object
' ... execute queries ...
conn.Close
Set conn = Nothing
```

---

## Include Directive Security

### Path Traversal via Includes

```vbscript
' ❌ Include with relative path that may be manipulated [important]
<!--#include file="../../../sensitive/config.asp"-->

' ❌ Virtual include exposing server structure
<!--#include virtual="/admin/dbconfig.asp"-->

' ✅ Include from a controlled, non-web-accessible directory
<!--#include file="includes/db.asp"-->

' ✅ Keep include files outside web root where possible
' Configure IIS to deny direct access to .inc files
' Use .asp extension for includes (IIS processes them, won't serve source)
```

### Sensitive Data in Include Files

```vbscript
' ❌ Database credentials in a .inc file (may be served as plain text) [blocking]
' /includes/config.inc
Dim connString
connString = "Provider=SQLOLEDB;Server=prod-db;Database=EPD;User Id=sa;Password=P@ssw0rd;"

' ✅ Use .asp extension so IIS processes (never serves source)
' /includes/config.asp
<%
Dim connString
connString = "Provider=SQLOLEDB;Server=prod-db;Database=EPD;Integrated Security=SSPI;"
%>

' ✅ Use Windows Integrated Authentication — no password in source
' ✅ Store credentials in IIS application settings or encrypted registry keys
```

---

## Error Handling

### On Error Resume Next Anti-Pattern

```vbscript
' ❌ Blanket On Error Resume Next — silently swallows all errors [important]
On Error Resume Next
Set conn = Server.CreateObject("ADODB.Connection")
conn.Open connString
Set rs = conn.Execute(sSQL)
value = rs("Column")  ' If any line fails, execution continues silently
Response.Write value  ' May write empty/wrong value with no indication of failure

' ✅ Scoped error handling — check after each critical operation
On Error Resume Next
Set conn = Server.CreateObject("ADODB.Connection")
conn.Open connString
If Err.Number <> 0 Then
    ' Log error details (not to user)
    LogError "DB connection failed: " & Err.Description
    Err.Clear
    Response.Write "System unavailable. Please try again later."
    Response.End
End If
On Error GoTo 0  ' Re-enable default error handling
```

### Information Disclosure via Error Messages

```vbscript
' ❌ Exposing error details to user — information disclosure [blocking]
On Error Resume Next
conn.Execute sSQL
If Err.Number <> 0 Then
    Response.Write "Error: " & Err.Description & "<br>"
    Response.Write "SQL: " & sSQL  ' Reveals query structure!
End If

' ✅ Generic user message, detailed server-side logging
If Err.Number <> 0 Then
    Dim errMsg
    errMsg = "Error " & Err.Number & ": " & Err.Description & " | Source: " & Err.Source
    ' Log to file or event log — NOT to Response
    LogError errMsg
    Response.Status = "500 Internal Server Error"
    Response.Write "An error occurred. Reference: " & CreateGUID()
    Response.End
End If

' ✅ Disable detailed errors in IIS for production
' customErrors mode="On" defaultRedirect="error.asp"
```

### Null/Empty Checks

```vbscript
' ❌ No null check on Request or database values [important]
Dim patientID
patientID = Request("id")
conn.Execute "UPDATE Patients SET Status = 1 WHERE ID = " & patientID
' If id is empty, SQL becomes "WHERE ID = " — syntax error or worse

' ✅ Validate and type-check all inputs
Dim patientID
patientID = Trim(Request("id"))
If patientID = "" Or Not IsNumeric(patientID) Then
    Response.Write "Invalid patient ID"
    Response.End
End If
patientID = CLng(patientID)
```

---

## Database Access (ADODB)

### Connection String Security

```vbscript
' ❌ SA account with password in source code [blocking]
connString = "Provider=SQLOLEDB;Server=PROD;Database=EPD;User Id=sa;Password=secret123;"

' ✅ Least-privilege account with Windows auth
connString = "Provider=SQLOLEDB;Server=PROD;Database=EPD;Integrated Security=SSPI;"

' ✅ If SQL auth required, store encrypted in registry/IIS config
' Read from IIS application variable set by administrator
connString = Application("SecureConnString")
```

### Transaction Handling

```vbscript
' ❌ Multiple related writes without transaction [important]
conn.Execute "INSERT INTO Admissions (PatientID, Date) VALUES (1, GETDATE())"
conn.Execute "UPDATE Patients SET Status = 'Admitted' WHERE PatientID = 1"
' If second statement fails, data is inconsistent

' ✅ Wrap related writes in a transaction
conn.BeginTrans
On Error Resume Next
conn.Execute "INSERT INTO Admissions (PatientID, Date) VALUES (1, GETDATE())"
If Err.Number = 0 Then
    conn.Execute "UPDATE Patients SET Status = 'Admitted' WHERE PatientID = 1"
End If
If Err.Number = 0 Then
    conn.CommitTrans
Else
    conn.RollbackTrans
    LogError "Transaction failed: " & Err.Description
End If
On Error GoTo 0
```

### Recordset Cursor Types

```vbscript
' ❌ Using server-side cursor for read-only display [nit]
rs.Open sSQL, conn, adOpenDynamic, adLockOptimistic
' Heavyweight cursor when you only need to read forward

' ✅ Forward-only, read-only cursor for display queries
rs.Open sSQL, conn, adOpenForwardOnly, adLockReadOnly
' Lightest cursor — best performance for rendering HTML tables
```

---

## Authentication & Authorization

### Page-Level Access Control

```vbscript
' ❌ Authorization check missing on protected page [blocking]
' admin/manage-patients.asp
' (No check — anyone who knows the URL can access)
Set rs = conn.Execute("SELECT * FROM Patients")

' ✅ Check authentication AND authorization at top of every protected page
If Session("IsAuthenticated") <> True Then
    Response.Redirect "login.asp"
    Response.End
End If
If Session("Role") <> "Doctor" And Session("Role") <> "Admin" Then
    Response.Status = "403 Forbidden"
    Response.Write "Access denied"
    Response.End
End If
```

### Password Handling

```vbscript
' ❌ Plaintext password comparison [blocking]
sSQL = "SELECT * FROM Users WHERE Username = ? AND Password = '" & Request("password") & "'"

' ❌ MD5 or SHA1 without salt — rainbow table vulnerable
hashedPw = MD5(Request("password"))
sSQL = "SELECT * FROM Users WHERE Username = ? AND PasswordHash = ?"

' ✅ Use salted hash comparison (bcrypt via COM component or stored procedure)
' In modern ASP Classic, delegate hashing to a .NET COM component or SQL CLR function
' The ASP page should NEVER see or compare plaintext passwords
Dim isValid
isValid = ValidatePasswordHash(Request("password"), storedHash, storedSalt)
```

---

## Performance

### Recordset Iteration

```vbscript
' ❌ GetRows not used for large result sets [nit]
Do While Not rs.EOF
    Response.Write rs("Name")
    rs.MoveNext
Loop

' ✅ Use GetRows for large datasets — reduces COM marshalling overhead
Dim dataArray
If Not rs.EOF Then
    dataArray = rs.GetRows()
    Dim row
    For row = 0 To UBound(dataArray, 2)
        Response.Write dataArray(0, row) ' Column 0
    Next
End If
```

### Response Buffering

```vbscript
' ❌ Buffering off — each Response.Write is a network roundtrip [nit]
Response.Buffer = False

' ✅ Enable buffering (default in IIS 6+, but verify)
Response.Buffer = True
' Build complete response, then flush once
```

### String Concatenation in Loops

```vbscript
' ❌ String concatenation in loop — O(n^2) for VBScript strings [important]
Dim html
html = ""
Do While Not rs.EOF
    html = html & "<tr><td>" & Server.HTMLEncode(rs("Name")) & "</td></tr>"
    rs.MoveNext
Loop

' ✅ Use Response.Write inside loop (buffered) — avoids string reallocation
Response.Write "<table>"
Do While Not rs.EOF
    Response.Write "<tr><td>" & Server.HTMLEncode(rs("Name")) & "</td></tr>"
    rs.MoveNext
Loop
Response.Write "</table>"
```

---

## Code Organization

### Separation of Concerns

```vbscript
' ❌ Database queries mixed with HTML rendering in one file [nit]
<%
Set conn = Server.CreateObject("ADODB.Connection")
conn.Open connString
Set rs = conn.Execute("SELECT * FROM Patients")
%>
<html><body>
<% Do While Not rs.EOF %>
    <tr><td><%= rs("Name") %></td></tr>
<% rs.MoveNext : Loop %>
</body></html>

' ✅ Separate data access into include files
' includes/patient_data.asp
<%
Function GetAllPatients(conn)
    Dim cmd
    Set cmd = Server.CreateObject("ADODB.Command")
    Set cmd.ActiveConnection = conn
    cmd.CommandText = "SELECT PatientID, LastName, FirstName FROM Patients ORDER BY LastName"
    Set GetAllPatients = cmd.Execute
    Set cmd = Nothing
End Function
%>

' patients.asp (presentation)
<!--#include file="includes/db.asp"-->
<!--#include file="includes/patient_data.asp"-->
<%
Set conn = GetConnection()
Set rs = GetAllPatients(conn)
%>
<html><!-- render rs here --></html>
```

### Naming Conventions

```vbscript
' ❌ Inconsistent or meaningless names [nit]
Dim x, s, rs1, rs2, temp

' ✅ Hungarian notation (standard for VBScript/ASP Classic)
Dim sPatientName   ' s = string
Dim iCount          ' i = integer
Dim bIsValid        ' b = boolean
Dim rsPatients      ' rs = recordset
Dim connEPD         ' conn = connection
Dim cmdInsert       ' cmd = command
```

---

## Review Checklist

### SQL Injection (Severity: blocking)
- [ ] No string concatenation in SQL statements with user input
- [ ] ADODB.Command with parameters used for all queries
- [ ] Stored procedures called via Command object, not string execution
- [ ] Dynamic column/table names validated against whitelist

### XSS (Severity: blocking)
- [ ] All `Response.Write` of user input uses `Server.HTMLEncode`
- [ ] All `Response.Write` of database values uses `Server.HTMLEncode`
- [ ] URL parameters use `Server.URLEncode`
- [ ] No user input injected into inline `<script>` blocks

### Session & Authentication (Severity: blocking / important)
- [ ] Every protected page checks `Session("IsAuthenticated")` at top
- [ ] Role-based authorization enforced per page
- [ ] Session timeout appropriate for data sensitivity (<=15 min for PHI)
- [ ] Session cookies have HttpOnly and Secure flags

### COM & Resources (Severity: important)
- [ ] All COM objects released (`Set obj = Nothing`) after use
- [ ] Recordsets closed before being set to Nothing
- [ ] Connections closed before being set to Nothing
- [ ] BOF/EOF checked before recordset access
- [ ] FileSystemObject paths validated against traversal

### Error Handling (Severity: important)
- [ ] `On Error Resume Next` is scoped, not file-wide
- [ ] `Err.Number` checked after each critical operation
- [ ] Error details logged server-side, not exposed to users
- [ ] `On Error GoTo 0` restores default handling after scoped blocks

### Database (Severity: important)
- [ ] Connection strings use Windows auth or encrypted credentials
- [ ] Related writes wrapped in transactions
- [ ] Forward-only cursors used for read operations
- [ ] No SA account in connection strings

### Code Quality (Severity: nit)
- [ ] Include files use `.asp` extension (not `.inc`)
- [ ] Hungarian notation used consistently
- [ ] Response buffering enabled
- [ ] String concatenation in loops avoided (use `Response.Write`)
