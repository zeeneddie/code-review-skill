# VB.NET Code Review Guide

> Review guide for VB.NET codebases covering Option Strict, async patterns, COM interop, LINQ pitfalls, WebForms vs MVC security, exception handling, and .NET Framework to .NET migration considerations.

## Table of Contents

- [Option Strict and Option Explicit](#option-strict-and-option-explicit)
- [Type Safety](#type-safety)
- [Async/Await Patterns](#asyncawait-patterns)
- [Exception Handling](#exception-handling)
- [LINQ Best Practices](#linq-best-practices)
- [String Handling](#string-handling)
- [COM Interop](#com-interop)
- [WebForms Security](#webforms-security)
- [Memory Management](#memory-management)
- [Collections and Generics](#collections-and-generics)
- [Migration Considerations](#migration-considerations)
- [Testing](#testing)
- [Review Checklist](#review-checklist)

---

## Option Strict and Option Explicit

### Option Strict Off — The Silent Bug Factory

```vb
' ❌ Option Strict Off allows implicit narrowing conversions [blocking]
Option Strict Off

Dim total As Integer = 100
Dim rate As Double = 3.14
total = rate  ' Silently truncates to 3 — no compiler error!

Dim name As String = 42  ' Implicit conversion — compiles but wrong intent

' ❌ Late binding with Option Strict Off — runtime errors instead of compile-time
Dim obj As Object = GetSomeObject()
obj.DoSomething()  ' No IntelliSense, no compile check, crashes at runtime if method missing

' ✅ Option Strict On — catches all implicit conversions at compile time
Option Strict On

Dim total As Integer = 100
Dim rate As Double = 3.14
total = CInt(rate)  ' Explicit conversion required — developer sees the truncation

Dim name As String = CStr(42)  ' Intent is clear
```

### Option Explicit

```vb
' ❌ Option Explicit Off — typos create new variables silently [blocking]
Option Explicit Off

Dim patientCount As Integer = 10
pateintCount = 20  ' Typo creates NEW variable, original unchanged!
' patientCount is still 10 — silent logic bug

' ✅ Option Explicit On (should always be on)
Option Explicit On
' Compiler error: 'pateintCount' is not declared
```

### Project-Level Settings

```vb
' ❌ Relying on file-level directives — inconsistent across files [important]
' Some files have Option Strict On, others don't

' ✅ Set at project level in .vbproj
' <PropertyGroup>
'   <OptionStrict>On</OptionStrict>
'   <OptionExplicit>On</OptionExplicit>
'   <OptionInfer>On</OptionInfer>
' </PropertyGroup>
```

---

## Type Safety

### CType vs DirectCast vs TryCast

```vb
' ❌ Using CType for everything — slower, can mask type errors [nit]
Dim ctrl As TextBox = CType(sender, TextBox)

' ✅ DirectCast when you know the exact type — faster, fails clearly
Dim ctrl As TextBox = DirectCast(sender, TextBox)

' ✅ TryCast when type is uncertain — returns Nothing instead of exception
Dim ctrl As TextBox = TryCast(sender, TextBox)
If ctrl IsNot Nothing Then
    ctrl.Text = "Updated"
End If

' ❌ Checking type then casting separately — double work
If TypeOf sender Is TextBox Then
    Dim tb As TextBox = DirectCast(sender, TextBox)
    tb.Text = "value"
End If

' ✅ Pattern matching (VB 14+ / .NET 5+)
If TypeOf sender Is TextBox tb Then
    tb.Text = "value"
End If
```

### Nothing Checks

```vb
' ❌ Not checking for Nothing before access [important]
Dim user As User = GetUser(id)
Dim name As String = user.Name  ' NullReferenceException if user is Nothing

' ✅ Guard clause
Dim user As User = GetUser(id)
If user Is Nothing Then
    Throw New ArgumentException($"User {id} not found")
End If
Dim name As String = user.Name

' ✅ Null-conditional operator (VB 14+)
Dim name As String = user?.Name

' ✅ Null-coalescing via If()
Dim displayName As String = If(user?.Name, "Unknown")
```

---

## Async/Await Patterns

### Async Sub vs Async Function

```vb
' ❌ Async Sub — exceptions cannot be caught by caller [blocking]
' Only valid for event handlers (Button_Click, etc.)
Public Async Sub ProcessDataAsync()
    Await Task.Delay(1000)
    Throw New InvalidOperationException("Oops")
    ' This exception crashes the process — no way to catch it!
End Sub

' ✅ Async Function — returns Task, exceptions propagate normally
Public Async Function ProcessDataAsync() As Task
    Await Task.Delay(1000)
    ' Exceptions are captured in the returned Task
End Function

' ✅ Async Sub is ONLY acceptable for event handlers
Private Async Sub btnSave_Click(sender As Object, e As EventArgs) Handles btnSave.Click
    Try
        Await SavePatientAsync()
    Catch ex As Exception
        MessageBox.Show(ex.Message)
    End Try
End Sub
```

### Blocking on Async Code

```vb
' ❌ .Result / .Wait() — deadlock risk in UI/ASP.NET contexts [blocking]
Public Function GetData() As String
    Dim result = GetDataAsync().Result  ' Deadlock!
    Return result
End Function

' ❌ .GetAwaiter().GetResult() — same deadlock risk
Public Function GetData() As String
    Return GetDataAsync().GetAwaiter().GetResult()
End Function

' ✅ Async all the way
Public Async Function GetDataAsync() As Task(Of String)
    Dim result = Await httpClient.GetStringAsync(url)
    Return result
End Function

' ✅ If truly needed from sync context (rare), use thread pool
Public Function GetDataFromSync() As String
    Return Task.Run(Function() GetDataAsync()).Result
End Function
```

### ConfigureAwait in Library Code

```vb
' ❌ Library code capturing synchronization context unnecessarily [important]
Public Async Function FetchAsync() As Task(Of String)
    Dim response = Await client.GetAsync(url)
    Return Await response.Content.ReadAsStringAsync()
End Function

' ✅ Use ConfigureAwait(False) in library/non-UI code
Public Async Function FetchAsync() As Task(Of String)
    Dim response = Await client.GetAsync(url).ConfigureAwait(False)
    Return Await response.Content.ReadAsStringAsync().ConfigureAwait(False)
End Function
```

### CancellationToken Propagation

```vb
' ❌ Ignoring CancellationToken — operations cannot be cancelled [important]
Public Async Function SearchPatientsAsync(query As String) As Task(Of List(Of Patient))
    Return Await db.Patients.Where(Function(p) p.Name.Contains(query)).ToListAsync()
End Function

' ✅ Accept and propagate CancellationToken
Public Async Function SearchPatientsAsync(query As String,
        Optional ct As CancellationToken = Nothing) As Task(Of List(Of Patient))
    Return Await db.Patients _
        .Where(Function(p) p.Name.Contains(query)) _
        .ToListAsync(ct)
End Function
```

---

## Exception Handling

### Catch-All Anti-Patterns

```vb
' ❌ Empty Catch block — silently swallows errors [blocking]
Try
    ProcessPatientData(data)
Catch ex As Exception
    ' Nothing — error is invisible
End Try

' ❌ Catching Exception and only logging — losing the error
Try
    ProcessPatientData(data)
Catch ex As Exception
    Debug.WriteLine(ex.Message)
End Try

' ✅ Catch specific exceptions, re-throw or handle meaningfully
Try
    ProcessPatientData(data)
Catch ex As ValidationException
    logger.LogWarning(ex, "Validation failed for patient {Id}", data.PatientId)
    Throw  ' Re-throw preserving stack trace
Catch ex As DbUpdateException
    logger.LogError(ex, "Database error saving patient {Id}", data.PatientId)
    Throw New DataAccessException($"Failed to save patient {data.PatientId}", ex)
End Try
```

### Exception Filters (When Clause)

```vb
' ❌ Catching then re-throwing based on condition — resets stack trace
Try
    CallExternalService()
Catch ex As HttpRequestException
    If ex.StatusCode = HttpStatusCode.NotFound Then
        Return Nothing
    End If
    Throw  ' Stack trace partially preserved but filter is cleaner
End Try

' ✅ Use When clause — exception filter, no stack trace corruption
Try
    CallExternalService()
Catch ex As HttpRequestException When ex.StatusCode = HttpStatusCode.NotFound
    Return Nothing
Catch ex As HttpRequestException When ex.StatusCode = HttpStatusCode.ServiceUnavailable
    Await Task.Delay(1000)
    Return Await CallExternalService()  ' Retry
End Try
```

### Finally Block for Resource Cleanup

```vb
' ❌ Cleanup only in Try — skipped on exception [important]
Try
    Dim stream = File.OpenRead(path)
    Dim data = ReadAll(stream)
    stream.Close()  ' Never reached if ReadAll throws
Catch ex As IOException
    logger.LogError(ex, "Read failed")
End Try

' ✅ Cleanup in Finally — always executes
Dim stream As FileStream = Nothing
Try
    stream = File.OpenRead(path)
    Dim data = ReadAll(stream)
Catch ex As IOException
    logger.LogError(ex, "Read failed")
    Throw
Finally
    stream?.Close()
End Try

' ✅ Even better — Using statement (IDisposable)
Using stream As FileStream = File.OpenRead(path)
    Dim data = ReadAll(stream)
End Using
```

---

## LINQ Best Practices

### Deferred Execution Pitfalls

```vb
' ❌ Deferred execution executed multiple times [important]
Dim expiredPatients = patients.Where(Function(p) p.IsExpired())
Dim count = expiredPatients.Count()  ' Executes query
For Each p In expiredPatients         ' Executes query AGAIN
    Notify(p)
Next

' ✅ Materialize once if used multiple times
Dim expiredPatients = patients.Where(Function(p) p.IsExpired()).ToList()
Dim count = expiredPatients.Count  ' Uses cached list
For Each p In expiredPatients       ' Uses cached list
    Notify(p)
Next
```

### Query Syntax vs Method Syntax

```vb
' ❌ Overly complex query syntax for simple operations [nit]
Dim names = From p In patients
            Where p.IsActive
            Select p.Name

' ✅ Method syntax is often clearer for simple queries
Dim names = patients.Where(Function(p) p.IsActive).Select(Function(p) p.Name)

' ✅ Query syntax is better for joins and complex grouping
Dim result = From p In patients
             Join a In appointments On p.Id Equals a.PatientId
             Where a.Date > DateTime.Today
             Group By p.Name Into AppointmentCount = Count()
             Order By AppointmentCount Descending
             Select Name, AppointmentCount
```

### Client-Side vs Server-Side Evaluation

```vb
' ❌ Calling .ToList() before filtering — loads entire table [blocking]
Dim results = db.Patients.ToList().Where(Function(p) p.City = "Amsterdam")
' Fetches ALL patients, then filters in memory

' ✅ Filter on server, then materialize
Dim results = Await db.Patients _
    .Where(Function(p) p.City = "Amsterdam") _
    .ToListAsync()
```

### Common LINQ Mistakes

```vb
' ❌ FirstOrDefault without null check [important]
Dim patient = patients.FirstOrDefault(Function(p) p.Id = id)
Dim name = patient.Name  ' NullReferenceException if not found

' ✅ Check for Nothing
Dim patient = patients.FirstOrDefault(Function(p) p.Id = id)
If patient Is Nothing Then
    Throw New PatientNotFoundException(id)
End If

' ❌ Count() > 0 instead of Any()
If patients.Count() > 0 Then  ' Counts ALL items

' ✅ Any() short-circuits at first match
If patients.Any() Then
```

---

## String Handling

### StringBuilder vs Concatenation

```vb
' ❌ String concatenation in loop — O(n^2) [important]
Dim result As String = ""
For Each item In largeCollection
    result &= item.ToString() & Environment.NewLine
Next

' ✅ StringBuilder for loop-based string building
Dim sb As New StringBuilder()
For Each item In largeCollection
    sb.AppendLine(item.ToString())
Next
Dim result As String = sb.ToString()
```

### String Interpolation

```vb
' ❌ String.Format with positional indices — error-prone [nit]
Dim msg = String.Format("Patient {0} admitted on {1} by Dr. {2}", name, date, doctor)

' ✅ String interpolation (VB 14+)
Dim msg = $"Patient {name} admitted on {date:yyyy-MM-dd} by Dr. {doctor}"
```

### String Comparison

```vb
' ❌ Case-insensitive comparison via ToLower — allocates new string [nit]
If username.ToLower() = "admin" Then

' ✅ Use String.Equals with comparison type
If String.Equals(username, "admin", StringComparison.OrdinalIgnoreCase) Then

' ✅ For culture-sensitive comparison (names, addresses)
If String.Compare(name1, name2, StringComparison.CurrentCultureIgnoreCase) = 0 Then
```

---

## COM Interop

### Memory Leaks with COM Objects

```vb
' ❌ COM object not explicitly released — GC timing unpredictable [important]
Dim excelApp As New Microsoft.Office.Interop.Excel.Application()
Dim workbook = excelApp.Workbooks.Open(path)
Dim sheet = workbook.Sheets(1)
' sheet, workbook, excelApp all leak — Excel process stays running

' ✅ Release COM objects in reverse order of creation
Dim excelApp As Microsoft.Office.Interop.Excel.Application = Nothing
Dim workbook As Microsoft.Office.Interop.Excel.Workbook = Nothing
Dim sheet As Microsoft.Office.Interop.Excel.Worksheet = Nothing
Try
    excelApp = New Microsoft.Office.Interop.Excel.Application()
    workbook = excelApp.Workbooks.Open(path)
    sheet = DirectCast(workbook.Sheets(1), Microsoft.Office.Interop.Excel.Worksheet)
    ' ... process data ...
Finally
    If sheet IsNot Nothing Then Marshal.ReleaseComObject(sheet)
    If workbook IsNot Nothing Then
        workbook.Close(False)
        Marshal.ReleaseComObject(workbook)
    End If
    If excelApp IsNot Nothing Then
        excelApp.Quit()
        Marshal.ReleaseComObject(excelApp)
    End If
End Try
```

### Two-Dot Rule

```vb
' ❌ Chained COM property access — intermediate objects leak [important]
Dim value = excelApp.Workbooks.Item(1).Sheets.Item(1).Cells(1, 1).Value
' Multiple intermediate COM objects created but never released

' ✅ Assign each intermediate COM object to a variable for cleanup
Dim workbooks = excelApp.Workbooks
Dim workbook = workbooks.Item(1)
Dim sheets = workbook.Sheets
Dim sheet = DirectCast(sheets.Item(1), Worksheet)
Dim cell = DirectCast(sheet.Cells(1, 1), Range)
Dim value = cell.Value

' Release ALL in reverse order in Finally block
Marshal.ReleaseComObject(cell)
Marshal.ReleaseComObject(sheet)
Marshal.ReleaseComObject(sheets)
Marshal.ReleaseComObject(workbook)
Marshal.ReleaseComObject(workbooks)
```

---

## WebForms Security

### ViewState Tampering

```vb
' ❌ Sensitive data in ViewState without MAC validation [blocking]
ViewState("PatientBSN") = "123456789"
' ViewState is base64-encoded, NOT encrypted by default

' ✅ Enable ViewState MAC validation (default in .NET 4.5+, verify it's not disabled)
' web.config: <pages enableViewStateMac="true" viewStateEncryptionMode="Always" />

' ✅ Better: don't put sensitive data in ViewState at all
Session("PatientBSN") = "123456789"  ' Server-side storage
```

### Request Validation

```vb
' ❌ Disabling request validation page-wide [blocking]
<%@ Page ValidateRequest="false" %>

' ❌ Disabling validation in web.config
' <httpRuntime requestValidationMode="2.0" />

' ✅ Keep request validation on, decode only where needed
' If you must accept HTML input, use a whitelist sanitizer
Dim sanitized = Sanitizer.GetSafeHtml(rawInput)
```

### Event Validation Bypass

```vb
' ❌ Disabling event validation [blocking]
<%@ Page EnableEventValidation="false" %>

' ✅ Keep event validation enabled
' If you need dynamic controls, register them properly:
Protected Overrides Sub Render(writer As HtmlTextWriter)
    For Each item In dynamicItems
        ClientScript.RegisterForEventValidation(item.UniqueID)
    Next
    MyBase.Render(writer)
End Sub
```

---

## Memory Management

### IDisposable Implementation

```vb
' ❌ Not disposing database connections [blocking]
Public Function GetPatients() As List(Of Patient)
    Dim conn As New SqlConnection(connString)
    conn.Open()
    ' ... query ...
    Return results
    ' Connection never closed!
End Function

' ✅ Using statement ensures disposal
Public Function GetPatients() As List(Of Patient)
    Using conn As New SqlConnection(connString)
        conn.Open()
        ' ... query ...
        Return results
    End Using  ' Automatically calls conn.Dispose()
End Function

' ✅ Multiple Using blocks
Using conn As New SqlConnection(connString)
    conn.Open()
    Using cmd As New SqlCommand(sql, conn)
        Using reader = cmd.ExecuteReader()
            ' ... process ...
        End Using
    End Using
End Using
```

### Large Object Heap Fragmentation

```vb
' ❌ Frequently allocating large arrays (>85KB) [important]
For i = 1 To 10000
    Dim buffer(100000) As Byte  ' Goes to LOH, causes fragmentation
    ProcessBuffer(buffer)
Next

' ✅ Reuse buffers via ArrayPool
Dim buffer = ArrayPool(Of Byte).Shared.Rent(100000)
Try
    ProcessBuffer(buffer)
Finally
    ArrayPool(Of Byte).Shared.Return(buffer)
End Try
```

---

## Collections and Generics

### Non-Generic Collections

```vb
' ❌ Using non-generic collections — boxing, no type safety [important]
Dim items As New ArrayList()
items.Add(42)       ' Boxing
items.Add("hello")  ' No type check!
Dim value As Integer = CInt(items(1))  ' InvalidCastException at runtime

' ✅ Use generic collections
Dim items As New List(Of Integer)()
items.Add(42)
' items.Add("hello")  ' Compile error!
Dim value As Integer = items(0)  ' No cast needed
```

### Dictionary Key Comparison

```vb
' ❌ Dictionary with case-sensitive keys when case-insensitive needed [important]
Dim lookup As New Dictionary(Of String, Patient)()
lookup.Add("SMITH", patient1)
Dim found = lookup("smith")  ' KeyNotFoundException!

' ✅ Specify comparer at construction
Dim lookup As New Dictionary(Of String, Patient)(StringComparer.OrdinalIgnoreCase)
lookup.Add("SMITH", patient1)
Dim found = lookup("smith")  ' Works
```

---

## Migration Considerations

### .NET Framework to .NET 8+ Differences

```vb
' ❌ APIs removed in .NET 8 [blocking for migration]
' System.Web namespace is gone (HttpContext.Current, etc.)
Dim user = HttpContext.Current.User  ' Does not exist in .NET 8

' ✅ Use dependency injection for HttpContext in .NET 8
Public Class PatientService
    Private ReadOnly _httpContextAccessor As IHttpContextAccessor

    Public Sub New(accessor As IHttpContextAccessor)
        _httpContextAccessor = accessor
    End Sub

    Public Function GetCurrentUser() As ClaimsPrincipal
        Return _httpContextAccessor.HttpContext?.User
    End Function
End Class

' ❌ AppDomain (unavailable in .NET 8)
Dim domain = AppDomain.CreateDomain("sandbox")

' ✅ Use AssemblyLoadContext instead
Dim context As New AssemblyLoadContext("sandbox", isCollectible:=True)
```

### WebForms to Razor/Blazor

```vb
' ❌ WebForms code-behind pattern (not supported in .NET 8) [important for migration]
' Default.aspx.vb
Partial Class _Default
    Inherits Page
    Protected Sub btnSubmit_Click(sender As Object, e As EventArgs)
        lblResult.Text = txtInput.Text
    End Sub
End Class

' ✅ Razor Pages equivalent (.NET 8)
' Pages/Index.cshtml.vb (or .vb with VB support — limited)
' Note: Razor Pages/Blazor have limited VB.NET support
' Consider C# for new UI code, keep VB.NET for business logic libraries
```

### Configuration Changes

```vb
' ❌ web.config ConfigurationManager (works but legacy pattern) [nit]
Dim connStr = ConfigurationManager.ConnectionStrings("EPD").ConnectionString

' ✅ .NET 8 configuration via DI
Public Class PatientRepository
    Private ReadOnly _connectionString As String

    Public Sub New(config As IConfiguration)
        _connectionString = config.GetConnectionString("EPD")
    End Sub
End Class
```

---

## Testing

### Unit Testing VB.NET

```vb
' ❌ No assertion message — unclear what failed [nit]
<Fact>
Public Sub TestPatientAge()
    Dim p As New Patient() With {.DateOfBirth = #1/1/1990#}
    Assert.Equal(36, p.Age)
End Sub

' ✅ Descriptive test name and focused assertion
<Fact>
Public Sub Patient_Age_CalculatedFromDateOfBirth()
    ' Arrange
    Dim patient As New Patient() With {
        .DateOfBirth = New DateTime(1990, 1, 1)
    }

    ' Act
    Dim age = patient.Age

    ' Assert
    Assert.Equal(36, age)
End Sub

' ✅ Parameterized tests
<Theory>
<InlineData("", False)>
<InlineData("123456789", True)>
<InlineData("12345678", False)>
<InlineData("1234567890", False)>
Public Sub BSN_Validation_HandlesVariousInputs(bsn As String, expected As Boolean)
    Assert.Equal(expected, BsnValidator.IsValid(bsn))
End Sub
```

---

## Review Checklist

### Type Safety (Severity: blocking)
- [ ] `Option Strict On` at project level
- [ ] `Option Explicit On` at project level
- [ ] No use of late-bound `Object` types without justification
- [ ] `DirectCast` / `TryCast` preferred over `CType`

### Async (Severity: blocking / important)
- [ ] No `Async Sub` except for event handlers
- [ ] No `.Result` or `.Wait()` calls (deadlock risk)
- [ ] `ConfigureAwait(False)` in library code
- [ ] `CancellationToken` propagated through async chains

### Exception Handling (Severity: blocking / important)
- [ ] No empty `Catch` blocks
- [ ] Specific exception types caught (not bare `Exception`)
- [ ] `When` clause used for conditional catch (not catch-and-rethrow)
- [ ] Resources cleaned up in `Finally` or `Using`

### LINQ (Severity: important)
- [ ] Deferred queries not evaluated multiple times
- [ ] `ToList()` / `ToArray()` called after server-side filtering
- [ ] `Any()` used instead of `Count() > 0`
- [ ] `FirstOrDefault` result checked for `Nothing`

### Strings (Severity: important / nit)
- [ ] `StringBuilder` used for loop concatenation
- [ ] String interpolation (`$""`) preferred over `String.Format`
- [ ] `StringComparison` specified for case-insensitive comparisons

### COM Interop (Severity: important)
- [ ] All COM objects released via `Marshal.ReleaseComObject`
- [ ] Two-dot rule followed (no chained property access)
- [ ] Release in reverse order of creation
- [ ] All release code in `Finally` blocks

### WebForms (Severity: blocking)
- [ ] ViewState MAC validation enabled (not disabled)
- [ ] Request validation not disabled
- [ ] Event validation not disabled
- [ ] No sensitive data in ViewState

### Memory (Severity: important)
- [ ] `IDisposable` objects wrapped in `Using`
- [ ] `ArrayPool` used for large temporary buffers
- [ ] Generic collections used (not `ArrayList` / `Hashtable`)

### Migration Readiness (Severity: nit)
- [ ] No `System.Web` dependencies in business logic
- [ ] Configuration via DI, not `ConfigurationManager`
- [ ] Business logic separated from WebForms code-behind
