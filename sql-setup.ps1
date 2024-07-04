<#
    .DESCRIPTION
    SQL Setup Script
#>

Param (
    [Parameter(Mandatory = $true)]
    [ValidateNotNullorEmpty()]
    [string] $adminUsername,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullorEmpty()]
    [string] $pw,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullorEmpty()]
    [string] $data_drive_letter,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullorEmpty()]
    [string] $log_drive_letter
)

begin {
    function Write-Log {
        [CmdletBinding()]
        <#
            .SYNOPSIS
            Create log function
        #>
        param (
            [Parameter(Mandatory = $True)]
            [ValidateNotNullOrEmpty()]
            [System.String] $logPath,

            [Parameter(Mandatory = $True)]
            [ValidateNotNullOrEmpty()]
            [System.String] $object,

            [Parameter(Mandatory = $True)]
            [ValidateNotNullOrEmpty()]
            [System.String] $message,

            [Parameter(Mandatory = $True)]
            [ValidateNotNullOrEmpty()]
            [ValidateSet('Information', 'Warning', 'Error', 'Verbose', 'Debug')]
            [System.String] $severity,

            [Parameter(Mandatory = $False)]
            [Switch] $toHost
        )

        begin {
            $date = (Get-Date).ToLongTimeString()
        }
        process {
            if (($severity -eq "Information") -or ($severity -eq "Warning") -or ($severity -eq "Error") -or ($severity -eq "Verbose" -and $VerbosePreference -ne "SilentlyContinue") -or ($severity -eq "Debug" -and $DebugPreference -ne "SilentlyContinue")) {
                if ($True -eq $toHost) {
                    Write-Host $date -ForegroundColor Cyan -NoNewline
                    Write-Host " - [" -ForegroundColor White -NoNewline
                    Write-Host "$object" -ForegroundColor Yellow -NoNewline
                    Write-Host "] " -ForegroundColor White -NoNewline
                    Write-Host ":: " -ForegroundColor White -NoNewline

                    Switch ($severity) {
                        'Information' {
                            Write-Host "$message" -ForegroundColor White
                        }
                        'Warning' {
                            Write-Warning "$message"
                        }
                        'Error' {
                            Write-Host "ERROR: $message" -ForegroundColor Red
                        }
                        'Verbose' {
                            Write-Verbose "$message"
                        }
                        'Debug' {
                            Write-Debug "$message"
                        }
                    }
                }
            }

            switch ($severity) {
                "Information" { [int]$type = 1 }
                "Warning" { [int]$type = 2 }
                "Error" { [int]$type = 3 }
                'Verbose' { [int]$type = 2 }
                'Debug' { [int]$type = 2 }
            }

            if (!(Test-Path (Split-Path $logPath -Parent))) { New-Item -Path (Split-Path $logPath -Parent) -ItemType Directory -Force | Out-Null }

            $content = "<![LOG[$message]LOG]!>" + `
                "<time=`"$(Get-Date -Format "HH:mm:ss.ffffff")`" " + `
                "date=`"$(Get-Date -Format "M-d-yyyy")`" " + `
                "component=`"$object`" " + `
                "context=`"$([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)`" " + `
                "type=`"$type`" " + `
                "thread=`"$([Threading.Thread]::CurrentThread.ManagedThreadId)`" " + `
                "file=`"`">"
            if (($severity -eq "Information") -or ($severity -eq "Warning") -or ($severity -eq "Error") -or ($severity -eq "Verbose" -and $VerbosePreference -ne "SilentlyContinue") -or ($severity -eq "Debug" -and $DebugPreference -ne "SilentlyContinue")) {
                Add-Content -Path $($logPath + ".log") -Value $content
            }
        }
        end {}
    }

    $LogPath = "$env:SYSTEMROOT\TEMP\Deployment_" + (Get-Date -Format 'yyyy-MM-dd')

    if ((Get-Service -Name "MSSQLSERVER").Status -eq 'Stopped') {
        Write-Log -Object "Hardening" -Message "Starting MSSQLSERVER service" -Severity Information -LogPath $LogPath
        Start-Service -Name "MSSQLSERVER"
    }
    while ((Get-Service -Name "MSSQLSERVER").Status -ne 'Running') {
        Write-Log -Object "Hardening" -Message "Waiting for MSSQLSERVER service to start" -Severity Information -LogPath $LogPath
        Start-Sleep -Seconds 5
    }
}

process {
    # Setting SQL Config ---------------------------------------------------------------#

    # Enable Built-in Administrator Account
    Enable-LocalUser -SID (Get-LocalUser | Where-Object { $_.SID -like 'S-1-5-*-500' }).Sid.Value
    Write-Log -Object "SQLConfig" -Message "Enabled SID500 Administator account" -Severity Information -LogPath $LogPath

    # Format Drives
    $dataVol = Get-Volume -DriveLetter $data_drive_letter
    Format-Volume -DriveLetter $dataVol.DriveLetter -FileSystem NTFS -NewFileSystemLabel $dataVol.FileSystemLabel -AllocationUnitSize 65536 -Force

    $logVol = Get-Volume -DriveLetter $log_drive_letter
    Format-Volume -DriveLetter $log_drive_letter -FileSystem NTFS -NewFileSystemLabel $dlogVol.FileSystemLabel -AllocationUnitSize 65536 -Force

    # create script file
    $script = @"
begin {
    function Write-Log {${function:Write-Log}}
    `$LogPath = "$LogPath"

    # Set the default data and log directories, and Server Instance
    `$dataDir = "$($data_drive_letter):\DATA"
    `$logDir = "$($log_drive_letter):\LOG"
    `$serverInstance = 'localhost'

    `$regPath = "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server"
    `$instance = Get-ChildItem `$regPath | Where-Object { ((`$_.PSChildName -like "MSSQL*") -and (`$_.PSChildName -ne "MSSQLSERVER")) }
    `$instanceName = `$instance.PSChildName
    `$wmipath = "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\`$instanceName\MSSQLServer\Parameters"
    `$Service = Get-Service -Name "MSSQLSERVER"
}

process {
    # Add the login
    `$connectionString = "Server=localhost;Database=master;Integrated Security=True;TrustServerCertificate=True"
    `$query = "CREATE LOGIN [$env:COMPUTERNAME\$adminUsername] FROM WINDOWS"
    try {
        Invoke-Sqlcmd -ConnectionString `$connectionString -Query `$query
        Write-Log -Object "SQLConfig" -Message "Created SQL Login" -Severity Information -LogPath `$LogPath
    }
    catch {
        `$ErrorMessage = `$_.Exception.Message
        if (`$Null -eq `$ErrorMessage) {
            Write-Log -Object "SQLConfig" -Message "Failed to create SQL Login: `$_" -Severity Error -LogPath `$LogPath
        }
        else {
            Write-Log -Object "SQLConfig" -Message "`$ErrorMessage" -Severity Error -LogPath `$LogPath
        }
    }

    # Add the login to the sysadmin server role
    `$query = "ALTER SERVER ROLE sysadmin ADD MEMBER [$env:COMPUTERNAME\$adminUsername]"
    try {
        Invoke-Sqlcmd -ConnectionString `$connectionString -Query `$query
        Write-Log -Object "SQLConfig" -Message "Added login to sysadmins role" -Severity Information -LogPath `$LogPath
    }
    catch {
        `$ErrorMessage = `$_.Exception.Message
        if (`$Null -eq `$ErrorMessage) {
            Write-Log -Object "SQLConfig" -Message "Failed to add login to sysadmins role: `$_" -Severity Error -LogPath `$LogPath
        }
        else {
            Write-Log -Object "SQLConfig" -Message "`$ErrorMessage" -Severity Error -LogPath `$LogPath
        }
    }

    # Update the registry settings for default data and log directories
    try {
        `$queryData = "EXEC xp_instance_regwrite N'HKEY_LOCAL_MACHINE', N'Software\Microsoft\MSSQLServer\MSSQLServer', N'DefaultData', REG_SZ, '`$dataDir';"
        Invoke-Sqlcmd -ServerInstance `$serverInstance -Query `$queryData
        Write-Log -Object "SQLConfig" -Message "Updated the registry settings for default data directory" -Severity Information -LogPath `$LogPath
    }
    catch {
        `$ErrorMessage = `$_.Exception.Message
        if (`$Null -eq `$ErrorMessage) {
            Write-Log -Object "SQLConfig" -Message "Failed to update the registry settings for default data directory" -Severity Error -LogPath `$LogPath
        }
        else {
            Write-Log -Object "SQLConfig" -Message "`$ErrorMessage" -Severity Error -LogPath `$LogPath
        }
    }

    try {
        `$queryLog = "EXEC xp_instance_regwrite N'HKEY_LOCAL_MACHINE', N'Software\Microsoft\MSSQLServer\MSSQLServer', N'DefaultLog', REG_SZ, '`$logDir';"
        Invoke-Sqlcmd -ServerInstance `$serverInstance -Query `$queryLog
        Write-Log -Object "SQLConfig" -Message "Updated the registry settings for default log directory" -Severity Information -LogPath `$LogPath
    }
    catch {
        `$ErrorMessage = `$_.Exception.Message
        if (`$Null -eq `$ErrorMessage) {
            Write-Log -Object "SQLConfig" -Message "Failed to update the registry settings for default log directory" -Severity Error -LogPath `$LogPath
        }
        else {
            Write-Log -Object "SQLConfig" -Message "`$ErrorMessage" -Severity Error -LogPath `$LogPath
        }
    }

    # Get databases
    try {
        `$query = @`"
SELECT
    DB_NAME(mdf.database_id) AS 'name',
	mdf.name AS 'data_logical',
    mdf.physical_name AS 'data_file',
	ldf.name AS 'log_logical',
    ldf.physical_name AS 'log_file'
FROM
    (SELECT * FROM sys.master_files WHERE type_desc = 'ROWS') mdf
JOIN
    (SELECT * FROM sys.master_files WHERE type_desc = 'LOG') ldf
ON
    mdf.database_id = ldf.database_id
`"@
        `$systemDatabases = Invoke-Sqlcmd -ServerInstance `$serverInstance -Query `$query
        `$systemDatabases = `$systemDatabases | Where-Object { `$_.name -notlike "*temp*" }
        Write-Log -Object "SQLConfig" -Message "Retrieved list of databases" -Severity Information -LogPath `$LogPath
    }
    catch {
        `$ErrorMessage = `$_.Exception.Message
        if (`$Null -eq `$ErrorMessage) {
            Write-Log -Object "SQLConfig" -Message "Failed to retriev list of databases" -Severity Error -LogPath `$LogPath
        }
        else {
            Write-Log -Object "SQLConfig" -Message "`$ErrorMessage" -Severity Error -LogPath `$LogPath
        }
    }

    # Set ACLs
    foreach (`$folderPath in @(`$dataDir, `$logDir)) {
        try {
            # Get the current ACL of the folder
            `$acl = Get-Acl -Path `$folderPath.Split('\')[0]

            # Create the NT Service\MSSQLSERVER identity
            `$identity = New-Object System.Security.Principal.NTAccount("NT SERVICE\MSSQLSERVER")

            # Grant full control permission to the identity
            `$rule = New-Object System.Security.AccessControl.FileSystemAccessRule(`$identity, "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")

            # Add the permission rule to the ACL
            `$acl.AddAccessRule(`$rule)

            # Apply the modified ACL to the folder
            Set-Acl -Path `$folderPath.Split('\')[0] -AclObject `$acl

            Write-Log -Object "SQLConfig" -Message "Amended ACLs on `$(`$folderPath.Split('\')[0])" -Severity Information -LogPath `$LogPath
        }
        catch {
            `$ErrorMessage = `$_.Exception.Message
            if (`$Null -eq `$ErrorMessage) {
                Write-Log -Object "SQLConfig" -Message "Failed to amend ACLs on `$(`$folderPath.Split('\')[0])" -Severity Error -LogPath `$LogPath
            }
            else {
                Write-Log -Object "SQLConfig" -Message "`$ErrorMessage" -Severity Error -LogPath `$LogPath
            }
        }
    }

    # Create folders
    foreach (`$folderPath in @(`$dataDir, `$logDir)) {
        try {
            New-Item -Path `$folderPath -ItemType Directory -Force | Out-Null
            Write-Log -Object "SQLConfig" -Message "Created `$folderPath" -Severity Information -LogPath `$LogPath
        }
        catch {
            `$ErrorMessage = `$_.Exception.Message
            if (`$Null -eq `$ErrorMessage) {
                Write-Log -Object "SQLConfig" -Message "Failed to create `$folderPath" -Severity Error -LogPath `$LogPath
            }
            else {
                Write-Log -Object "SQLConfig" -Message "`$ErrorMessage" -Severity Error -LogPath `$LogPath
            }
        }
    }

    # Modify the file paths
    foreach (`$database in (`$systemDatabases | Where-Object { `$_.name -ne 'master' })) {
        # Set data location
        try {
            `$dataFile = Get-Item -Path `$database.data_file
            `$query = @`"
        USE master;
        ALTER DATABASE `$(`$database.name) MODIFY FILE (NAME = '`$(`$database.data_logical)', FILENAME = '`$(Join-Path `$dataDir `$dataFile.Name)');
`"@
            Invoke-Sqlcmd -ServerInstance `$serverInstance -Query `$query
            Write-Log -Object "SQLConfig" -Message "Set `$(`$database.name) db data location to `$(Join-Path `$dataDir `$dataFile.Name)" -Severity Information -LogPath `$LogPath
        }
        catch {
            `$ErrorMessage = `$_.Exception.Message
            if (`$Null -eq `$ErrorMessage) {
                Write-Log -Object "SQLConfig" -Message "Failed to set `$(`$database.name) db data location to `$(Join-Path `$dataDir `$dataFile.Name)" -Severity Error -LogPath `$LogPath
            }
            else {
                Write-Log -Object "SQLConfig" -Message "`$ErrorMessage" -Severity Error -LogPath `$LogPath
            }
        }

        # Set log location
        try {
            `$logFile = Get-Item -Path `$database.log_file
            `$query = @`"
        USE master;
        ALTER DATABASE `$(`$database.name) MODIFY FILE (NAME = '`$(`$database.log_logical)', FILENAME = '`$(Join-Path `$logDir `$logFile.Name)');
`"@
            Invoke-Sqlcmd -ServerInstance `$serverInstance -Query `$query
            Write-Log -Object "SQLConfig" -Message "Set `$(`$database.name) db log location to `$(Join-Path `$logDir `$logFile.Name)" -Severity Information -LogPath `$LogPath
        }
        catch {
            `$ErrorMessage = `$_.Exception.Message
            if (`$Null -eq `$ErrorMessage) {
                Write-Log -Object "SQLConfig" -Message "Failed to set `$(`$database.name) db log location to `$(Join-Path `$logDir `$logFile.Name)" -Severity Error -LogPath `$LogPath
            }
            else {
                Write-Log -Object "SQLConfig" -Message "`$ErrorMessage" -Severity Error -LogPath `$LogPath
            }
        }

    }

    # Update the startup parameters for the SQL Server service
    `$regPath = "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server"
    `$instance = Get-ChildItem `$regPath | Where-Object { ((`$_.PSChildName -like "MSSQL*") -and (`$_.PSChildName -ne "MSSQLSERVER")) }
    `$instanceName = `$instance.PSChildName
    `$wmipath = "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\`$instanceName\MSSQLServer\Parameters"

    try {
        Set-ItemProperty -Path `$wmipath -Name 'SQLArg0' -Value "-d`$dataDir\master.mdf"
        Write-Log -Object "SQLConfig" -Message "Set master db data location to `$(`$dataDir)\master.mdf" -Severity Information -LogPath `$LogPath
    }
    catch {
        `$ErrorMessage = `$_.Exception.Message
        if (`$Null -eq `$ErrorMessage) {
            Write-Log -Object "SQLConfig" -Message "Failed to set master db data location to `$(`$dataDir)\master.mdf" -Severity Error -LogPath `$LogPath
        }
        else {
            Write-Log -Object "SQLConfig" -Message "`$ErrorMessage" -Severity Error -LogPath `$LogPath
        }
    }

    try {
        Set-ItemProperty -Path `$wmipath -Name 'SQLArg2' -Value "-l`$logDir\mastlog.ldf"
        Write-Log -Object "SQLConfig" -Message "Set master db log location to `$(`$logDir)\mastlog" -Severity Information -LogPath `$LogPath
    }
    catch {
        `$ErrorMessage = `$_.Exception.Message
        if (`$Null -eq `$ErrorMessage) {
            Write-Log -Object "SQLConfig" -Message "Failed to set master db log location to `$(`$logDir)\mastlog" -Severity Error -LogPath `$LogPath
        }
        else {
            Write-Log -Object "SQLConfig" -Message "`$ErrorMessage" -Severity Error -LogPath `$LogPath
        }
    }

    try {
        Set-ItemProperty -Path `$wmipath -Name 'SQLArg1' -Value "-e`$logDir\ERRORLOG"
        Write-Log -Object "SQLConfig" -Message "Set master db error log location to `$(`$logDir)\ERRORLOG" -Severity Information -LogPath `$LogPath
    }
    catch {
        `$ErrorMessage = `$_.Exception.Message
        if (`$Null -eq `$ErrorMessage) {
            Write-Log -Object "SQLConfig" -Message "Failed to set master db error log location to `$(`$logDir)\ERRORLOG" -Severity Error -LogPath `$LogPath
        }
        else {
            Write-Log -Object "SQLConfig" -Message "`$ErrorMessage" -Severity Error -LogPath `$LogPath
        }
    }

    # Stop the SQL Server service
    try {
        `$Service | Stop-Service -Force
        Write-Log -Object "SQLConfig" -Message "Stopped MSSQLSERVER service" -Severity Information -LogPath `$LogPath
    }
    catch {
        `$ErrorMessage = `$_.Exception.Message
        if (`$Null -eq `$ErrorMessage) {
            Write-Log -Object "SQLConfig" -Message "Failed to stop MSSQLSERVER service" -Severity Error -LogPath `$LogPath
        }
        else {
            Write-Log -Object "SQLConfig" -Message "`$ErrorMessage" -Severity Error -LogPath `$LogPath
        }
    }

    # Move Databases
    foreach (`$database in `$systemDatabases) {
        `$dataFile = Get-Item -Path `$database.data_file
        `$logFile = Get-Item -Path `$database.log_file

        try {
            Move-Item -Path `$dataFile.FullName -Destination (Join-Path `$dataDir (`$dataFile.Name)) -Force
            Write-Log -Object "SQLConfig" -Message "Moved `$(`$database.name) data file" -Severity Information -LogPath `$LogPath
        }
        catch {
            `$ErrorMessage = `$_.Exception.Message
            if (`$Null -eq `$ErrorMessage) {
                Write-Log -Object "SQLConfig" -Message "Failed to move `$(`$database.name) data file" -Severity Error -LogPath `$LogPath
            }
            else {
                Write-Log -Object "SQLConfig" -Message "`$ErrorMessage" -Severity Error -LogPath `$LogPath
            }
        }

        try {
            Move-Item -Path `$logFile.FullName -Destination (Join-Path `$logDir (`$logFile.Name)) -Force
            Write-Log -Object "SQLConfig" -Message "Moved `$(`$database.name) log file" -Severity Information -LogPath `$LogPath
        }
        catch {
            `$ErrorMessage = `$_.Exception.Message
            if (`$Null -eq `$ErrorMessage) {
                Write-Log -Object "SQLConfig" -Message "Failed to move `$(`$database.name) log file" -Severity Error -LogPath `$LogPath
            }
            else {
                Write-Log -Object "SQLConfig" -Message "`$ErrorMessage" -Severity Error -LogPath `$LogPath
            }
        }
    }

    # Start the SQL Server service
    try {
        `$Service | Start-Service
        Write-Log -Object "SQLConfig" -Message "Started MSSQLSERVER service" -Severity Information -LogPath `$LogPath
    }
    catch {
        `$ErrorMessage = `$_.Exception.Message
        if (`$Null -eq `$ErrorMessage) {
            Write-Log -Object "SQLConfig" -Message "Failed to start MSSQLSERVER service" -Severity Error -LogPath `$LogPath
        }
        else {
            Write-Log -Object "SQLConfig" -Message "`$ErrorMessage" -Severity Error -LogPath `$LogPath
        }
    }

`$query = @`"
    SELECT name, physical_name AS CurrentLocation, state_desc
    FROM sys.master_files
    WHERE database_id = DB_ID('master');
`"@
    `$return = Invoke-Sqlcmd -ServerInstance `$serverInstance -Query `$query

    foreach (`$item in `$return) {
        if (`$item.state_desc -ne 'ONLINE') {
            Write-Log -Object "SQLConfig" -Message "`$(`$item.name) is OFFLINE" -Severity Error -LogPath `$LogPath
        }
        else {
            Write-Log -Object "SQLConfig" -Message "`$(`$item.name) is ONLINE" -Severity Information -LogPath `$LogPath
        }
    }

    # Recommendation: Disable trace flag 1118 in SQL Server 2016 and higher versions
    # Severity: Information
    # Description: Trace Flag 1118 forces page allocations on uniform extents instead of mixed extents, and together with trace flag 1117, can help reduce allocation contention in the SQL Server TempDB database. When a new object is created, by default, the first eight pages are allocated from different extents (mixed extents). Afterwards, when more pages are needed, those are allocated from that same extent (uniform extent). The SGAM page is used to track these mixed extents, so can quickly become a bottleneck when numerous mixed page allocations are occurring. This trace flag allocates all eight pages from the same extent when creating new objects, minimizing the need to scan the SGAM page and forces uniform extent allocations instead of mixed page allocations. Starting with SQL Server 2016, this behavior is controlled by the SET MIXED_PAGE_ALLOCATION option of ALTER DATABASE syntax.
    # Checkid: TF1118
    # HelpLink: https://docs.microsoft.com/sql/t-sql/statements/alter-database-transact-sql-file-and-filegroup-options
    try {
        Remove-ItemProperty -Path `$wmipath -Name 'SQLArg4'
        Write-Log -Object "SQLConfig" -Message "Disabled trace flag 1118 in SQL Server 2016 and higher versions" -Severity Information -LogPath `$LogPath
    }
    catch {
        `$ErrorMessage = `$_.Exception.Message
        if (`$Null -eq `$ErrorMessage) {
            Write-Log -Object "SQLConfig" -Message "Failed to disable trace flag 1118 in SQL Server 2016 and higher versions" -Severity Error -LogPath `$LogPath
        }
        else {
            Write-Log -Object "SQLConfig" -Message "`$ErrorMessage" -Severity Error -LogPath `$LogPath
        }
    }

    # Recommendation: Disable trace flag 1117 in SQL Server 2016 and higher versions
    # Severity: Information
    # Description: Trace Flag 1117 initiates the growth of every file in the filegroup, when a file in the filegroup meets the autogrow threshold, and together with trace flag 1118, can help reduce allocation contention in the SQL Server TempDB database. Starting with SQL Server 2016, this behavior is controlled by the AUTOGROW_SINGLE_FILE and AUTOGROW_ALL_FILES options of ALTER DATABASE syntax.
    # Checkid: TF1117
    # Helplink: https://docs.microsoft.com/sql/t-sql/statements/alter-database-transact-sql-file-and-filegroup-options
    try {
        Remove-ItemProperty -Path `$wmipath -Name 'SQLArg3'
        Write-Log -Object "SQLConfig" -Message "Disabled trace flag 1117 in SQL Server 2016 and higher versions" -Severity Information -LogPath `$LogPath
    }
    catch {
        `$ErrorMessage = `$_.Exception.Message
        if (`$Null -eq `$ErrorMessage) {
            Write-Log -Object "SQLConfig" -Message "Failed to disable trace flag 1117 in SQL Server 2016 and higher versions" -Severity Error -LogPath `$LogPath
        }
        else {
            Write-Log -Object "SQLConfig" -Message "`$ErrorMessage" -Severity Error -LogPath `$LogPath
        }
    }

    # Recommendation: Enable 'Agent XPs' option
    # Severity: Information
    # Description: The 'Agent XPs' option enables the SQL Server Agent extended stored procedures. When this option is disabled, the SQL Server Agent node is not available in SQL Server Management Studio Object Explorer.
    # Checkid: AgentXPs
    # Helplink: https://docs.microsoft.com/sql/database-engine/configure-windows/agent-xps-server-configuration-option
    try {
        `$query = "EXEC sp_configure 'Agent XPs', 1; RECONFIGURE;"
        Invoke-Sqlcmd -ServerInstance `$serverInstance -Query `$query
        Write-Log -Object "SQLConfig" -Message "Disabled 'Agent XPs' option" -Severity Information -LogPath `$LogPath
    }
    catch {
        `$ErrorMessage = `$_.Exception.Message
        if (`$Null -eq `$ErrorMessage) {
            Write-Log -Object "SQLConfig" -Message "Failed to disable 'Agent XPs' option" -Severity Error -LogPath `$LogPath
        }
        else {
            Write-Log -Object "SQLConfig" -Message "`$ErrorMessage" -Severity Error -LogPath `$LogPath
        }
    }

    # Recommendation: Enable 'disallow results from triggers' option as the ability to return result sets from triggers will be removed in a future version
    # Severity: Information
    # Description: Use the 'disallow results from triggers' option to control whether triggers return result sets. Triggers that return result sets may cause unexpected behavior in applications that are not designed to work with them.
    # Checkid: DisallowResultsTriggers
    # Helplink: https://docs.microsoft.com/sql/database-engine/configure-windows/disallow-results-from-triggers-server-configuration-option
    `$query = "EXEC sp_configure 'disallow results from triggers', 1; RECONFIGURE;"
    Invoke-Sqlcmd -ServerInstance `$serverInstance -Query `$query

    # Recommendation: Enable 'backup compression default' option
    # Severity: Information
    # Description: The 'backup compression default' option determines whether the server instance creates compressed backups by default. Because a compressed backup is smaller than an uncompressed backup of the same data, compressing a backup typically requires less device I/O and therefore usually increases backup speed significantly.
    # Checkid: BackupCompression
    # Helplink: https://docs.microsoft.com/sql/database-engine/configure-windows/view-or-configure-the-backup-compression-default-server-configuration-option
    try {
        `$query = "EXEC sp_configure 'backup compression default', 1; RECONFIGURE;"
        Invoke-Sqlcmd -ServerInstance `$serverInstance -Query `$query
        Write-Log -Object "SQLConfig" -Message "Disabled 'backup compression default' option" -Severity Information -LogPath `$LogPath
    }
    catch {
        `$ErrorMessage = `$_.Exception.Message
        if (`$Null -eq `$ErrorMessage) {
            Write-Log -Object "SQLConfig" -Message "Failed to disable 'backup compression default' option" -Severity Error -LogPath `$LogPath
        }
        else {
            Write-Log -Object "SQLConfig" -Message "`$ErrorMessage" -Severity Error -LogPath `$LogPath
        }
    }

    # Recommendation: Enable trace flag 174 to increase plan cache bucket count
    # Severity: Information
    # Description: Trace Flag 174 increases the SQL Server plan cache bucket count from 40,009 to 160,001 on 64-bit systems. When the SQL Server plan cache reaches its entry limit, plans that have low cost must be evicted in order to insert new plans. This can cause severe contention on the SOS_CACHESTORE spinlock and a high CPU usage occurs in SQL Server. On 64-bit systems, the number of buckets for the SQL Server plan cache is 40,009. Therefore, the maximum number of entries that can fit inside the SQL Server plan cache is 160,036. Enabling trace flag 174 on high performance systems increases the size of the cache and can avoid SOS_CACHESTORE spinlock contention.
    # Checkid: TF174
    # Helplink: https://docs.microsoft.com/sql/t-sql/database-console-commands/dbcc-traceon-trace-flags-transact-sql
    try {
        Set-ItemProperty -Path `$wmipath -Name 'SQLArg3' -Value '-T174'
        Write-Log -Object "SQLConfig" -Message "Enabled trace flag 174 to increase plan cache bucket count" -Severity Information -LogPath `$LogPath
    }
    catch {
        `$ErrorMessage = `$_.Exception.Message
        if (`$Null -eq `$ErrorMessage) {
            Write-Log -Object "SQLConfig" -Message "Failed to enable trace flag 174 to increase plan cache bucket count" -Severity Error -LogPath `$LogPath
        }
        else {
            Write-Log -Object "SQLConfig" -Message "`$ErrorMessage" -Severity Error -LogPath `$LogPath
        }
    }

    #####################################################################################################################
    ####The following should be the last change as it disables advanced options required by some of the above changes####
    #####################################################################################################################

    # Recommendation: Disable 'show advanced options' option
    # Severity: Information
    # Description: Some configuration options are designated as advanced options. By default, these options are not available for viewing and changing. When you set 'show advanced options' option to 1, you can list the advanced options by using 'sp_configure' system stored procedure. It is recommended to only use this state temporarily and switch back to 0 when done with the task that required viewing the advanced options.
    # Checkid: ShowAdvancedOptions
    # Helplink: https://docs.microsoft.com/sql/database-engine/configure-windows/show-advanced-options-server-configuration-option
    try {
        `$query = "EXEC sp_configure 'show advanced options', 0; RECONFIGURE;"
        Invoke-Sqlcmd -ServerInstance `$serverInstance -Query `$query
        Write-Log -Object "SQLConfig" -Message "Disabled 'show advanced options' option" -Severity Information -LogPath `$LogPath
    }
    catch {
        `$ErrorMessage = `$_.Exception.Message
        if (`$Null -eq `$ErrorMessage) {
            Write-Log -Object "SQLConfig" -Message "Failed to disable 'show advanced options' option" -Severity Error -LogPath `$LogPath
        }
        else {
            Write-Log -Object "SQLConfig" -Message "`$ErrorMessage" -Severity Error -LogPath `$LogPath
        }
    }
}

end {
    # Restart MSSQLSERVER service

    try {
        `$Service | Restart-Service -Force
        Write-Log -Object "SQLConfig" -Message "Restarted MSSQLSERVER service" -Severity Information -LogPath `$LogPath
    }
    catch {
        `$ErrorMessage = `$_.Exception.Message
        if (`$Null -eq `$ErrorMessage) {
            Write-Log -Object "SQLConfig" -Message "Failed to restart MSSQLSERVER service" -Severity Error -LogPath `$LogPath
        }
        else {
            Write-Log -Object "SQLConfig" -Message "`$ErrorMessage" -Severity Error -LogPath `$LogPath
        }
    }
}
"@

    $script = New-Item -Path "$env:SYSTEMROOT\Temp\" -Name "script.ps1" -ItemType File -Value $script -Force

    # create scheduled task
    $taskName = 'SQLConfig'
    $taskRunAsUser = "$((Get-LocalUser | Where-Object { $_.SID -like 'S-1-5-*-500' }).Name)"

    $taskAction = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-ExecutionPolicy Bypass -File $($script.Fullname)"

    try {
        Register-ScheduledTask -TaskName $taskName -Action $taskAction -User $taskRunAsUser -Password $pw -Force -RunLevel Highest
        Write-Log -Object "SQLConfig" -Message "Created admin scheduled task" -Severity Information -LogPath $LogPath
    }
    catch {
        $ErrorMessage = $_.Exception.Message
        if ($Null -eq $ErrorMessage) {
            Write-Log -Object "SQLConfig" -Message "Failed to create admin scheduled task: $_" -Severity Error -LogPath $LogPath
        }
        else {
            Write-Log -Object "SQLConfig" -Message "$ErrorMessage" -Severity Error -LogPath $LogPath
        }
    }

    # run scheduled task
    Start-ScheduledTask -TaskName $taskName

    # wait while task is running
    while ((Get-ScheduledTask -TaskName $taskName).State -eq "Running") {
        Start-Sleep -Seconds 1
    }

    # cleanup
    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
    Remove-Item -Path $script.FullName

    # Disable Built-in Administrator Account
    Disable-LocalUser -SID (Get-LocalUser | Where-Object { $_.SID -like 'S-1-5-*-500' }).Sid.Value
    Write-Log -Object "SQLConfig" -Message "Disabled SID500 Administator account" -Severity Information -LogPath $LogPath
}
