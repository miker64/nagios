<#  
.SYNOPSIS  
    Windows monitoring script for integration with Nagios.
.DESCRIPTION  
    Contains separate functions for checking operating system and IIS components and outputting the results into a format used by Nagios monitoring.
    Configured by monitor_config.xml located in the same directory.
.NOTES  
    File Name   : monitor.ps1
      Version   : 1.2.6.6
      Contact   : CC Streamline
     Requires   : Powershell v4
          SVN   : [host]:8085/svn/NagiosScripts/Checks/Master
        To do   : Add performance data capture.
                : Add log file activity/string monitoring.
      Remarks   : To display help, run "Get-Help .\monitor.ps1 -full"
      Changes   : v1.2.6.4 : Added link to Confluence documentation. Some cosmetic changes. Fixed bug with Get-SiteStatus. Added check for required PS version. Improved error handling. Fixed bug in Schtask check whereby a disabled task with successful last run reports as OK. 
                : v1.2.6 : Added file age monitoring. Fixed formatting issue in Get-TCPConnections output. Added command line entry of process to standard output if supplied. Fixed bug with Get-ScheduledTasks whereby tasks in progress generated errors. Added friendly error message when check fails because of old PS version or 32 bit environment.
                : v1.2.5 : Fixed bug in Get-ProcessStatus whereby multiple instances of the same name with different command lines did not get checked
                : v1.2.4 : Added TCP connection monitoring. Updated help file. Created deployment script, stored in SVN (requires input file with server names).
                : v1.2.3 : Small cosmetic changes
                : v1.2.2 : Added ability to define checks as Critical or Non-Critical (i.e., invoke standby or do not invoke standby, Nagios must be configured correspondingly)
                : v1.2.1 : Added scheduled task monitoring
.LINK
    https://confluence.xxx.xxx.com/xxx
.PARAMETER services
    Checks the configuration file for any services to be monitored. Can be specified using either the service name or display name. Only services explicity defined will be monitored. Wildcards are supported. 

If a service is specified that doesn't exist on the server, the check will exit in Unknown status. Ensure services specified in the configuration exist on the server. See examples for more information.
.PARAMETER processes
    Checks the configuration file for any processes to be monitored. Only processes explicity defined will be monitored. Supports including the Command Line switch a process is using. If Command Line is 

included, both the process name and command line string must match for a process to be "OK". Full command line is not required, just a unique string. See examples for more information.
.PARAMETER sites
    Checks all IIS websites running on the server. To exclude a site from monitoring, add its name to the configuration inside the <sites> element. See examples for more information.
.PARAMETER pools
    Checks all IIS application pools on the server. To exclude a pool from monitoring, add its name to the configuration inside the <pools> element. See examples for more information.
.PARAMETER fileage
    Checks specified directories for files older than a specified age.
.PARAMETER tcpconnections
    No configuration required. Counts all established TCP connections. Works with PNP4Nagios.
.EXAMPLE
    .\monitor.ps1 services
    Add the service name to the configuration inside the <services> element:
    
        <services>
            <service name="ABC*" />
        </services>
        
    This will monitor all services starting with the string ABC. To monitor a specific service, put in its full name or display name, e.g.,:
    
        <services>
            <service name="VMWare Tools" />
            <service name="wuauserv" />
        </services>
        
    Ensure the service actually exists on the server or the script will exit with an "Unknown" warning.
.EXAMPLE
    .\monitor.ps1 -processes
    Add the process name inside the <processes> element, including the "commandline" attribute if so required:
    
        <processes>
            <process name="NServiceBus.Host.exe" commandline="ProductionLine" />
        </processes>
        
    This will monitor the instance of NServiceBus.host.exe (appending .exe is optional; wildcards are also supported) running with a command line which contains the string 

"ProductionLine". If the command line contains characters which would need to be escaped (i.e., /, ", '), select part of the string that is only text and unique 

to the specific process. If the command line is specified, then it must be found or the process check will be marked as "KO".
    Where the command line switch isn't needed, it can be omitted as follows:
    
        <processes>
            <process name="svchost" />
            <process name="nservicebus.host.exe" />
        </processes>
.EXAMPLE
    .\monitor.ps1 pools
    All pools are monitored by default. To exclude a specific pool from monitoring, add it inside the <pools> element as follows:
    
        <pools>
        	<pool name="integration" />
        </pools>
        
    Specify the exact name of the application pool to exclude.
.EXAMPLE
    .\monitor.ps1 sites
    All web sites are monitored by default. To exclude a specific site from monitoring, add it inside the <sites> element as follows:
    
        <sites>
            <site name="OnlineHelp" />
        </sites>
        
    Specify the exact name of the web site to exclude.
.EXAMPLE
    .\monitor.ps1 tasks
    Add the name of the task to the configuration file and its last execution (exit code) will be checked. Successful tasks will have an exit code of 0, anything else will raise an alert. Include the <task> 

tag inside the <scheduledtasks> element :

        <scheduledtasks>
            <task name="SRF File Maintenance" />
        </scheduledtasks>
        
    Specify the  exact name of the task as it appears in the Task Scheduler. Be aware that although tasks themselves can exit successfully the script they call might not. Ensure the script behind the task is 

functioning correctly. Add additional (e.g., log file) monitoring if so required.
    Note, monitored tasks that are disabled will be considered as failures and raise alerts.
.EXAMPLE
    .\monitor.ps1 fileage
    
    Configure with the <directory> tag inside the <fileage> element. The "maxagehours" attribute is required. The script will then check the directory (but not sub-directories) for any files older than the 

maxagehours value (in hours, obviously).

        <config>
            <fileage>
                <directory name="C:\ImportantLogFiles" maxagehours="24" />
            </fileage>
        </config>
        
.EXAMPLE
    .\monitor.ps1 tcpconnections
    No configuration needed. Just call the script or function. Includes trailing performance data for use with PNP4Nagios.
.COMPONENT
    Microsoft PowerShell v4
#>
[cmdletBinding()]Param([string]$check)
$xmlConfig = "C:\infog\streamline\monitor_config.xml"

function Get-ServiceStatus ($severity)
{
    try
    {
        $ErrorActionPreference="stop"
        Check-Archictecture
        [xml]$configuration = get-content $xmlConfig

        if ($severity -eq "critical")
        {
            $services = @($configuration.config.includes.services.critical.service.name)
        }
        else
        {
            $services = @($configuration.config.includes.services.noncritical.service.name)
        }

    	$serviceUp   = @()
        $serviceDown = @()
        $servicesAll = @()
        if (!($services)) { write-output "OK: (nothing is monitored)"; exit 0 }

        foreach ($service in $services)
        {
           $servicesToCheck = @(get-service -name $service -ea 0 | Select -expandproperty Name)

           if (!($servicesToCheck)) { write-output "ERROR: One or more specified services do not exist. Please check the configuration file for errors."; exit 3 }

           foreach ($serviceToCheck in $servicesToCheck)
           {
                $servicesAll += $serviceToCheck

                if ((get-service -name $serviceToCheck).status -eq "Running")
                {
                    $serviceUp += $serviceToCheck
                }
                else
                {
                    $serviceDown += $serviceToCheck
                }
            }
        }

        $totalServices   = ($servicesAll | measure-object)
        $totalServices   = $totalServices.count
        $startedServices = ($serviceUp | measure-object)
        $startedServices = $startedServices.count
        $stoppedServices = ($serviceDown | measure-object)
        $stoppedServices = $stoppedServices.count
        $status          = "$startedServices/$totalServices services running"

        if ($stoppedServices -ge 1)
        {
            $msg = foreach ($item in $serviceDown) {"[$item]"}
            if ($severity -eq "critical" ) { write-output "CRITICAL: $status - $msg NOT running"; exit 2 }
            else                           { write-output "WARNING: $status - $msg NOT running"; exit 1 }
        }
        else
        {
            $msg = foreach ($item in $serviceUp) {"\n[$item]"}
            write-output "OK: $status [...] $msg running"
            exit 0
        }
    }  
    catch  { $errorMessage = $_.exception.message; write-output "ERROR: $errorMessage"; exit 3 }
}

function Get-ProcessStatus ($severity)
{
    try
    {
        $ErrorActionPreference="stop"
        if ($severity -eq "critical")
        {
            $ht_procs = @{}
            $processUp= @()
            $processDown = @()
            $processAll  = @()

            [xml]$configuration= get-content $xmlConfig
            if ($configuration.config.includes.processes.critical.ChildNodes.count -eq 0) { write-output "OK: (nothing is monitored)"; exit 0 }

            $data = $configuration.config.includes.processes.critical.childnodes
	    $totalProcesses = $data.count
            $data | foreach {$ht_procs[$_.Name+$(get-random -minimum 100 -Maximum 999)] = $_.commandline}

            $ht_procs.GetEnumerator() | foreach-object {

                $key = $_.key.substring(0,$_.key.length-3)
                $value = $_.value

                if (gwmi -class win32_process | where {$_.name -like "$key*" -and $_.commandline -like "*$value*"})
                {
                    if($value) { $processUp += "$key / cmd:$value"}
                    else {$processUp += $key}
                }
                else
                {
                    if($value) { $processDown += "$key / cmd:$value"}
                    else {$processDown += $key}
                }
            }

            $startedProcesses = ($processUp | measure-object)
            $startedProcesses = $startedProcesses.count
            $stoppedProcesses = ($processDown | measure-object)
            $stoppedProcesses = $stoppedProcesses.count
            $status= "$startedProcesses/$totalProcesses processes running"

            if ($stoppedProcesses -ge 1)
            {
                $msg = foreach ($item in $processDown) {"[$item]"}
                if ($severity -eq "critical" ) { write-output "CRITICAL: $status - $msg not running"; exit 2 }
                else                           { write-output "WARNING: $status - $msg not running"; exit 1 }
            }
            else
            {
                $msg = foreach ($item in $processUp) {"\n[$item]"}
                write-output "OK: $status [...] $msg running"
                exit 0
            }
        }
        else
        {
            $ht_procs = @{}
            $processUp= @()
            $processDown = @()
            $processAll  = @()

            [xml]$configuration= get-content $xmlConfig
            if ($configuration.config.includes.processes.noncritical.ChildNodes.count -eq 0){write-output "OK: (nothing is monitored)"; exit 0}

            $data = $configuration.config.includes.processes.noncritical.childnodes
            $totalProcesses = $data.count
            $data | foreach {$ht_procs[$_.Name+$(get-random -minimum 100 -Maximum 999)] = $_.commandline}

            $ht_procs.GetEnumerator() | foreach-object {

                $key = $_.key.substring(0,$_.key.length-3)
                $value = $_.value

                if (gwmi -class win32_process | where {$_.name -like "$key*" -and $_.commandline -like "*$value*"})
                {
                    if($value) { $processUp += "$key / cmd:$value"}
                    else {$processUp += $key}
                }
                else
                {
                    if($value) { $processDown += "$key / cmd:$value"}
                    else {$processDown += $key}
                }
            }

            $startedProcesses = ($processUp | measure-object)
            $startedProcesses = $startedProcesses.count
            $stoppedProcesses = ($processDown | measure-object)
            $stoppedProcesses = $stoppedProcesses.count
            $status= "$startedProcesses/$totalProcesses processes running"

            if ($stoppedProcesses -ge 1)
            {
                $msg = foreach ($item in $processDown) {"[$item]"}
                if ($severity -eq "critical" ) { write-output "CRITICAL: $status - $msg not running"; exit 2 }
                else                           { write-output "WARNING: $status - $msg not running"; exit 1 }
            }
            else
            {
                $msg = foreach ($item in $processUp) {"\n[$item]"}
                write-output "OK: $status [...] $msg running"
                exit 0
            }
        }
    }  
    catch  { $errorMessage = $_.exception.message; write-output "ERROR: $errorMessage"; exit 3 }
}

function Get-SiteStatus
{
    try
    {
        $ErrorActionPreference="stop"
        Check-Archictecture
    	[xml]$configuration = get-content $xmlConfig
        $siteUp   = @()
        $siteDown = @()

        if (!(Import-Module WebAdministration)) {get-pssnapin -Registered | select-string -pattern 'WebAdministration'}

        $ignoredSites = @($configuration.config.excludes.sites.site.name)
        $ignoredCount = ($ignoredSites | measure-object)
        $ignoredCount = $ignoredCount.count
        $sites        = @(get-website | select -expandproperty Name)
        $sites        = $sites | where {$ignoredSites -notcontains $_}
        $totalSites   = ($sites | measure-object)
        $totalSites   = $totalSites.count

        foreach ($site in $sites)
        {
            if ((Get-WebsiteState -name $site).value -eq "Started")
            {
                $siteUp += $site
            }
            else 
            {
                $siteDown += $site
            }
        }

        $startedSites = ($siteUp | measure-object)
        $startedSites = $startedSites.count
        $stoppedSites = ($siteDown | measure-object)
        $stoppedSites = $stoppedSites.count
        $listIgnored  = if ($ignoredSites) {"";foreach ($item in $ignoredSites){"[$item]"}}
        $status       = "$startedSites/$totalSites sites running ($ignoredCount excluded$listIgnored)"

        if ($stoppedSites -ge 1)
        {
            $msg = foreach ($item in $siteDown) {"[$item]"}
            write-output "CRITICAL: $status - $msg not started"
            exit 2
        }
        else
        {
            $msg = foreach ($item in $siteUp) {"\n[$item]"}
            write-output "OK: $status [...] $msg started"
            exit 0
        }
    }  
    catch  { $errorMessage = $_.exception.message; write-output "ERROR: $errorMessage"; exit 3 }
}

function Get-PoolStatus
{
    try
    {
        $ErrorActionPreference="stop"
        Check-Archictecture
    	[xml]$configuration = get-content $xmlConfig
        $poolUp   = @()
        $poolDown = @()

        Import-Module WebAdministration -ea 0
        if (!$?) {write-output "WARNING: IIS module failed to load on $env:computername"; exit 3}

        $ignoredPools = @($configuration.config.excludes.pools.pool.name)
        $ignoredCount = ($ignoredPools | measure-object)
        $ignoredCount = $ignoredCount.count
        $pools        = @(gci IIS:\AppPools | select -expandproperty Name)
        $pools        = $pools | where {$ignoredPools -notcontains $_}
        $totalPools   = ($pools | measure-object)
        $totalPools   = $totalPools.count

        foreach ($pool in $pools)
        {
            if ((Get-WebAppPoolState -name $pool).value -eq "Started")
            {
                $poolUp += $pool
            }
            else
            {
                $poolDown += $pool
            }
        }

        $startedPools = ($poolUp | measure-object)
        $startedPools = $startedPools.count
        $stoppedPools = ($poolDown | measure-object)
        $stoppedPools = $stoppedPools.count
        $listIgnored  = if ($ignoredPools) {"";foreach ($item in $ignoredPools){"[$item]"}}
        $status       = "$startedPools/$totalPools pools running ($ignoredCount excluded$listIgnored)"

        if ($stoppedPools -ge 1)
        {
            $msg = foreach ($item in $poolDown) {"[$item]"}
            write-output "CRITICAL: $status - $msg not running"
            exit 2
        }
        else
        {
            $msg = foreach ($item in $poolUp) {"\n[$item]"}
            write-output "OK: $status [...] $msg running"
            exit 0
        }
    }  
    catch  { $errorMessage = $_.exception.message; write-output "ERROR: $errorMessage"; exit 3 }
}

function Get-TaskStatus
{
    try
    {
        $ErrorActionPreference="stop"
        Check-Archictecture
        Check-ifPSisVersion 4
        [xml]$configuration = get-content $xmlConfig
        
        $tasks         =  @($configuration.config.includes.scheduledtasks.task.name)
        $taskOk        =  @()
        $taskNotOk     =  @()
        $taskNotFound  =  @()

        foreach ($task in $tasks)
        {
            if (!($tasks)) {
                write-output "OK: (nothing is monitored)"
                exit 0
            }
            
            $taskResult = Get-ScheduledTask -TaskName $task | Get-ScheduledTaskInfo
            $taskState  = (Get-ScheduledTask -TaskName $task).State

            if ($taskResult.LastTaskResult -eq '267009' -or $taskResult.LastTaskResult -eq '0')
            {
                if ($taskState -eq 'Running' -or $taskState -eq 'Ready')
                {
                    $taskOk += $task
                }

                else { $taskNotOk += $task }
            } 

            else { $taskNotOk += $task }
        }
            $totalTasks   = ($tasks | measure-object)
            $totalTasks   = $totalTasks.count
            $okTasks      = ($taskOk | measure-object)
            $okTasks      = ($okTasks).count
            $notokTasks   = ($taskNotOk | measure-object)
            $notokTasks   = $notokTasks.count
	        $finalCount   = $totalTasks - $notOkTasks
            $status       = "$finalCount/$totalTasks tasks finished successfully"

        if ($notokTasks -ge 1)
        {
            $msg = foreach ($item in $taskNotOk) {"[$item]"}
            write-output "CRITICAL: $status - $msg disabled or last run didn't complete"
            exit 2
        }
        else
        {
            $msg = foreach ($item in $taskOk) {"\n[$item]"}
            write-output "OK: $status [...] $msg with exit code 0"
            exit 0
        }
    }  
    catch  { $errorMessage = $_.exception.message; write-output "ERROR: $errorMessage"; exit 3 }
}

function Get-FileAge 
{
    try
    {
        $ErrorActionPreference="stop"
        $ht_directories = @{}
        $alertFlag = @()
        $msg = @()

        [xml]$configuration= get-content $xmlConfig
        if ($configuration.config.fileage.ChildNodes.count -eq 0){write-output "OK: (nothing is monitored)"; exit 0}

        $data = $configuration.config.fileage.childnodes
        $data | foreach {$ht_directories[$_.Name+$(get-random -minimum 100 -Maximum 999)] = $_.maxagehours}

        $ht_directories.GetEnumerator() | foreach-object {

            $key = $_.key.substring(0,$_.key.length-3)
            $value = $_.value
            $now = (Get-Date).AddHours(-$value)

            if (gci -path $key | where-object {!$_.PSIsContainer -and $_.LastWriteTime -lt $now})
            {
                $alertFlag += $True
                $msg += "[$key]"
            }
            else
            {
                $alertFlag += $False
                $msg += "\n[$key]"
            }
        }

        if ($alertFlag -eq $True)
        {
            write-output "CRITICAL: some old files found in $msg"
            exit 2
        }
        else
        {
            write-output "OK: No files older than threshold [...] $msg"
            exit 0
        }
    }  
    catch  { $errorMessage = $_.exception.message; write-output "ERROR: $errorMessage"; exit 3 }
}

function Get-TCPConnections
{
    try
    {
        $ErrorActionPreference="stop"
        $TCPConns = (netstat -anp tcp | select-string "established").count
        write-output "$TCPConns | active_connections=$TCPConns"
        exit 0
    }  
    catch  { $errorMessage = $_.exception.message; write-output "ERROR: $errorMessage"; exit 3 }
}

function Check-Archictecture
{
    try
    {
        $ErrorActionPreference="stop"
        if ($env:processor_architecture -ne "AMD64")
        {
            write-output "INFO: This check requires modules only available in an x64 environment."
            exit 0
        }
    }  
    catch  { $errorMessage = $_.exception.message; write-output "ERROR: $errorMessage"; exit 3 }
}

function Check-ifPSisVersion ($version)
{
    try
    {
        $ErrorActionPreference="stop"
        $major = $psversiontable.psversion.major
        if ($major -lt "$version")
        {
            write-output "INFO: This check requires Powershell v$version"
            exit 0
        }
    }
    catch  { $errorMessage = $_.exception.message; write-output "ERROR: $errorMessage"; exit 3 }
}

if ($check -eq "critical-services")   { Get-ServiceStatus critical }
if ($check -eq "services")            { Get-ServiceStatus }
if ($check -eq "critical-processes")  { Get-ProcessStatus critical }
if ($check -eq "processes")           { Get-ProcessStatus }
if ($check -eq "sites")               { Get-SiteStatus }
if ($check -eq "pools")               { Get-PoolStatus }
if ($check -eq "tasks")               { Get-TaskStatus }
if ($check -eq "fileage")             { Get-FileAge }
if ($check -eq "tcpconnections")      { Get-TCPConnections }

write-output "No check has been specified."
exit 3