<#
.SYNOPSIS
    Azure Virtual Desktop (AVD) Orphan Resource Discovery and Cleanup Script

.DESCRIPTION
    This comprehensive PowerShell script identifies orphan resources created by previous AVD implementations,
    whether they were created via the AVD Accelerator, ARM templates, Azure portal, or manual processes.
    
    The script performs deep analysis to identify:
    - Abandoned AVD host pools without session hosts
    - Unassigned application groups and workspaces
    - Orphaned session host VMs (not registered to any host pool)
    - Unused networking resources (VNets, NSGs, NICs)
    - Abandoned storage accounts and file shares
    - Unused Azure AD app registrations and service principals
    - Orphaned managed identities and role assignments
    - Stale automation accounts and log analytics workspaces
    - Unused Key Vault resources
    - Orphaned disk resources
    
    FEATURES:
    - Multi-subscription scanning capability
    - Comprehensive resource type coverage
    - Relationship mapping between resources
    - Age-based filtering for safety
    - Detailed reporting with recommendations
    - Interactive cleanup prompts by resource type (no automatic deletion)
    - Multiple authentication methods (Device Code, Browser, Service Principal, Managed Identity)
    - Export capabilities (CSV, JSON, Excel)
    - Dry-run mode for safe analysis
    - Backup recommendations before cleanup

.PARAMETER SubscriptionIds
    Array of subscription IDs to scan. If not provided, scans all accessible subscriptions.

.PARAMETER ResourceGroupPattern
    Regex pattern to filter resource groups (e.g., "*avd*", "*wvd*", "*vdi*")

.PARAMETER MinAgeInDays
    Minimum age in days for resources to be considered for cleanup (default: 30 days)

.PARAMETER ExcludeResourceGroups
    Array of resource group names to exclude from scanning

.PARAMETER SkipInteractiveSelection
    If specified, skips the interactive selection menu and only performs analysis

.PARAMETER AutoCleanup
    Deprecated. Automatic deletion is disabled. Use interactive prompts to approve deletions by resource type.

.PARAMETER ExportFormat
    Export format for results: CSV, JSON, Excel, or All (default: All)

.PARAMETER OutputPath
    Path for output files (default: current directory)

.PARAMETER IncludeRelatedResources
    Include analysis of related Azure resources (networking, storage, etc.)

.EXAMPLE
    .\06_AVD_Delete_Orphan_Resources.ps1
    Performs analysis of all accessible subscriptions with interactive authentication method selection,
    then allows interactive selection of resources to remove by resource type

.EXAMPLE
    .\06_AVD_Delete_Orphan_Resources.ps1 -SubscriptionIds @("sub1", "sub2") -MinAgeInDays 60 -ResourceGroupPattern "*avd*"
    Scans specific subscriptions for AVD resource groups with resources older than 60 days, 
    prompts for authentication method, then allows selection by resource type

.EXAMPLE
    .\06_AVD_Delete_Orphan_Resources.ps1 -SkipInteractiveSelection
    Performs analysis only without any cleanup options

.EXAMPLE
    .\06_AVD_Delete_Orphan_Resources.ps1 -MinAgeInDays 90 -ExportFormat Excel
    Performs analysis, then prompts per resource type for deletion approval and exports results to Excel

.NOTES
    Author: Azure Virtual Desktop Team
    Version: 1.0
    Date: November 12, 2025
    
    IMPORTANT: 
    - Always test in non-production environments first
    - Review the analysis report before performing any cleanup
    - Consider creating backups of critical resources
    - Some resources may have dependencies that require manual review
    
.LINK
    https://docs.microsoft.com/en-us/azure/virtual-desktop/
    https://github.com/Azure/avd-accelerator
    https://docs.microsoft.com/en-us/azure/virtual-desktop/delete-host-pool
#>

param(
    [Parameter(Mandatory = $false)]
    [string[]]$SubscriptionIds,
    
    [Parameter(Mandatory = $false)]
    [string]$ResourceGroupPattern = "*",
    
    [Parameter(Mandatory = $false)]
    [int]$MinAgeInDays = 30,
    
    [Parameter(Mandatory = $false)]
    [string[]]$ExcludeResourceGroups = @(),
    
    [Parameter(Mandatory = $false)]
    [switch]$SkipInteractiveSelection,
    
    [Parameter(Mandatory = $false)]
    [switch]$AutoCleanup,
    
    [Parameter(Mandatory = $false)]
    [ValidateSet("CSV", "JSON", "Excel", "All")]
    [string]$ExportFormat = "All",
    
    [Parameter(Mandatory = $false)]
    [string]$OutputPath = (Get-Location).Path,
    
    [Parameter(Mandatory = $false)]
    [switch]$IncludeRelatedResources
)

#Requires -Modules Az.Accounts, Az.Resources, Az.DesktopVirtualization, Az.Compute, Az.Network, Az.Storage

# Initialize script variables
$script:OrphanResources = @()
$script:RelatedResources = @()
$script:ResourceRelationships = @{}
$script:TotalScanned = 0
$script:TotalOrphans = 0
$script:CleanupActions = @()
$StartTime = Get-Date
$Timestamp = $StartTime.ToString("yyyyMMdd_HHmmss")

# Common AVD resource patterns
$AVDResourcePatterns = @{
    ResourceGroups = @("*avd*", "*wvd*", "*vdi*", "*hostpool*", "*sessionhost*", "*rg-avd*", "*rg-wvd*")
    VirtualMachines = @("*avd*", "*wvd*", "*sessionhost*", "*vd*", "*desktop*")
    NetworkInterfaces = @("*avd*", "*wvd*", "*sessionhost*", "*vd*")
    VirtualNetworks = @("*avd*", "*wvd*", "*vnet-avd*", "*vnet-wvd*")
    NetworkSecurityGroups = @("*avd*", "*wvd*", "*nsg-avd*", "*nsg-wvd*")
    StorageAccounts = @("*avd*", "*wvd*", "*fslogix*", "*profiles*")
    KeyVaults = @("*avd*", "*wvd*", "*kv-avd*", "*kv-wvd*")
    AutomationAccounts = @("*avd*", "*wvd*", "*automation*")
    LogAnalytics = @("*avd*", "*wvd*", "*log*", "*analytics*")
}

# Related resource types to scan for orphaned resources
$RelatedResourceTypes = @(
    "Microsoft.Storage/storageAccounts",
    "Microsoft.KeyVault/vaults",
    "Microsoft.Automation/automationAccounts",
    "Microsoft.OperationalInsights/workspaces",
    "Microsoft.ManagedIdentity/userAssignedIdentities",
    "Microsoft.Compute/disks",
    "Microsoft.Network/virtualNetworks",
    "Microsoft.Network/publicIPAddresses",
    "Microsoft.Network/loadBalancers"
)


function Write-Log {
    param(
        [string]$Message,
        [ValidateSet("Info", "Warning", "Error", "Success")]
        [string]$Level = "Info"
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $colors = @{
        "Info" = "White"
        "Warning" = "Yellow" 
        "Error" = "Red"
        "Success" = "Green"
    }
    
    Write-Host "[$timestamp] [$Level] $Message" -ForegroundColor $colors[$Level]
}

function Initialize-RequiredModules {
    Write-Log "Checking required PowerShell modules..." -Level Info
    
    $requiredModules = @(
        "Az.Accounts", "Az.Resources", "Az.DesktopVirtualization", 
        "Az.Compute", "Az.Network", "Az.Storage", "Az.KeyVault",
        "Az.Automation", "Az.OperationalInsights", "Az.ManagedServiceIdentity"
    )
    
    foreach ($module in $requiredModules) {
        if (!(Get-Module -ListAvailable -Name $module)) {
            Write-Log "Installing module: $module" -Level Warning
            try {
                Install-Module -Name $module -Force -AllowClobber -Scope CurrentUser
                Write-Log "Successfully installed: $module" -Level Success
            }
            catch {
                Write-Log "Failed to install module $module`: $_" -Level Error
                return $false
            }
        }
        
        try {
            Import-Module -Name $module -Force -ErrorAction Stop
        }
        catch {
            Write-Log "Failed to import module $module`: $_" -Level Error
            return $false
        }
    }
    
    Write-Log "All required modules are available" -Level Success
    return $true
}

function Select-AuthenticationMethod {
    if ($SkipInteractiveSelection) {
        Write-Host "Non-interactive mode: Using default authentication method" -ForegroundColor Yellow
        return "DeviceCode"
    }
    
    Write-Host ""
    Write-Host "Please select your preferred Azure authentication method:" -ForegroundColor White
    Write-Host ""
    Write-Host "  1. Device Code Authentication (Recommended)" -ForegroundColor White
    Write-Host "      - Use when browser login is not available" -ForegroundColor Gray
    Write-Host "      - Good for remote sessions or restricted environments" -ForegroundColor Gray
    Write-Host ""
    Write-Host "  2. Interactive Browser Login" -ForegroundColor White
    Write-Host "      - Opens browser for authentication" -ForegroundColor Gray
    Write-Host "      - May not work in all environments" -ForegroundColor Gray
    Write-Host ""
    Write-Host "  3. Service Principal (Client Secret)" -ForegroundColor White
    Write-Host "      - For automated scenarios" -ForegroundColor Gray
    Write-Host "      - Requires Application ID and Secret" -ForegroundColor Gray
    Write-Host ""
    Write-Host "  4. Service Principal (Certificate)" -ForegroundColor White
    Write-Host "      - For automated scenarios with certificate authentication" -ForegroundColor Gray
    Write-Host "      - Requires Application ID and Certificate" -ForegroundColor Gray
    Write-Host ""
    Write-Host "  5. Managed Identity" -ForegroundColor White
    Write-Host "      - For Azure VMs with managed identity enabled" -ForegroundColor Gray
    Write-Host "      - No credentials required" -ForegroundColor Gray
    Write-Host ""
    
    do {
        $selection = Read-Host "Please select an authentication method (1-5) [Default: 1]"
        
        if ([string]::IsNullOrWhiteSpace($selection)) {
            $selection = "1"
        }
        
        $selectionInt = 0
        $validSelection = [int]::TryParse($selection, [ref]$selectionInt) -and 
                          $selectionInt -ge 1 -and $selectionInt -le 5
        
        if (-not $validSelection) {
            Write-Host "Invalid selection. Please enter a number between 1 and 5." -ForegroundColor Red
        }
    } while (-not $validSelection)
    
    $authMethods = @{
        1 = "DeviceCode"
        2 = "Interactive"
        3 = "ServicePrincipalSecret"
        4 = "ServicePrincipalCertificate"
        5 = "ManagedIdentity"
    }
    
    $selectedMethod = $authMethods[$selectionInt]
    
    $methodNames = @{
        "DeviceCode" = "Device Code Authentication"
        "Interactive" = "Interactive Browser Login"
        "ServicePrincipalSecret" = "Service Principal (Client Secret)"
        "ServicePrincipalCertificate" = "Service Principal (Certificate)"
        "ManagedIdentity" = "Managed Identity"
    }
    
    Write-Host "Selected authentication method: $($methodNames[$selectedMethod])" -ForegroundColor Green
    Write-Host ""
    
    return $selectedMethod
}

function Invoke-AzureAuthentication {
    param(
        [string]$AuthMethod,
        [string]$TenantId
    )
    
    Write-Log "Initiating Azure authentication using: $AuthMethod" -Level Info
    
    try {
        switch ($AuthMethod) {
            "DeviceCode" {
                Write-Log "Starting device code authentication..." -Level Info
                Write-Host "You will see a device code that you need to enter at https://microsoft.com/devicelogin" -ForegroundColor Cyan
                if ($TenantId) {
                    $authResult = Connect-AzAccount -UseDeviceAuthentication -TenantId $TenantId
                } else {
                    $authResult = Connect-AzAccount -UseDeviceAuthentication
                }
            }
            
            "Interactive" {
                if ($TenantId) {
                    Write-Log "Opening browser for interactive login to tenant: $TenantId" -Level Info
                    $authResult = Connect-AzAccount -TenantId $TenantId
                } else {
                    Write-Log "Opening browser for interactive login..." -Level Info
                    $authResult = Connect-AzAccount
                }
            }
            
            "ServicePrincipalSecret" {
                Write-Log "Service Principal authentication with client secret..." -Level Info
                $appId = Read-Host "Enter Application (Client) ID"
                $clientSecret = Read-Host "Enter Client Secret" -AsSecureString
                $tenantForAuth = if ($TenantId) { $TenantId } else { Read-Host "Enter Tenant ID" }
                
                $credential = New-Object System.Management.Automation.PSCredential($appId, $clientSecret)
                $authResult = Connect-AzAccount -ServicePrincipal -Credential $credential -TenantId $tenantForAuth
            }
            
            "ServicePrincipalCertificate" {
                Write-Log "Service Principal authentication with certificate..." -Level Info
                $appId = Read-Host "Enter Application (Client) ID"
                $certThumbprint = Read-Host "Enter Certificate Thumbprint"
                $tenantForAuth = if ($TenantId) { $TenantId } else { Read-Host "Enter Tenant ID" }
                
                $authResult = Connect-AzAccount -ServicePrincipal -ApplicationId $appId -CertificateThumbprint $certThumbprint -TenantId $tenantForAuth
            }
            
            "ManagedIdentity" {
                Write-Log "Authenticating using Managed Identity..." -Level Info
                $authResult = Connect-AzAccount -Identity
            }
            
            default {
                throw "Unknown authentication method: $AuthMethod"
            }
        }
        
        if (-not $authResult) {
            throw "Authentication failed - no result returned"
        }
        
        Write-Log "Authentication successful!" -Level Success
        return $authResult
        
    } catch {
        Write-Log "Authentication failed: $($_.Exception.Message)" -Level Error
        throw $_
    }
}

function Connect-ToAzure {
    Write-Log "Checking Azure connection..." -Level Info
    
    Write-Host ""
    Write-Host ("="*100) -ForegroundColor Cyan
    Write-Host " Azure Authentication " -ForegroundColor Cyan
    Write-Host ("="*100) -ForegroundColor Cyan
    Write-Host ""
    
    Write-Log "Clearing any cached Azure credentials..." -Level Info
    Write-Host "Fresh authentication required for this session." -ForegroundColor Yellow
    Write-Host ""
    
    # Clear existing contexts - Force fresh authentication every time
    try {
        Clear-AzContext -Force -ErrorAction SilentlyContinue
        Disconnect-AzAccount -ErrorAction SilentlyContinue
    } catch { }
    
    # Select authentication method
    $selectedAuthMethod = Select-AuthenticationMethod
    
    Write-Log "Authentication method selected: $selectedAuthMethod" -Level Info
    
    try {
        # Attempt authentication with selected method
        $authResult = Invoke-AzureAuthentication -AuthMethod $selectedAuthMethod
        
        # Verify connection
        $context = Get-AzContext
        if ($context) {
            Write-Log "Connected to Azure as: $($context.Account.Id)" -Level Success
            Write-Log "Current tenant: $($context.Tenant.Id)" -Level Info
            Write-Log "Current subscription: $($context.Subscription.Name) ($($context.Subscription.Id))" -Level Info
            return $true
        } else {
            throw "Authentication succeeded but no context was established"
        }
        
    } catch {
        Write-Log "Authentication failed: $($_.Exception.Message)" -Level Error
        
        # Offer retry with different method if not in skip mode
        if (-not $SkipInteractiveSelection) {
            Write-Host ""
            Write-Host "Authentication failed. Would you like to try a different method?" -ForegroundColor Yellow
            $retry = Read-Host "Enter 'y' to retry with different method, or any other key to exit"
            
            if ($retry.ToLower() -eq 'y') {
                return Connect-ToAzure
            }
        }
        
        return $false
    }
}

function Get-TargetSubscriptions {
    Write-Log "Determining target subscriptions..." -Level Info
    
    if ($SubscriptionIds -and $SubscriptionIds.Count -gt 0) {
        $subscriptions = @()
        foreach ($subId in $SubscriptionIds) {
            try {
                $sub = Get-AzSubscription -SubscriptionId $subId -ErrorAction Stop
                $subscriptions += $sub
                Write-Log "Added subscription: $($sub.Name) ($($sub.Id))" -Level Info
            }
            catch {
                Write-Log "Could not access subscription $subId`: $_" -Level Warning
            }
        }
    }
    else {
        Write-Log "No specific subscriptions provided. Scanning all accessible subscriptions..." -Level Info
        $subscriptions = Get-AzSubscription | Where-Object { $_.State -eq "Enabled" }
    }
    
    Write-Log "Will scan $($subscriptions.Count) subscription(s)" -Level Success
    return $subscriptions
}

function Get-TargetResourceGroups {
    param([string]$SubscriptionId)
    
    Write-Log "Getting resource groups in subscription: $SubscriptionId" -Level Info
    
    try {
        Set-AzContext -SubscriptionId $SubscriptionId -ErrorAction Stop | Out-Null
        
        $allResourceGroups = Get-AzResourceGroup
        $targetResourceGroups = @()
        
        # Apply resource group pattern filter
        foreach ($rg in $allResourceGroups) {
            $matchesPattern = $false
            
            # Check if matches any AVD pattern or the specified pattern
            foreach ($pattern in $AVDResourcePatterns.ResourceGroups) {
                if ($rg.ResourceGroupName -like $pattern) {
                    $matchesPattern = $true
                    break
                }
            }
            
            # Also check user-specified pattern
            if ($rg.ResourceGroupName -like $ResourceGroupPattern) {
                $matchesPattern = $true
            }
            
            # Skip excluded resource groups
            if ($ExcludeResourceGroups -contains $rg.ResourceGroupName) {
                Write-Log "Excluding resource group: $($rg.ResourceGroupName)" -Level Info
                continue
            }
            
            if ($matchesPattern) {
                $targetResourceGroups += $rg
            }
        }
        
        Write-Log "Found $($targetResourceGroups.Count) resource groups matching criteria" -Level Info
        return $targetResourceGroups
    }
    catch {
        Write-Log "Failed to get resource groups for subscription $SubscriptionId`: $_" -Level Error
        return @()
    }
}

function Test-ResourceAge {
    param(
        [Parameter(Mandatory = $true)]
        $Resource
    )
    
    $ageDays = Get-ResourceAgeDays -Resource $Resource
    if ($null -eq $ageDays) {
        # If no creation time available, consider it old enough
        return $true
    }

    return $ageDays -ge $MinAgeInDays
}

function Get-ResourceAgeDays {
    param(
        [Parameter(Mandatory = $true)]
        $Resource
    )

    $creationDate = $null

    if ($Resource.PSObject.Properties.Match('CreatedTime').Count -gt 0) {
        $creationDate = $Resource.CreatedTime
    }
    if (!$creationDate -and $Resource.PSObject.Properties.Match('CreationTime').Count -gt 0) {
        $creationDate = $Resource.CreationTime
    }
    if (!$creationDate -and $Resource.PSObject.Properties.Match('TimeCreated').Count -gt 0) {
        $creationDate = $Resource.TimeCreated
    }
    if (!$creationDate -and $Resource.PSObject.Properties.Match('ChangedTime').Count -gt 0) {
        $creationDate = $Resource.ChangedTime
    }

    if (!$creationDate) {
        return $null
    }

    return [int]((Get-Date) - [DateTime]$creationDate).TotalDays
}

function Test-AVDNameMatch {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    foreach ($patternCategory in $AVDResourcePatterns.Values) {
        foreach ($pattern in $patternCategory) {
            if ($Name -like $pattern) {
                return $true
            }
        }
    }

    return $false
}

function Get-CleanupEligible {
    param(
        [Parameter(Mandatory = $true)]
        [string]$RiskLevel,
        [Parameter(Mandatory = $true)]
        [string]$RecommendedAction
    )

    if ($RiskLevel -ne "Low") { return $false }
    if ([string]::IsNullOrWhiteSpace($RecommendedAction)) { return $false }
    return $RecommendedAction -like "Delete*"
}

function Get-AnalysisModeLabel {
    if ($SkipInteractiveSelection) { return "AnalysisOnly" }
    return "Interactive"
}

function Add-CleanupAction {
    param(
        [Parameter(Mandatory = $true)][string]$SubscriptionId,
        [Parameter(Mandatory = $true)][string]$SubscriptionName,
        [Parameter(Mandatory = $true)][string]$ResourceGroup,
        [Parameter(Mandatory = $true)][string]$ResourceName,
        [Parameter(Mandatory = $true)][string]$ResourceType,
        [Parameter(Mandatory = $true)][string]$Status,
        [Parameter(Mandatory = $true)][string]$Message,
        [Parameter(Mandatory = $false)][string]$ResourceId = ""
    )

    $script:CleanupActions += [PSCustomObject]@{
        Timestamp = Get-Date
        SubscriptionId = $SubscriptionId
        SubscriptionName = $SubscriptionName
        ResourceGroup = $ResourceGroup
        ResourceName = $ResourceName
        ResourceType = $ResourceType
        ResourceId = $ResourceId
        Status = $Status
        Message = $Message
    }
}

function Get-AVDHostPools {
    param([string]$SubscriptionId, [string]$ResourceGroupName)
    
    try {
        if ($ResourceGroupName) {
            $hostPools = Get-AzWvdHostPool -ResourceGroupName $ResourceGroupName -ErrorAction SilentlyContinue
        }
        else {
            $hostPools = Get-AzWvdHostPool -ErrorAction SilentlyContinue
        }
        
        return $hostPools | Where-Object { Test-ResourceAge -Resource $_ }
    }
    catch {
        Write-Log "Failed to get host pools: $_" -Level Warning
        return @()
    }
}

function Get-AVDApplicationGroups {
    param([string]$SubscriptionId, [string]$ResourceGroupName)
    
    try {
        if ($ResourceGroupName) {
            $appGroups = Get-AzWvdApplicationGroup -ResourceGroupName $ResourceGroupName -ErrorAction SilentlyContinue
        }
        else {
            $appGroups = Get-AzWvdApplicationGroup -ErrorAction SilentlyContinue
        }
        
        return $appGroups | Where-Object { Test-ResourceAge -Resource $_ }
    }
    catch {
        Write-Log "Failed to get application groups: $_" -Level Warning
        return @()
    }
}

function Get-AVDWorkspaces {
    param([string]$SubscriptionId, [string]$ResourceGroupName)
    
    try {
        if ($ResourceGroupName) {
            $workspaces = Get-AzWvdWorkspace -ResourceGroupName $ResourceGroupName -ErrorAction SilentlyContinue
        }
        else {
            $workspaces = Get-AzWvdWorkspace -ErrorAction SilentlyContinue
        }
        
        return $workspaces | Where-Object { Test-ResourceAge -Resource $_ }
    }
    catch {
        Write-Log "Failed to get workspaces: $_" -Level Warning
        return @()
    }
}

function Get-SessionHosts {
    param([object]$HostPool)
    
    try {
        $sessionHosts = Get-AzWvdSessionHost -ResourceGroupName $HostPool.Id.Split('/')[4] -HostPoolName $HostPool.Name -ErrorAction SilentlyContinue
        return $sessionHosts
    }
    catch {
        Write-Log "Failed to get session hosts for host pool $($HostPool.Name): $_" -Level Warning
        return @()
    }
}

function Find-OrphanAVDResources {
    param(
        [string]$SubscriptionId,
        [string]$SubscriptionName,
        [string]$ResourceGroupName = $null
    )
    
    Write-Log "Analyzing AVD resources in subscription: $SubscriptionId" -Level Info
    
    # Get AVD resources
    $hostPools = Get-AVDHostPools -SubscriptionId $SubscriptionId -ResourceGroupName $ResourceGroupName
    $applicationGroups = Get-AVDApplicationGroups -SubscriptionId $SubscriptionId -ResourceGroupName $ResourceGroupName
    $workspaces = Get-AVDWorkspaces -SubscriptionId $SubscriptionId -ResourceGroupName $ResourceGroupName
    
    Write-Log "Found $($hostPools.Count) host pools, $($applicationGroups.Count) application groups, $($workspaces.Count) workspaces" -Level Info
    
    # Analyze host pools
    foreach ($hostPool in $hostPools) {
        $sessionHosts = Get-SessionHosts -HostPool $hostPool
        $appGroupsInPool = $applicationGroups | Where-Object { $_.HostPoolArmPath -eq $hostPool.Id }
        
        $orphanReasons = @()
        
        # Check if host pool has no session hosts
        if (!$sessionHosts -or $sessionHosts.Count -eq 0) {
            $orphanReasons += "No session hosts registered"
        }
        
        # Check if host pool has no application groups
        if (!$appGroupsInPool -or $appGroupsInPool.Count -eq 0) {
            $orphanReasons += "No application groups assigned"
        }
        
        # Check for inactive session hosts
        if ($sessionHosts) {
            $inactiveHosts = $sessionHosts | Where-Object { 
                $_.Status -eq "Unavailable" -or $_.Status -eq "Shutdown" 
            }
            if ($inactiveHosts.Count -eq $sessionHosts.Count) {
                $orphanReasons += "All session hosts are inactive"
            }
        }
        
        if ($orphanReasons.Count -gt 0) {
            $ageDays = Get-ResourceAgeDays -Resource $hostPool
            $recommendedAction = if ($sessionHosts.Count -eq 0) { "Delete (no session hosts)" } else { "Review and cleanup session hosts first" }
            $riskLevel = if ($sessionHosts.Count -eq 0) { "Low" } else { "Medium" }
            $script:OrphanResources += [PSCustomObject]@{
                SubscriptionId = $SubscriptionId
                SubscriptionName = $SubscriptionName
                ResourceGroup = $hostPool.Id.Split('/')[4]
                ResourceType = "Microsoft.DesktopVirtualization/hostpools"
                ResourceName = $hostPool.Name
                ResourceId = $hostPool.Id
                OrphanReason = ($orphanReasons -join "; ")
                CreatedDate = $hostPool.CreatedTime
                LastModified = $hostPool.ChangedTime
                AgeDays = $ageDays
                EstimatedMonthlyCost = "Low"
                RecommendedAction = $recommendedAction
                RelatedResources = @()
                RiskLevel = $riskLevel
                CleanupEligible = (Get-CleanupEligible -RiskLevel $riskLevel -RecommendedAction $recommendedAction)
            }
            $script:TotalOrphans++
        }
        
        $script:TotalScanned++
    }
    
    # Analyze application groups
    foreach ($appGroup in $applicationGroups) {
        $orphanReasons = @()
        
        # Check if application group is assigned to a workspace
        $assignedWorkspaces = $workspaces | Where-Object { 
            $_.ApplicationGroupReference -contains $appGroup.Id 
        }
        
        if (!$assignedWorkspaces -or $assignedWorkspaces.Count -eq 0) {
            $orphanReasons += "Not assigned to any workspace"
        }
        
        # Check if host pool exists
        $relatedHostPool = $hostPools | Where-Object { $_.Id -eq $appGroup.HostPoolArmPath }
        if (!$relatedHostPool) {
            $orphanReasons += "Related host pool not found"
        }
        
        if ($orphanReasons.Count -gt 0) {
            $ageDays = Get-ResourceAgeDays -Resource $appGroup
            $recommendedAction = "Delete (safe to remove)"
            $riskLevel = "Low"
            $script:OrphanResources += [PSCustomObject]@{
                SubscriptionId = $SubscriptionId
                SubscriptionName = $SubscriptionName
                ResourceGroup = $appGroup.Id.Split('/')[4]
                ResourceType = "Microsoft.DesktopVirtualization/applicationgroups"
                ResourceName = $appGroup.Name
                ResourceId = $appGroup.Id
                OrphanReason = ($orphanReasons -join "; ")
                CreatedDate = $appGroup.CreatedTime
                LastModified = $appGroup.ChangedTime
                AgeDays = $ageDays
                EstimatedMonthlyCost = "Minimal"
                RecommendedAction = $recommendedAction
                RelatedResources = @($appGroup.HostPoolArmPath)
                RiskLevel = $riskLevel
                CleanupEligible = (Get-CleanupEligible -RiskLevel $riskLevel -RecommendedAction $recommendedAction)
            }
            $script:TotalOrphans++
        }
        
        $script:TotalScanned++
    }
    
    # Analyze workspaces
    foreach ($workspace in $workspaces) {
        $orphanReasons = @()
        
        # Check if workspace has any application groups assigned
        if (!$workspace.ApplicationGroupReference -or $workspace.ApplicationGroupReference.Count -eq 0) {
            $orphanReasons += "No application groups assigned"
        }
        else {
            # Check if assigned application groups still exist
            $existingAppGroups = 0
            foreach ($appGroupRef in $workspace.ApplicationGroupReference) {
                if ($applicationGroups | Where-Object { $_.Id -eq $appGroupRef }) {
                    $existingAppGroups++
                }
            }
            
            if ($existingAppGroups -eq 0) {
                $orphanReasons += "All assigned application groups no longer exist"
            }
        }
        
        if ($orphanReasons.Count -gt 0) {
            $ageDays = Get-ResourceAgeDays -Resource $workspace
            $recommendedAction = "Delete (safe to remove)"
            $riskLevel = "Low"
            $script:OrphanResources += [PSCustomObject]@{
                SubscriptionId = $SubscriptionId
                SubscriptionName = $SubscriptionName
                ResourceGroup = $workspace.Id.Split('/')[4]
                ResourceType = "Microsoft.DesktopVirtualization/workspaces"
                ResourceName = $workspace.Name
                ResourceId = $workspace.Id
                OrphanReason = ($orphanReasons -join "; ")
                CreatedDate = $workspace.CreatedTime
                LastModified = $workspace.ChangedTime
                AgeDays = $ageDays
                EstimatedMonthlyCost = "Minimal"
                RecommendedAction = $recommendedAction
                RelatedResources = $workspace.ApplicationGroupReference
                RiskLevel = $riskLevel
                CleanupEligible = (Get-CleanupEligible -RiskLevel $riskLevel -RecommendedAction $recommendedAction)
            }
            $script:TotalOrphans++
        }
        
        $script:TotalScanned++
    }
}

function Find-OrphanVirtualMachines {
    param(
        [string]$SubscriptionId,
        [string]$SubscriptionName,
        [string]$ResourceGroupName = $null
    )
    
    if (!$IncludeRelatedResources) { return }
    
    Write-Log "Analyzing virtual machines for orphaned session hosts..." -Level Info
    
    try {
        if ($ResourceGroupName) {
            $vms = Get-AzVM -ResourceGroupName $ResourceGroupName -ErrorAction SilentlyContinue
        }
        else {
            $vms = Get-AzVM -ErrorAction SilentlyContinue
        }
        
        # Get all host pools to check registration
        $hostPools = Get-AVDHostPools -SubscriptionId $SubscriptionId
        
        foreach ($vm in $vms) {
            # Check if VM name matches AVD patterns
            $matchesAVDPattern = $false
            foreach ($pattern in $AVDResourcePatterns.VirtualMachines) {
                if ($vm.Name -like $pattern) {
                    $matchesAVDPattern = $true
                    break
                }
            }
            
            if (!$matchesAVDPattern) { continue }
            
            # Check if VM is registered as a session host
            $isRegisteredSessionHost = $false
            foreach ($hostPool in $hostPools) {
                $sessionHosts = Get-SessionHosts -HostPool $hostPool
                if ($sessionHosts | Where-Object { $_.Name -like "*$($vm.Name)*" }) {
                    $isRegisteredSessionHost = $true
                    break
                }
            }
            
            if (!$isRegisteredSessionHost -and (Test-ResourceAge -Resource $vm)) {
                $ageDays = Get-ResourceAgeDays -Resource $vm
                $recommendedAction = "Review VM usage and consider decommissioning"
                $riskLevel = "High"
                $script:OrphanResources += [PSCustomObject]@{
                    SubscriptionId = $SubscriptionId
                    SubscriptionName = $SubscriptionName
                    ResourceGroup = $vm.ResourceGroupName
                    ResourceType = "Microsoft.Compute/virtualMachines"
                    ResourceName = $vm.Name
                    ResourceId = $vm.Id
                    OrphanReason = "VM appears to be AVD session host but not registered to any host pool"
                    CreatedDate = $null
                    LastModified = $null
                    AgeDays = $ageDays
                    EstimatedMonthlyCost = "High"
                    RecommendedAction = $recommendedAction
                    RelatedResources = @()
                    RiskLevel = $riskLevel
                    CleanupEligible = (Get-CleanupEligible -RiskLevel $riskLevel -RecommendedAction $recommendedAction)
                }
                $script:TotalOrphans++
            }
            
            $script:TotalScanned++
        }
    }
    catch {
        Write-Log "Failed to analyze virtual machines: $_" -Level Warning
    }
}

function Find-OrphanNetworkResources {
    param(
        [string]$SubscriptionId,
        [string]$SubscriptionName,
        [string]$ResourceGroupName = $null
    )
    
    if (!$IncludeRelatedResources) { return }
    
    Write-Log "Analyzing network resources..." -Level Info
    
    try {
        # Network Interfaces
        if ($ResourceGroupName) {
            $nics = Get-AzNetworkInterface -ResourceGroupName $ResourceGroupName -ErrorAction SilentlyContinue
        }
        else {
            $nics = Get-AzNetworkInterface -ErrorAction SilentlyContinue
        }
        
        foreach ($nic in $nics) {
            $matchesPattern = $false
            foreach ($pattern in $AVDResourcePatterns.NetworkInterfaces) {
                if ($nic.Name -like $pattern) {
                    $matchesPattern = $true
                    break
                }
            }
            
            if ($matchesPattern -and !$nic.VirtualMachine) {
                $ageDays = Get-ResourceAgeDays -Resource $nic
                $recommendedAction = "Delete (safe to remove)"
                $riskLevel = "Low"
                $script:OrphanResources += [PSCustomObject]@{
                    SubscriptionId = $SubscriptionId
                    SubscriptionName = $SubscriptionName
                    ResourceGroup = $nic.ResourceGroupName
                    ResourceType = "Microsoft.Network/networkInterfaces"
                    ResourceName = $nic.Name
                    ResourceId = $nic.Id
                    OrphanReason = "Network interface not attached to any VM"
                    CreatedDate = $null
                    LastModified = $null
                    AgeDays = $ageDays
                    EstimatedMonthlyCost = "Low"
                    RecommendedAction = $recommendedAction
                    RelatedResources = @()
                    RiskLevel = $riskLevel
                    CleanupEligible = (Get-CleanupEligible -RiskLevel $riskLevel -RecommendedAction $recommendedAction)
                }
                $script:TotalOrphans++
            }
            
            $script:TotalScanned++
        }
        
        # Network Security Groups
        if ($ResourceGroupName) {
            $nsgs = Get-AzNetworkSecurityGroup -ResourceGroupName $ResourceGroupName -ErrorAction SilentlyContinue
        }
        else {
            $nsgs = Get-AzNetworkSecurityGroup -ErrorAction SilentlyContinue
        }
        
        foreach ($nsg in $nsgs) {
            $matchesPattern = $false
            foreach ($pattern in $AVDResourcePatterns.NetworkSecurityGroups) {
                if ($nsg.Name -like $pattern) {
                    $matchesPattern = $true
                    break
                }
            }
            
            if ($matchesPattern -and (!$nsg.Subnets -or $nsg.Subnets.Count -eq 0) -and (!$nsg.NetworkInterfaces -or $nsg.NetworkInterfaces.Count -eq 0)) {
                $ageDays = Get-ResourceAgeDays -Resource $nsg
                $recommendedAction = "Delete (safe to remove)"
                $riskLevel = "Low"
                $script:OrphanResources += [PSCustomObject]@{
                    SubscriptionId = $SubscriptionId
                    SubscriptionName = $SubscriptionName
                    ResourceGroup = $nsg.ResourceGroupName
                    ResourceType = "Microsoft.Network/networkSecurityGroups"
                    ResourceName = $nsg.Name
                    ResourceId = $nsg.Id
                    OrphanReason = "NSG not associated with any subnet or network interface"
                    CreatedDate = $null
                    LastModified = $null
                    AgeDays = $ageDays
                    EstimatedMonthlyCost = "Minimal"
                    RecommendedAction = $recommendedAction
                    RelatedResources = @()
                    RiskLevel = $riskLevel
                    CleanupEligible = (Get-CleanupEligible -RiskLevel $riskLevel -RecommendedAction $recommendedAction)
                }
                $script:TotalOrphans++
            }
            
            $script:TotalScanned++
        }
        
        # Scan for other related resource types
        Find-OrphanPublicIpResources -SubscriptionId $SubscriptionId -SubscriptionName $SubscriptionName -ResourceGroupName $ResourceGroupName
        Find-OrphanLoadBalancers -SubscriptionId $SubscriptionId -SubscriptionName $SubscriptionName -ResourceGroupName $ResourceGroupName
        Find-AdditionalRelatedResources -SubscriptionId $SubscriptionId -SubscriptionName $SubscriptionName -ResourceGroupName $ResourceGroupName
        
    }
    catch {
        Write-Log "Failed to analyze network resources: $_" -Level Warning
    }
}

function Find-AdditionalRelatedResources {
    param(
        [string]$SubscriptionId,
        [string]$SubscriptionName,
        [string]$ResourceGroupName = $null
    )
    
    Write-Log "Scanning additional related resource types..." -Level Info
    
    foreach ($resourceType in $RelatedResourceTypes) {
        try {
            # Skip resource types already handled by specific functions
            if ($resourceType -in @(
                    "Microsoft.Network/networkInterfaces",
                    "Microsoft.Network/networkSecurityGroups",
                    "Microsoft.Compute/virtualMachines",
                    "Microsoft.Storage/storageAccounts",
                    "Microsoft.Network/publicIPAddresses",
                    "Microsoft.Network/loadBalancers",
                    "Microsoft.Compute/disks",
                    "Microsoft.Network/virtualNetworks",
                    "Microsoft.KeyVault/vaults",
                    "Microsoft.Automation/automationAccounts",
                    "Microsoft.OperationalInsights/workspaces"
                )) {
                continue
            }
            
            if ($ResourceGroupName) {
                $resources = Get-AzResource -ResourceGroupName $ResourceGroupName -ResourceType $resourceType -ErrorAction SilentlyContinue
            }
            else {
                $resources = Get-AzResource -ResourceType $resourceType -ErrorAction SilentlyContinue
            }
            
            foreach ($resource in $resources) {
                # Check if resource matches AVD naming patterns
                $matchesAVDPattern = $false
                foreach ($patternCategory in $AVDResourcePatterns.Values) {
                    foreach ($pattern in $patternCategory) {
                        if ($resource.Name -like $pattern) {
                            $matchesAVDPattern = $true
                            break
                        }
                    }
                    if ($matchesAVDPattern) { break }
                }
                
                if ($matchesAVDPattern -and (Test-ResourceAge -Resource $resource)) {
                    $ageDays = Get-ResourceAgeDays -Resource $resource
                    $recommendedAction = "Manual review required"
                    $riskLevel = "Medium"
                    $script:OrphanResources += [PSCustomObject]@{
                        SubscriptionId = $SubscriptionId
                        SubscriptionName = $SubscriptionName
                        ResourceGroup = $resource.ResourceGroupName
                        ResourceType = $resource.ResourceType
                        ResourceName = $resource.Name
                        ResourceId = $resource.ResourceId
                        OrphanReason = "Matches AVD naming pattern but may be orphaned"
                        CreatedDate = $resource.CreatedTime
                        LastModified = $resource.ChangedTime
                        AgeDays = $ageDays
                        EstimatedMonthlyCost = "Medium"
                        RecommendedAction = $recommendedAction
                        RelatedResources = @()
                        RiskLevel = $riskLevel
                        CleanupEligible = (Get-CleanupEligible -RiskLevel $riskLevel -RecommendedAction $recommendedAction)
                    }
                    $script:TotalOrphans++
                }
                
                $script:TotalScanned++
            }
        }
        catch {
            Write-Log "Failed to analyze resource type $resourceType`: $_" -Level Warning
        }
    }
}

function Find-OrphanStorageResources {
    param(
        [string]$SubscriptionId,
        [string]$SubscriptionName,
        [string]$ResourceGroupName = $null
    )
    
    if (!$IncludeRelatedResources) { return }
    
    Write-Log "Analyzing storage resources..." -Level Info
    
    try {
        if ($ResourceGroupName) {
            $storageAccounts = Get-AzStorageAccount -ResourceGroupName $ResourceGroupName -ErrorAction SilentlyContinue
        }
        else {
            $storageAccounts = Get-AzStorageAccount -ErrorAction SilentlyContinue
        }
        
        foreach ($storage in $storageAccounts) {
            $matchesPattern = $false
            foreach ($pattern in $AVDResourcePatterns.StorageAccounts) {
                if ($storage.StorageAccountName -like $pattern) {
                    $matchesPattern = $true
                    break
                }
            }
            
            if ($matchesPattern) {
                # Check if storage account is being used (simplified check)
                $orphanReasons = @()
                
                # Check last access time if available
                $ctx = $storage.Context
                if ($ctx) {
                    try {
                        $containers = Get-AzStorageContainer -Context $ctx -ErrorAction SilentlyContinue
                        if (!$containers -or $containers.Count -eq 0) {
                            $orphanReasons += "No containers found"
                        }
                        else {
                            # Check for empty containers (simplified)
                            $emptyContainers = 0
                            foreach ($container in $containers) {
                                $blobs = Get-AzStorageBlob -Container $container.Name -Context $ctx -ErrorAction SilentlyContinue
                                if (!$blobs -or $blobs.Count -eq 0) {
                                    $emptyContainers++
                                }
                            }
                            
                            if ($emptyContainers -eq $containers.Count) {
                                $orphanReasons += "All containers are empty"
                            }
                        }

                        $shares = Get-AzStorageShare -Context $ctx -ErrorAction SilentlyContinue
                        if (!$shares -or $shares.Count -eq 0) {
                            $orphanReasons += "No file shares found"
                        }
                    }
                    catch {
                        $orphanReasons += "Cannot access storage contents (may be secured)"
                    }
                }
                
                if ($orphanReasons.Count -gt 0) {
                    $ageDays = Get-ResourceAgeDays -Resource $storage
                    $recommendedAction = "Review contents before deletion"
                    $riskLevel = "Medium"
                    $script:OrphanResources += [PSCustomObject]@{
                        SubscriptionId = $SubscriptionId
                        SubscriptionName = $SubscriptionName
                        ResourceGroup = $storage.ResourceGroupName
                        ResourceType = "Microsoft.Storage/storageAccounts"
                        ResourceName = $storage.StorageAccountName
                        ResourceId = $storage.Id
                        OrphanReason = ($orphanReasons -join "; ")
                        CreatedDate = $storage.CreationTime
                        LastModified = $null
                        AgeDays = $ageDays
                        EstimatedMonthlyCost = "Medium"
                        RecommendedAction = $recommendedAction
                        RelatedResources = @()
                        RiskLevel = $riskLevel
                        CleanupEligible = (Get-CleanupEligible -RiskLevel $riskLevel -RecommendedAction $recommendedAction)
                    }
                    $script:TotalOrphans++
                }
            function Find-OrphanDiskResources {
                param(
                    [string]$SubscriptionId,
                    [string]$SubscriptionName,
                    [string]$ResourceGroupName = $null
                )

                if (!$IncludeRelatedResources) { return }

                Write-Log "Analyzing managed disks for orphaned resources..." -Level Info

                try {
                    if ($ResourceGroupName) {
                        $disks = Get-AzDisk -ResourceGroupName $ResourceGroupName -ErrorAction SilentlyContinue
                    }
                    else {
                        $disks = Get-AzDisk -ErrorAction SilentlyContinue
                    }

                    foreach ($disk in $disks) {
                        if ($disk.ManagedBy) { continue }
                        if (!(Test-AVDNameMatch -Name $disk.Name)) { continue }
                        if (!(Test-ResourceAge -Resource $disk)) { continue }

                        $ageDays = Get-ResourceAgeDays -Resource $disk
                        $recommendedAction = "Delete (unattached disk)"
                        $riskLevel = "Low"

                        $script:OrphanResources += [PSCustomObject]@{
                            SubscriptionId = $SubscriptionId
                            SubscriptionName = $SubscriptionName
                            ResourceGroup = $disk.ResourceGroupName
                            ResourceType = "Microsoft.Compute/disks"
                            ResourceName = $disk.Name
                            ResourceId = $disk.Id
                            OrphanReason = "Managed disk is not attached to any VM"
                            CreatedDate = $disk.TimeCreated
                            LastModified = $null
                            AgeDays = $ageDays
                            EstimatedMonthlyCost = "Medium"
                            RecommendedAction = $recommendedAction
                            RelatedResources = @()
                            RiskLevel = $riskLevel
                            CleanupEligible = (Get-CleanupEligible -RiskLevel $riskLevel -RecommendedAction $recommendedAction)
                        }

                        $script:TotalOrphans++
                    }

                    $script:TotalScanned += $disks.Count
                }
                catch {
                    Write-Log "Failed to analyze disks: $_" -Level Warning
                }
            }

            function Find-OrphanPublicIpResources {
                param(
                    [string]$SubscriptionId,
                    [string]$SubscriptionName,
                    [string]$ResourceGroupName = $null
                )

                if (!$IncludeRelatedResources) { return }

                Write-Log "Analyzing public IP addresses..." -Level Info

                try {
                    if ($ResourceGroupName) {
                        $publicIps = Get-AzPublicIpAddress -ResourceGroupName $ResourceGroupName -ErrorAction SilentlyContinue
                    }
                    else {
                        $publicIps = Get-AzPublicIpAddress -ErrorAction SilentlyContinue
                    }

                    foreach ($publicIp in $publicIps) {
                        if ($publicIp.IpConfiguration) { continue }
                        if (!(Test-AVDNameMatch -Name $publicIp.Name)) { continue }
                        if (!(Test-ResourceAge -Resource $publicIp)) { continue }

                        $ageDays = Get-ResourceAgeDays -Resource $publicIp
                        $recommendedAction = "Delete (unassociated public IP)"
                        $riskLevel = "Low"

                        $script:OrphanResources += [PSCustomObject]@{
                            SubscriptionId = $SubscriptionId
                            SubscriptionName = $SubscriptionName
                            ResourceGroup = $publicIp.ResourceGroupName
                            ResourceType = "Microsoft.Network/publicIPAddresses"
                            ResourceName = $publicIp.Name
                            ResourceId = $publicIp.Id
                            OrphanReason = "Public IP address is not associated with any resource"
                            CreatedDate = $publicIp.CreatedTime
                            LastModified = $publicIp.ChangedTime
                            AgeDays = $ageDays
                            EstimatedMonthlyCost = "Low"
                            RecommendedAction = $recommendedAction
                            RelatedResources = @()
                            RiskLevel = $riskLevel
                            CleanupEligible = (Get-CleanupEligible -RiskLevel $riskLevel -RecommendedAction $recommendedAction)
                        }

                        $script:TotalOrphans++
                    }

                    $script:TotalScanned += $publicIps.Count
                }
                catch {
                    Write-Log "Failed to analyze public IP addresses: $_" -Level Warning
                }
            }

            function Find-OrphanLoadBalancers {
                param(
                    [string]$SubscriptionId,
                    [string]$SubscriptionName,
                    [string]$ResourceGroupName = $null
                )

                if (!$IncludeRelatedResources) { return }

                Write-Log "Analyzing load balancers..." -Level Info

                try {
                    if ($ResourceGroupName) {
                        $loadBalancers = Get-AzLoadBalancer -ResourceGroupName $ResourceGroupName -ErrorAction SilentlyContinue
                    }
                    else {
                        $loadBalancers = Get-AzLoadBalancer -ErrorAction SilentlyContinue
                    }

                    foreach ($lb in $loadBalancers) {
                        if (!(Test-AVDNameMatch -Name $lb.Name)) { continue }
                        if (!(Test-ResourceAge -Resource $lb)) { continue }

                        $hasBackends = $false
                        foreach ($pool in $lb.BackendAddressPools) {
                            if ($pool.BackendIpConfigurations -and $pool.BackendIpConfigurations.Count -gt 0) {
                                $hasBackends = $true
                                break
                            }
                        }

                        $hasRules = ($lb.LoadBalancingRules -and $lb.LoadBalancingRules.Count -gt 0)
                        $hasNatRules = ($lb.InboundNatRules -and $lb.InboundNatRules.Count -gt 0)

                        if ($hasBackends -or $hasRules -or $hasNatRules) { continue }

                        $ageDays = Get-ResourceAgeDays -Resource $lb
                        $recommendedAction = "Manual review required"
                        $riskLevel = "Medium"

                        $script:OrphanResources += [PSCustomObject]@{
                            SubscriptionId = $SubscriptionId
                            SubscriptionName = $SubscriptionName
                            ResourceGroup = $lb.ResourceGroupName
                            ResourceType = "Microsoft.Network/loadBalancers"
                            ResourceName = $lb.Name
                            ResourceId = $lb.Id
                            OrphanReason = "Load balancer has no backend pools or rules"
                            CreatedDate = $lb.CreatedTime
                            LastModified = $lb.ChangedTime
                            AgeDays = $ageDays
                            EstimatedMonthlyCost = "Medium"
                            RecommendedAction = $recommendedAction
                            RelatedResources = @()
                            RiskLevel = $riskLevel
                            CleanupEligible = (Get-CleanupEligible -RiskLevel $riskLevel -RecommendedAction $recommendedAction)
                        }

                        $script:TotalOrphans++
                    }

                    $script:TotalScanned += $loadBalancers.Count
                }
                catch {
                    Write-Log "Failed to analyze load balancers: $_" -Level Warning
                }
            }
            }
            
            $script:TotalScanned++
        }
    }
    catch {
        Write-Log "Failed to analyze storage resources: $_" -Level Warning
    }
}

function Find-OrphanVnetResources {
    param(
        [string]$SubscriptionId,
        [string]$SubscriptionName,
        [string]$ResourceGroupName = $null
    )

    if (!$IncludeRelatedResources) { return }

    Write-Log "Analyzing virtual networks for AVD-related orphans..." -Level Info

    try {
        if ($ResourceGroupName) {
            $vnets = Get-AzVirtualNetwork -ResourceGroupName $ResourceGroupName -ErrorAction SilentlyContinue
            $nics = Get-AzNetworkInterface -ResourceGroupName $ResourceGroupName -ErrorAction SilentlyContinue
        }
        else {
            $vnets = Get-AzVirtualNetwork -ErrorAction SilentlyContinue
            $nics = Get-AzNetworkInterface -ErrorAction SilentlyContinue
        }

        $nicSubnetIds = @()
        foreach ($nic in $nics) {
            foreach ($ipConfig in $nic.IpConfigurations) {
                if ($ipConfig.Subnet -and $ipConfig.Subnet.Id) {
                    $nicSubnetIds += $ipConfig.Subnet.Id
                }
            }
        }

        foreach ($vnet in $vnets) {
            if (!(Test-AVDNameMatch -Name $vnet.Name)) { continue }
            if (!(Test-ResourceAge -Resource $vnet)) { continue }
            if ($vnet.VirtualNetworkPeerings -and $vnet.VirtualNetworkPeerings.Count -gt 0) { continue }

            $orphanReasons = @()

            if (!$vnet.Subnets -or $vnet.Subnets.Count -eq 0) {
                $orphanReasons += "No subnets defined"
            }
            else {
                $subnetIds = $vnet.Subnets | ForEach-Object { $_.Id }
                $hasNicInSubnet = $false
                foreach ($subnetId in $subnetIds) {
                    if ($nicSubnetIds -contains $subnetId) {
                        $hasNicInSubnet = $true
                        break
                    }
                }

                if (!$hasNicInSubnet) {
                    $orphanReasons += "No network interfaces found in subnets"
                }
            }

            if ($orphanReasons.Count -gt 0) {
                $ageDays = Get-ResourceAgeDays -Resource $vnet
                $recommendedAction = "Manual review required"
                $riskLevel = "Medium"

                $script:OrphanResources += [PSCustomObject]@{
                    SubscriptionId = $SubscriptionId
                    SubscriptionName = $SubscriptionName
                    ResourceGroup = $vnet.ResourceGroupName
                    ResourceType = "Microsoft.Network/virtualNetworks"
                    ResourceName = $vnet.Name
                    ResourceId = $vnet.Id
                    OrphanReason = ($orphanReasons -join "; ")
                    CreatedDate = $vnet.CreatedTime
                    LastModified = $vnet.ChangedTime
                    AgeDays = $ageDays
                    EstimatedMonthlyCost = "Low"
                    RecommendedAction = $recommendedAction
                    RelatedResources = @()
                    RiskLevel = $riskLevel
                    CleanupEligible = (Get-CleanupEligible -RiskLevel $riskLevel -RecommendedAction $recommendedAction)
                }

                $script:TotalOrphans++
            }
        }

        $script:TotalScanned += $vnets.Count
    }
    catch {
        Write-Log "Failed to analyze virtual networks: $_" -Level Warning
    }
}

function Find-OrphanKeyVaultResources {
    param(
        [string]$SubscriptionId,
        [string]$SubscriptionName,
        [string]$ResourceGroupName = $null
    )

    if (!$IncludeRelatedResources) { return }

    Write-Log "Analyzing Key Vaults for AVD-related orphans..." -Level Info

    try {
        if ($ResourceGroupName) {
            $vaults = Get-AzKeyVault -ResourceGroupName $ResourceGroupName -ErrorAction SilentlyContinue
        }
        else {
            $vaults = Get-AzKeyVault -ErrorAction SilentlyContinue
        }

        foreach ($vault in $vaults) {
            if (!(Test-AVDNameMatch -Name $vault.VaultName)) { continue }
            if (!(Test-ResourceAge -Resource $vault)) { continue }

            $orphanReasons = @()
            $riskLevel = "Medium"
            $recommendedAction = "Manual review required"

            try {
                $secrets = Get-AzKeyVaultSecret -VaultName $vault.VaultName -ErrorAction SilentlyContinue
                $keys = Get-AzKeyVaultKey -VaultName $vault.VaultName -ErrorAction SilentlyContinue
                $certs = Get-AzKeyVaultCertificate -VaultName $vault.VaultName -ErrorAction SilentlyContinue

                if ((!$secrets -or $secrets.Count -eq 0) -and (!$keys -or $keys.Count -eq 0) -and (!$certs -or $certs.Count -eq 0)) {
                    $orphanReasons += "No secrets, keys, or certificates found"
                }
            }
            catch {
                $orphanReasons += "Vault contents not accessible"
            }

            if ($orphanReasons.Count -gt 0) {
                $ageDays = Get-ResourceAgeDays -Resource $vault

                $script:OrphanResources += [PSCustomObject]@{
                    SubscriptionId = $SubscriptionId
                    SubscriptionName = $SubscriptionName
                    ResourceGroup = $vault.ResourceGroupName
                    ResourceType = "Microsoft.KeyVault/vaults"
                    ResourceName = $vault.VaultName
                    ResourceId = $vault.ResourceId
                    OrphanReason = ($orphanReasons -join "; ")
                    CreatedDate = $vault.CreatedTime
                    LastModified = $vault.ChangedTime
                    AgeDays = $ageDays
                    EstimatedMonthlyCost = "Low"
                    RecommendedAction = $recommendedAction
                    RelatedResources = @()
                    RiskLevel = $riskLevel
                    CleanupEligible = (Get-CleanupEligible -RiskLevel $riskLevel -RecommendedAction $recommendedAction)
                }

                $script:TotalOrphans++
            }
        }

        $script:TotalScanned += $vaults.Count
    }
    catch {
        Write-Log "Failed to analyze Key Vaults: $_" -Level Warning
    }
}

function Find-OrphanAutomationResources {
    param(
        [string]$SubscriptionId,
        [string]$SubscriptionName,
        [string]$ResourceGroupName = $null
    )

    if (!$IncludeRelatedResources) { return }

    Write-Log "Analyzing Automation Accounts for AVD-related orphans..." -Level Info

    try {
        if ($ResourceGroupName) {
            $automationAccounts = Get-AzAutomationAccount -ResourceGroupName $ResourceGroupName -ErrorAction SilentlyContinue
        }
        else {
            $automationAccounts = Get-AzAutomationAccount -ErrorAction SilentlyContinue
        }

        foreach ($account in $automationAccounts) {
            if (!(Test-AVDNameMatch -Name $account.AutomationAccountName)) { continue }
            if (!(Test-ResourceAge -Resource $account)) { continue }

            $orphanReasons = @()
            $riskLevel = "Medium"
            $recommendedAction = "Manual review required"

            try {
                $runbooks = Get-AzAutomationRunbook -ResourceGroupName $account.ResourceGroupName -AutomationAccountName $account.AutomationAccountName -ErrorAction SilentlyContinue
                $schedules = Get-AzAutomationSchedule -ResourceGroupName $account.ResourceGroupName -AutomationAccountName $account.AutomationAccountName -ErrorAction SilentlyContinue

                if ((!$runbooks -or $runbooks.Count -eq 0) -and (!$schedules -or $schedules.Count -eq 0)) {
                    $orphanReasons += "No runbooks or schedules found"
                }
            }
            catch {
                $orphanReasons += "Automation content not accessible"
            }

            if ($orphanReasons.Count -gt 0) {
                $ageDays = Get-ResourceAgeDays -Resource $account

                $script:OrphanResources += [PSCustomObject]@{
                    SubscriptionId = $SubscriptionId
                    SubscriptionName = $SubscriptionName
                    ResourceGroup = $account.ResourceGroupName
                    ResourceType = "Microsoft.Automation/automationAccounts"
                    ResourceName = $account.AutomationAccountName
                    ResourceId = $account.ResourceId
                    OrphanReason = ($orphanReasons -join "; ")
                    CreatedDate = $account.CreationTime
                    LastModified = $null
                    AgeDays = $ageDays
                    EstimatedMonthlyCost = "Low"
                    RecommendedAction = $recommendedAction
                    RelatedResources = @()
                    RiskLevel = $riskLevel
                    CleanupEligible = (Get-CleanupEligible -RiskLevel $riskLevel -RecommendedAction $recommendedAction)
                }

                $script:TotalOrphans++
            }
        }

        $script:TotalScanned += $automationAccounts.Count
    }
    catch {
        Write-Log "Failed to analyze Automation Accounts: $_" -Level Warning
    }
}

function Find-OrphanLogAnalyticsResources {
    param(
        [string]$SubscriptionId,
        [string]$SubscriptionName,
        [string]$ResourceGroupName = $null
    )

    if (!$IncludeRelatedResources) { return }

    Write-Log "Analyzing Log Analytics workspaces for AVD-related orphans..." -Level Info

    try {
        if ($ResourceGroupName) {
            $workspaces = Get-AzOperationalInsightsWorkspace -ResourceGroupName $ResourceGroupName -ErrorAction SilentlyContinue
        }
        else {
            $workspaces = Get-AzOperationalInsightsWorkspace -ErrorAction SilentlyContinue
        }

        foreach ($workspace in $workspaces) {
            if (!(Test-AVDNameMatch -Name $workspace.Name)) { continue }
            if (!(Test-ResourceAge -Resource $workspace)) { continue }

            $orphanReasons = @()
            $riskLevel = "Medium"
            $recommendedAction = "Manual review required"

            try {
                $dataSources = Get-AzOperationalInsightsDataSource -ResourceGroupName $workspace.ResourceGroupName -WorkspaceName $workspace.Name -ErrorAction SilentlyContinue
                $linkedServices = Get-AzOperationalInsightsLinkedService -ResourceGroupName $workspace.ResourceGroupName -WorkspaceName $workspace.Name -ErrorAction SilentlyContinue

                if ((!$dataSources -or $dataSources.Count -eq 0) -and (!$linkedServices -or $linkedServices.Count -eq 0)) {
                    $orphanReasons += "No data sources or linked services found"
                }
            }
            catch {
                $orphanReasons += "Workspace contents not accessible"
            }

            if ($orphanReasons.Count -gt 0) {
                $ageDays = Get-ResourceAgeDays -Resource $workspace

                $script:OrphanResources += [PSCustomObject]@{
                    SubscriptionId = $SubscriptionId
                    SubscriptionName = $SubscriptionName
                    ResourceGroup = $workspace.ResourceGroupName
                    ResourceType = "Microsoft.OperationalInsights/workspaces"
                    ResourceName = $workspace.Name
                    ResourceId = $workspace.ResourceId
                    OrphanReason = ($orphanReasons -join "; ")
                    CreatedDate = $workspace.CreatedTime
                    LastModified = $workspace.ChangedTime
                    AgeDays = $ageDays
                    EstimatedMonthlyCost = "Medium"
                    RecommendedAction = $recommendedAction
                    RelatedResources = @()
                    RiskLevel = $riskLevel
                    CleanupEligible = (Get-CleanupEligible -RiskLevel $riskLevel -RecommendedAction $recommendedAction)
                }

                $script:TotalOrphans++
            }
        }

        $script:TotalScanned += $workspaces.Count
    }
    catch {
        Write-Log "Failed to analyze Log Analytics workspaces: $_" -Level Warning
    }
}

function Export-Results {
    param([string]$Format)
    
    $exportData = $script:OrphanResources | Select-Object -Property @(
        'SubscriptionId',
        'SubscriptionName',
        'ResourceGroup', 
        'ResourceType',
        'ResourceName',
        'ResourceId',
        'OrphanReason',
        'CreatedDate',
        'LastModified',
        'AgeDays',
        'EstimatedMonthlyCost',
        'RecommendedAction',
        'RiskLevel',
        'CleanupEligible',
        @{Name='RelatedResourcesCount'; Expression={ if ($_.RelatedResources) { $_.RelatedResources.Count } else { 0 } }}
    )
    
    $summaryData = [PSCustomObject]@{
        ScanDate = $StartTime
        TotalResourcesScanned = $script:TotalScanned
        TotalOrphanResourcesFound = $script:TotalOrphans
        SubscriptionsScanned = ($script:OrphanResources | Select-Object -Unique SubscriptionId).Count
        ResourceGroupsAffected = ($script:OrphanResources | Select-Object -Unique ResourceGroup).Count
        HighRiskResources = ($script:OrphanResources | Where-Object { $_.RiskLevel -eq "High" }).Count
        MediumRiskResources = ($script:OrphanResources | Where-Object { $_.RiskLevel -eq "Medium" }).Count
        LowRiskResources = ($script:OrphanResources | Where-Object { $_.RiskLevel -eq "Low" }).Count
        AnalysisMode = (Get-AnalysisModeLabel)
    }
    
    $safeChars = $Timestamp -replace ':', '-'
    
    if ($Format -eq "CSV" -or $Format -eq "All") {
        $csvFile = Join-Path $OutputPath "AVD_Orphan_Resources_$safeChars.csv"
        $exportData | Export-Csv -Path $csvFile -NoTypeInformation
        Write-Log "Exported results to CSV: $csvFile" -Level Success
        
        $csvSummaryFile = Join-Path $OutputPath "AVD_Orphan_Summary_$safeChars.csv"
        $summaryData | Export-Csv -Path $csvSummaryFile -NoTypeInformation
        Write-Log "Exported summary to CSV: $csvSummaryFile" -Level Success
    }
    
    if ($Format -eq "JSON" -or $Format -eq "All") {
        $jsonFile = Join-Path $OutputPath "AVD_Orphan_Resources_$safeChars.json"
        $fullReport = @{
            Summary = $summaryData
            OrphanResources = $exportData
            GeneratedBy = "AVD Orphan Resource Cleanup Script"
            GeneratedAt = $StartTime
        }
        $fullReport | ConvertTo-Json -Depth 10 | Out-File -FilePath $jsonFile -Encoding UTF8
        Write-Log "Exported results to JSON: $jsonFile" -Level Success
    }
    
    if ($Format -eq "Excel" -or $Format -eq "All") {
        if (Get-Module -ListAvailable -Name ImportExcel) {
            $excelFile = Join-Path $OutputPath "AVD_Orphan_Resources_$safeChars.xlsx"
            
            # Export to multiple worksheets
            $exportData | Export-Excel -Path $excelFile -WorksheetName "Orphan Resources" -AutoSize -BoldTopRow -FreezeTopRow
            $summaryData | Export-Excel -Path $excelFile -WorksheetName "Summary" -AutoSize -BoldTopRow
            
            # Create charts worksheet if there's data
            if ($script:OrphanResources.Count -gt 0) {
                $chartData = $script:OrphanResources | Group-Object ResourceType | Select-Object Name, Count
                $chartData | Export-Excel -Path $excelFile -WorksheetName "Charts" -AutoSize -BoldTopRow
            }
            
            Write-Log "Exported results to Excel: $excelFile" -Level Success
        }
        else {
            Write-Log "ImportExcel module not available. Skipping Excel export." -Level Warning
        }
    }
}

function Show-Summary {
    Write-Host ""
    Write-Host ("="*80) -ForegroundColor Cyan
    Write-Host " AVD ORPHAN RESOURCE ANALYSIS SUMMARY" -ForegroundColor Cyan
    Write-Host ("="*80) -ForegroundColor Cyan
    Write-Host ""
    
    Write-Host "Scan Details:" -ForegroundColor Yellow
    Write-Host "  - Scan Date: $StartTime"
    Write-Host "  - Duration: $((Get-Date) - $StartTime)"
    Write-Host "  - Mode: Analysis Complete (Interactive Selection Available)"
    Write-Host "  - Min Age Filter: $MinAgeInDays days"
    Write-Host ""
    
    Write-Host "Resources Analyzed:" -ForegroundColor Yellow
    Write-Host "  - Total Resources Scanned: $script:TotalScanned"
    Write-Host "  - Orphan Resources Found: $script:TotalOrphans"
    Write-Host "  - Subscriptions Scanned: $(($script:OrphanResources | Select-Object -Unique SubscriptionId).Count)"
    Write-Host "  - Resource Groups Affected: $(($script:OrphanResources | Select-Object -Unique ResourceGroup).Count)"
    Write-Host ""
    
    if ($script:OrphanResources.Count -gt 0) {
        Write-Host "Risk Breakdown:" -ForegroundColor Yellow
        $riskBreakdown = $script:OrphanResources | Group-Object RiskLevel
        foreach ($risk in $riskBreakdown) {
            $color = switch ($risk.Name) {
                "High" { "Red" }
                "Medium" { "Yellow" }
                "Low" { "Green" }
                default { "White" }
            }
            Write-Host "  - $($risk.Name) Risk: $($risk.Count) resources" -ForegroundColor $color
        }
        Write-Host ""
        
        Write-Host "Resource Type Breakdown:" -ForegroundColor Yellow
        $typeBreakdown = $script:OrphanResources | Group-Object ResourceType | Sort-Object Count -Descending
        foreach ($type in $typeBreakdown) {
            Write-Host "  - $($type.Name): $($type.Count) resources"
        }
        Write-Host ""
        
        # Show top 10 orphan resources
        Write-Host "Top Orphan Resources (by risk level):" -ForegroundColor Yellow
        $topOrphans = $script:OrphanResources | Sort-Object @{Expression={
            switch ($_.RiskLevel) {
                "High" { 1 }
                "Medium" { 2 }
                "Low" { 3 }
                default { 4 }
            }
        }}, ResourceName | Select-Object -First 10
        
        foreach ($orphan in $topOrphans) {
            $color = switch ($orphan.RiskLevel) {
                "High" { "Red" }
                "Medium" { "Yellow" }
                "Low" { "Green" }
                default { "White" }
            }
            Write-Host "  [$($orphan.RiskLevel)] $($orphan.ResourceName) - $($orphan.OrphanReason)" -ForegroundColor $color
        }
    }
    else {
        Write-Host "No orphan resources found!" -ForegroundColor Green
    }
    
    Write-Host ""
    Write-Host ("="*80) -ForegroundColor Cyan
}

function Invoke-InteractiveCleanup {
    param(
        [Parameter(Mandatory = $true)]
        [array]$SelectedResources
    )
    
    if ($SelectedResources.Count -eq 0) {
        Write-Log "No resources selected for cleanup" -Level Info
        return
    }
    
    Write-Host ""
    Write-Host "WARNING: You are about to delete $($SelectedResources.Count) resource(s)" -ForegroundColor Red
    Write-Host "This action cannot be undone!" -ForegroundColor Red
    Write-Host ""
    
    $confirmation = Read-Host "Type 'DELETE' to confirm deletion of selected resources"
    
    if ($confirmation -ne 'DELETE') {
        Write-Log "Cleanup cancelled by user" -Level Warning
        return
    }
    
    Write-Log "Starting cleanup of $($SelectedResources.Count) selected resource(s)..." -Level Warning
    
    foreach ($resource in $SelectedResources) {
        try {
            Write-Log "Deleting: $($resource.ResourceName) ($($resource.ResourceType))" -Level Info
            
            # Set context to correct subscription
            Set-AzContext -SubscriptionId $resource.SubscriptionId -ErrorAction Stop | Out-Null
            
            switch ($resource.ResourceType) {
                "Microsoft.DesktopVirtualization/hostpools" {
                    Remove-AzWvdHostPool -ResourceGroupName $resource.ResourceGroup -Name $resource.ResourceName -Force -ErrorAction Stop
                }
                "Microsoft.DesktopVirtualization/applicationgroups" {
                    Remove-AzWvdApplicationGroup -ResourceGroupName $resource.ResourceGroup -Name $resource.ResourceName -Force -ErrorAction Stop
                }
                "Microsoft.DesktopVirtualization/workspaces" {
                    Remove-AzWvdWorkspace -ResourceGroupName $resource.ResourceGroup -Name $resource.ResourceName -Force -ErrorAction Stop
                }
                "Microsoft.Compute/virtualMachines" {
                    Remove-AzVM -ResourceGroupName $resource.ResourceGroup -Name $resource.ResourceName -Force -ErrorAction Stop
                }
                "Microsoft.Network/networkInterfaces" {
                    Remove-AzNetworkInterface -ResourceGroupName $resource.ResourceGroup -Name $resource.ResourceName -Force -ErrorAction Stop
                }
                "Microsoft.Network/networkSecurityGroups" {
                    Remove-AzNetworkSecurityGroup -ResourceGroupName $resource.ResourceGroup -Name $resource.ResourceName -Force -ErrorAction Stop
                }
                "Microsoft.Storage/storageAccounts" {
                    Remove-AzStorageAccount -ResourceGroupName $resource.ResourceGroup -Name $resource.ResourceName -Force -ErrorAction Stop
                }
                default {
                    Remove-AzResource -ResourceId $resource.ResourceId -Force -ErrorAction Stop
                }
            }
            
            Write-Log "Successfully deleted: $($resource.ResourceName)" -Level Success
            Add-CleanupAction -SubscriptionId $resource.SubscriptionId -SubscriptionName $resource.SubscriptionName -ResourceGroup $resource.ResourceGroup -ResourceName $resource.ResourceName -ResourceType $resource.ResourceType -Status "Deleted" -Message "Resource deleted" -ResourceId $resource.ResourceId
        }
        catch {
            Write-Log "Failed to delete $($resource.ResourceName): $_" -Level Error
            Add-CleanupAction -SubscriptionId $resource.SubscriptionId -SubscriptionName $resource.SubscriptionName -ResourceGroup $resource.ResourceGroup -ResourceName $resource.ResourceName -ResourceType $resource.ResourceType -Status "Failed" -Message $_.Exception.Message -ResourceId $resource.ResourceId
        }
    }
    
    Write-Log "Cleanup completed. $($script:CleanupActions.Count) actions performed." -Level Success
}

function Show-InteractiveMenu {
    if ($script:OrphanResources.Count -eq 0) {
        Write-Log "No orphan resources found to select" -Level Info
        return @()
    }

    Write-Host ""
    Write-Host ("="*100) -ForegroundColor Cyan
    Write-Host " INTERACTIVE RESOURCE SELECTION (BY TYPE)" -ForegroundColor Cyan
    Write-Host ("="*100) -ForegroundColor Cyan
    Write-Host ""

    $selectedResources = @()
    $groupedByType = $script:OrphanResources | Group-Object ResourceType | Sort-Object Name

    foreach ($group in $groupedByType) {
        Write-Host ("-"*100) -ForegroundColor DarkGray
        Write-Host "Resource Type: $($group.Name)" -ForegroundColor Yellow
        Write-Host "Count: $($group.Count)" -ForegroundColor Yellow
        Write-Host ""

        foreach ($resource in ($group.Group | Sort-Object RiskLevel, ResourceName)) {
            $color = switch ($resource.RiskLevel) {
                "High" { "Red" }
                "Medium" { "Yellow" }
                "Low" { "Green" }
                default { "White" }
            }

            Write-Host "  [$($resource.RiskLevel)] " -ForegroundColor $color -NoNewline
            Write-Host "$($resource.ResourceName)" -NoNewline
            Write-Host " ($($resource.ResourceGroup))" -ForegroundColor Gray
            Write-Host "      Reason: $($resource.OrphanReason)" -ForegroundColor DarkGray
            Write-Host "      Action: $($resource.RecommendedAction)" -ForegroundColor DarkGray
        }

        Write-Host ""
        $response = Read-Host "Delete ALL resources of this type? (y/n)"
        if ($response -match '^(y|yes)$') {
            $selectedResources += $group.Group
            Write-Log "Selected $($group.Count) resource(s) for type: $($group.Name)" -Level Info
        }
        else {
            Write-Log "Skipped resource type: $($group.Name)" -Level Info
        }

        Write-Host ""
    }

    if ($selectedResources.Count -gt 0) {
        Write-Host ("="*100) -ForegroundColor Cyan
        Write-Host "Selected Resources (by type):" -ForegroundColor Yellow
        foreach ($res in ($selectedResources | Sort-Object ResourceType, ResourceName)) {
            $color = switch ($res.RiskLevel) {
                "High" { "Red" }
                "Medium" { "Yellow" }
                "Low" { "Green" }
                default { "White" }
            }
            Write-Host "  - " -NoNewline
            Write-Host "[$($res.RiskLevel)]" -ForegroundColor $color -NoNewline
            Write-Host " $($res.ResourceName) ($($res.ResourceType))"
        }
    }

    return $selectedResources
}

function Invoke-CleanupActions {
    if ($AutoCleanup) {
        Write-Log "AutoCleanup is disabled. Manual approval by resource type is required." -Level Warning
    }

    if ($SkipInteractiveSelection) {
        Write-Log "Interactive selection skipped. Review exported reports for analysis." -Level Info
        return
    }

    # Show interactive menu
    $selectedResources = Show-InteractiveMenu

    if ($selectedResources.Count -gt 0) {
        Invoke-InteractiveCleanup -SelectedResources $selectedResources
    }
}

function Export-CleanupLog {
    if ($script:CleanupActions.Count -eq 0) { return }

    $safeChars = $Timestamp -replace ':', '-'
    $cleanupLogFile = Join-Path $OutputPath "AVD_Orphan_Cleanup_Log_$safeChars.csv"
    $script:CleanupActions | Export-Csv -Path $cleanupLogFile -NoTypeInformation
    Write-Log "Exported cleanup log to CSV: $cleanupLogFile" -Level Success

    $cleanupJsonFile = Join-Path $OutputPath "AVD_Orphan_Cleanup_Log_$safeChars.json"
    $script:CleanupActions | ConvertTo-Json -Depth 6 | Out-File -FilePath $cleanupJsonFile -Encoding UTF8
    Write-Log "Exported cleanup log to JSON: $cleanupJsonFile" -Level Success
}

# Main execution
function Main {
    Write-Host ""
    Write-Host ("="*100) -ForegroundColor Cyan
    Write-Host " AVD - ORPHAN RESOURCE CLEANUP SCRIPT" -ForegroundColor Cyan
    Write-Host ("="*100) -ForegroundColor Cyan
    Write-Host ""
    
    # Initialize and validate environment
    if (!(Initialize-RequiredModules)) {
        Write-Log "Failed to initialize required modules. Exiting." -Level Error
        exit 1
    }
    
    if (!(Connect-ToAzure)) {
        Write-Log "Failed to connect to Azure. Exiting." -Level Error
        exit 1
    }
    
    # Get target subscriptions
    $subscriptions = Get-TargetSubscriptions
    if ($subscriptions.Count -eq 0) {
        Write-Log "No subscriptions found to scan. Exiting." -Level Error
        exit 1
    }
    
    # Process each subscription
    foreach ($subscription in $subscriptions) {
        Write-Log "Processing subscription: $($subscription.Name) ($($subscription.Id))" -Level Info
        
        try {
            Set-AzContext -SubscriptionId $subscription.Id -ErrorAction Stop | Out-Null
            
            # Get target resource groups
            $resourceGroups = Get-TargetResourceGroups -SubscriptionId $subscription.Id
            
            if ($resourceGroups.Count -eq 0) {
                Write-Log "No matching resource groups found in subscription" -Level Warning
                continue
            }
            
            # Analyze each resource group
            foreach ($rg in $resourceGroups) {
                Write-Log "Analyzing resource group: $($rg.ResourceGroupName)" -Level Info
                
                # Find orphan AVD resources
                Find-OrphanAVDResources -SubscriptionId $subscription.Id -SubscriptionName $subscription.Name -ResourceGroupName $rg.ResourceGroupName
                
                # Find orphan related resources if requested
                if ($IncludeRelatedResources) {
                    Find-OrphanVirtualMachines -SubscriptionId $subscription.Id -SubscriptionName $subscription.Name -ResourceGroupName $rg.ResourceGroupName
                    Find-OrphanNetworkResources -SubscriptionId $subscription.Id -SubscriptionName $subscription.Name -ResourceGroupName $rg.ResourceGroupName
                    Find-OrphanStorageResources -SubscriptionId $subscription.Id -SubscriptionName $subscription.Name -ResourceGroupName $rg.ResourceGroupName
                    Find-OrphanDiskResources -SubscriptionId $subscription.Id -SubscriptionName $subscription.Name -ResourceGroupName $rg.ResourceGroupName
                    Find-OrphanVnetResources -SubscriptionId $subscription.Id -SubscriptionName $subscription.Name -ResourceGroupName $rg.ResourceGroupName
                    Find-OrphanKeyVaultResources -SubscriptionId $subscription.Id -SubscriptionName $subscription.Name -ResourceGroupName $rg.ResourceGroupName
                    Find-OrphanAutomationResources -SubscriptionId $subscription.Id -SubscriptionName $subscription.Name -ResourceGroupName $rg.ResourceGroupName
                    Find-OrphanLogAnalyticsResources -SubscriptionId $subscription.Id -SubscriptionName $subscription.Name -ResourceGroupName $rg.ResourceGroupName
                }
            }
            
            # Also scan subscription-wide for AVD resources not in matching RGs
            Write-Log "Scanning subscription-wide for additional AVD resources..." -Level Info
            Find-OrphanAVDResources -SubscriptionId $subscription.Id -SubscriptionName $subscription.Name
            
        }
        catch {
            Write-Log "Failed to process subscription $($subscription.Id): $_" -Level Error
        }
    }
    
    # Show summary
    Show-Summary
    
    # Export results
    if ($script:OrphanResources.Count -gt 0) {
        Export-Results -Format $ExportFormat
    }
    
    # Perform cleanup if requested
    Invoke-CleanupActions

    Export-CleanupLog
    
    Write-Host ""
    Write-Host "Script execution completed." -ForegroundColor Green
    Write-Host "Duration: $((Get-Date) - $StartTime)" -ForegroundColor Green
    Write-Host ""
}

# Execute main function
Main
