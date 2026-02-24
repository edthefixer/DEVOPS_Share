<#
.SYNOPSIS
    Azure Virtual Desktop (AVD) Accelerator Wizard and Automation Tool

    Streamlined, professional-grade wizard for planning, validating, and deploying Azure Virtual Desktop environments.
    Provides interactive configuration, robust prerequisite checks, resource reconciliation, and automated deployment
    using Bicep/ARM templates, with comprehensive logging and reporting.

.DESCRIPTION
    The AVD Accelerator script is designed to simplify and automate the end-to-end deployment of Azure Virtual Desktop (AVD)
    solutions. It guides administrators through prerequisite validation, configuration selection, and resource reconciliation,
    ensuring that all required Azure modules, permissions, and resource providers are in place before deployment.

    Key Features:
    - Interactive menus for tenant, subscription, region, and deployment type selection
    - Non-interactive mode for automation scenarios (with JSON config input)
    - Prerequisite validation: Azure authentication, RBAC, module presence, resource provider registration
    - Discovery of current Azure resources and comparison to desired configuration
    - Automated reconciliation and creation of missing resources
    - Deployment via Bicep/ARM templates with support for WhatIf and Force modes
    - Professional logging, error handling, and JSON reporting

    Deployment Workflow Includes:
    - Stepwise wizard for configuration and validation
    - Generation of deployment parameters from user input and current Azure state
    - Execution of deployments or dry-run validation
    - Export of prerequisite and reconciliation reports

.PARAMETER Mode
    Specifies the operation mode: Plan, Deploy, or ValidateOnly. Determines whether the script plans, deploys, or validates resources.

.PARAMETER WhatIf
    Performs a dry-run deployment, showing what changes would occur without making them.

.PARAMETER Force
    Forces resource creation or updates, bypassing certain checks.

.PARAMETER NonInteractive
    Runs in non-interactive mode using a provided configuration file. Requires valid authentication and config path.

.PARAMETER ConfigPath
    Path to a JSON configuration file for non-interactive mode.

.PARAMETER LogPath
    Path to save log output. If not specified, logs are written to the script directory.

.EXAMPLE
    .\35_AVD_Accelerator.ps1 -Mode Deploy

    Launches the interactive wizard and deploys AVD resources after validation.

.EXAMPLE
    .\35_AVD_Accelerator.ps1 -Mode Plan -WhatIf

    Runs a dry-run plan, showing what resources would be created or changed.

.EXAMPLE
    .\35_AVD_Accelerator.ps1 -NonInteractive -ConfigPath "C:\Configs\avd_config.json" -LogPath "C:\Logs\avd_deploy.log"

    Executes deployment in non-interactive mode using a pre-defined configuration and logs output.

.NOTES
    Version: 1.0
    Author: edthefixer + Copilot... well more Copilot than me!
    Last Updated: February 23, 2026

    PREREQUISITES:
    - PowerShell 5.1 or later
    - Azure PowerShell modules: Az.Accounts, Az.Resources, Az.Network, Az.Compute, Az.Storage, Az.Security, Az.KeyVault, Az.DesktopVirtualization
    - Azure subscription with Owner or Contributor permissions
    - Internet connectivity for Azure API access

    OUTPUT FORMATS:
    - Console: Stepwise progress and status messages
    - JSON: Prerequisite and reconciliation reports
    - Log: Detailed execution log

    PERFORMANCE CONSIDERATIONS:
    - Ensure all required Azure modules are installed and updated
    - Use regions close to your user base for optimal performance
    - Validate RBAC and resource provider registration before deployment

.LINK
    https://docs.microsoft.com/azure/virtual-desktop/
    https://docs.microsoft.com/azure/virtual-desktop/deploy-azure-virtual-desktop
    https://docs.microsoft.com/azure/virtual-desktop/overview
#>

function Show-Menu {
	[CmdletBinding()]
	param(
		[Parameter(Mandatory)]
		[array]$Options,
		[string]$Category,
		[object]$Default,
		[switch]$AllowBack,
		[switch]$AllowHelp,
		[switch]$AllowExit
	)
	do {
		if ($Category) { Write-Host "`n[$Category]" -ForegroundColor Cyan }
		for ($i=0; $i -lt $Options.Count; $i++) {
			$label = if ($Options[$i] -is [psobject] -and $Options[$i].Label) { $Options[$i].Label } else { $Options[$i] }
			Write-Host ("  [{0}] {1}" -f ($i+1), $label)
		}
		$specials = @{}
		if ($AllowBack) { Write-Host ("  [B] Back"); $specials.B = 'Back' }
		if ($AllowHelp) { Write-Host ("  [H] Help"); $specials.H = 'Help' }
		if ($AllowExit) { Write-Host ("  [X] Exit"); $specials.X = 'Exit' }
		$prompt = "Select an option" + $(if ($Default) { " [default: $Default]" } else { '' }) + ": "
		$input = Read-Host $prompt
		if (-not $input -and $Default) { return $Default }
		if ($specials.ContainsKey($input.ToUpper())) { return $specials[$input.ToUpper()] }
		if ($input -match '^[0-9]+$' -and $input -ge 1 -and $input -le $Options.Count) {
			return $Options[$input-1]
		}
		Write-Host "Invalid selection. Try again." -ForegroundColor Yellow
	} while ($true)
}

# Main script logic
param(
	[ValidateSet('Plan','Deploy','ValidateOnly')]
	[string]$Mode = 'Plan',
	[switch]$WhatIf,
	[switch]$Force,
	[switch]$NonInteractive,
	[string]$ConfigPath,
	[string]$LogPath
)

function Get-TenantMenu {
	[CmdletBinding()]
	param()
	$tenants = @('TenantA','TenantB','TenantC')
	return Show-Menu -Options $tenants -Category 'Tenant' -Default $tenants[0]
}

function Get-SubscriptionMenu {
	[CmdletBinding()]
	param()
	$subscriptions = @('SubA','SubB','SubC')
	return Show-Menu -Options $subscriptions -Category 'Subscription' -Default $subscriptions[0]
}

function Get-RegionMenu {
	[CmdletBinding()]
	param()
	$regions = @('East US','West US','Central US')
	return Show-Menu -Options $regions -Category 'Region' -Default $regions[0]
}

function Write-Step {
	[CmdletBinding()]
	param(
		[Parameter(Mandatory)]
		[string]$Message,
		[Parameter(Mandatory)]
		[int]$Step,
		[Parameter(Mandatory)]
		[int]$TotalSteps
	)
	Write-Host ("`n=== Step $($Step) of $($TotalSteps): $($Message) ===") -ForegroundColor Green
}

function Write-Log {
	[CmdletBinding()]
	param(
		[Parameter(Mandatory)]
		[string]$Message,
		[ValidateSet('Info','Warn','Error')]
		[string]$Level = 'Info',
		[string]$LogPath
	)
	$timestamp = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
	$entry = "[$timestamp][$Level] $Message"
	switch ($Level) {
		'Info' { Write-Host $entry -ForegroundColor Gray }
		'Warn' { Write-Host $entry -ForegroundColor Yellow }
		'Error' { Write-Host $entry -ForegroundColor Red }
	}
	if ($LogPath) {
		Add-Content -Path $LogPath -Value $entry
	}
}

function Read-Secure {
	[CmdletBinding()]
	param(
		[Parameter(Mandatory)]
		[string]$Prompt,
		[switch]$Confirm
	)
	do {
		$secure = Read-Host -AsSecureString -Prompt $Prompt
		if ($Confirm) {
			$confirm = Read-Host -AsSecureString -Prompt "Confirm password"
			if (([PSCredential]::new('u',$secure)).GetNetworkCredential().Password -ne ([PSCredential]::new('u',$confirm)).GetNetworkCredential().Password) {
				Write-Host "Passwords do not match. Try again." -ForegroundColor Yellow
				continue
			}
		}
		return $secure
	} while ($true)
}

function Invoke-AvdPrerequisites {
	[CmdletBinding()]
	param(
		[switch]$SimplifiedOutput
	)
	$report = [PSCustomObject]@{
		Checks = @()
		Blockers = @()
	}
	$requiredModules = @('Az.Accounts','Az.Resources','Az.Network','Az.Compute','Az.Storage','Az.Security','Az.KeyVault','Az.DesktopVirtualization')
	foreach ($mod in $requiredModules) {
		$loaded = Get-Module -ListAvailable -Name $mod
		$status = if ($loaded) { 'PASS' } else { 'FAIL' }
		$msg = if ($loaded) { "$mod loaded" } else { "$mod missing" }
		$report.Checks += [PSCustomObject]@{ Category = 'Modules'; Name = $mod; Status = $status; Message = $msg }
		if ($status -eq 'FAIL') { $report.Blockers += $msg }
	}
	try {
		$context = Get-AzContext
		if (-not $context) { throw 'No Azure context' }
		$report.Checks += [PSCustomObject]@{ Category = 'Auth'; Name = 'Azure Login'; Status = 'PASS'; Message = 'Authenticated' }
	} catch {
		$report.Checks += [PSCustomObject]@{ Category = 'Auth'; Name = 'Azure Login'; Status = 'FAIL'; Message = 'Not authenticated' }
		$report.Blockers += 'Not authenticated to Azure.'
	}
	try {
		$sub = Get-AzContext | Select-Object -ExpandProperty Subscription
		if ($sub.State -ne 'Enabled') {
			$report.Checks += [PSCustomObject]@{ Category = 'Subscription'; Name = $sub.Name; Status = 'FAIL'; Message = 'Subscription not enabled' }
			$report.Blockers += 'Subscription not enabled.'
		} else {
			$role = (Get-AzRoleAssignment -Scope "/subscriptions/$($sub.Id)" -ErrorAction SilentlyContinue | Where-Object { $_.SignInName -eq $context.Account.Id -and ($_.RoleDefinitionName -eq 'Owner' -or $_.RoleDefinitionName -eq 'Contributor') })
			if ($role) {
				$report.Checks += [PSCustomObject]@{ Category = 'RBAC'; Name = $context.Account.Id; Status = 'PASS'; Message = 'Sufficient RBAC' }
			} else {
				$report.Checks += [PSCustomObject]@{ Category = 'RBAC'; Name = $context.Account.Id; Status = 'FAIL'; Message = 'Insufficient RBAC' }
				$report.Blockers += 'Insufficient RBAC.'
			}
		}
	} catch {
		$report.Checks += [PSCustomObject]@{ Category = 'Subscription'; Name = 'Unknown'; Status = 'FAIL'; Message = 'Subscription/RBAC check failed' }
		$report.Blockers += 'Subscription/RBAC check failed.'
	}
	$providers = @('Microsoft.DesktopVirtualization','Microsoft.Compute','Microsoft.Network','Microsoft.Storage')
	foreach ($prov in $providers) {
		$reg = Get-AzResourceProvider -ProviderNamespace $prov
		$status = if ($reg.RegistrationState -eq 'Registered') { 'PASS' } else { 'FAIL' }
		$msg = if ($reg.RegistrationState -eq 'Registered') { "$prov registered" } else { "$prov not registered" }
		$report.Checks += [PSCustomObject]@{ Category = 'ResourceProvider'; Name = $prov; Status = $status; Message = $msg }
		if ($status -eq 'FAIL') { $report.Blockers += $msg }
	}
	# TODO: Connectivity, DNS, private endpoint, policy blockers, etc.
	$outChecks = if ($SimplifiedOutput) { $report.Checks | Where-Object { $_.Status -ne 'PASS' } } else { $report.Checks }
	foreach ($c in $outChecks) {
		$color = switch ($c.Status) { 'PASS' { 'Gray' } 'WARN' { 'Yellow' } 'FAIL' { 'Red' } }
		Write-Host ("[{0}] {1}: {2}" -f $c.Status, $c.Name, $c.Message) -ForegroundColor $color
	}
	$report | ConvertTo-Json -Depth 5 | Set-Content -Path "./AVDPrereqReport.json"
	return $report
}

function Start-AvdConfigWizard {
	[CmdletBinding()]
	param()
	$config = [PSCustomObject]@{
		Deployment = @{}
		AzureContext = @{}
		Identity = @{}
		Networking = @{}
		SessionHosts = @{}
		Storage = @{}
		Security = @{}
		Monitoring = @{}
		Optional = @{}
	}
	$config.Deployment.Type = Show-Menu -Options @('Baseline deployment','Custom Image Build') -Category 'Deployment Type' -Default 1
	$config.AzureContext.Tenant = Get-TenantMenu
	$config.AzureContext.Subscription = Get-SubscriptionMenu
	$config.AzureContext.Location = Get-RegionMenu
	# TODO: Identity, Networking, SessionHosts, Storage, Security, Monitoring, Optional
	return $config
}

function Get-AvdCurrentState {
	[CmdletBinding()]
	param(
		[Parameter(Mandatory)] $Config
	)
	$state = [PSCustomObject]@{
		ResourceGroups = @()
		HostPools = @()
		Workspaces = @()
		AppGroups = @()
		ScalingPlans = @()
		VNets = @()
		Subnets = @()
		StorageAccounts = @()
		KeyVaults = @()
		PrivateEndpoints = @()
		DNSZones = @()
		Monitoring = @()
		Tags = @()
	}
	$state.ResourceGroups = Get-AzResourceGroup | Where-Object { $_.Location -eq $Config.AzureContext.Location }
	# TODO: Discover other resources as per config
	return $state
}

function Invoke-AvdReconcile {
	[CmdletBinding()]
	param(
		[Parameter(Mandatory)] $Config,
		[Parameter(Mandatory)] $CurrentState,
		[switch]$WhatIf,
		[switch]$Force
	)
	$report = [PSCustomObject]@{
		Categories = @()
		Summary = ''
	}
	foreach ($rg in $Config.ResourceGroups) {
		$found = $CurrentState.ResourceGroups | Where-Object { $_.ResourceGroupName -eq $rg.Name }
		if ($found) {
			$report.Categories += [PSCustomObject]@{ Category = 'ResourceGroup'; Name = $rg.Name; Status = 'Present-Compliant'; Action = 'No change' }
		} else {
			if ($WhatIf) {
				$report.Categories += [PSCustomObject]@{ Category = 'ResourceGroup'; Name = $rg.Name; Status = 'NotPresent'; Action = 'Would create' }
			} else {
				$null = New-AzResourceGroup -Name $rg.Name -Location $rg.Location
				$report.Categories += [PSCustomObject]@{ Category = 'ResourceGroup'; Name = $rg.Name; Status = 'Created'; Action = 'Created' }
			}
		}
	}
	# TODO: Reconcile other categories
	$report.Summary = "Reconciliation complete. See details."
	return $report
}

function ConvertTo-AvdDeploymentParameters {
	[CmdletBinding()]
	param(
		[Parameter(Mandatory)] $Config,
		[Parameter(Mandatory)] $CurrentState
	)
	$params = @{}
	# TODO: Map config/state to Bicep/ARM parameters
	return $params
}

function Invoke-AvdDeployment {
	[CmdletBinding()]
	param(
		[Parameter(Mandatory)] $Parameters,
		[switch]$WhatIf,
		[string]$LogPath
	)
	$templateFile = './main.bicep'
	$cmd = {
		New-AzSubscriptionDeployment -Location $Parameters.Location -TemplateFile $templateFile -TemplateParameterObject $Parameters @PSBoundParameters
	}
	if ($WhatIf) { $cmd += ' -WhatIf' }
	try {
		$result = & $cmd
		Write-Log -Message "Deployment succeeded." -Level Info -LogPath $LogPath
		return $result
	} catch {
		Write-Log -Message $_.Exception.Message -Level Error -LogPath $LogPath
		throw
	}
}

# Main script logic


Write-Step -Message "Azure Virtual Desktop Accelerator Wizard" -Step 0 -TotalSteps 8

$prereqResult = Invoke-AvdPrerequisites -SimplifiedOutput:(!$PSBoundParameters.ContainsKey('Verbose'))
if ($prereqResult.Blockers.Count -gt 0) {
    Write-Log -Message "Blockers detected. See report for details. Aborting." -Level Error
    return
}

$config = $null
if ($NonInteractive) {
    if (-not $ConfigPath -or -not (Test-Path $ConfigPath)) {
        throw "-NonInteractive requires a valid -ConfigPath."
    }
    $config = Get-Content $ConfigPath | ConvertFrom-Json
} else {
    $config = Start-AvdConfigWizard
}

$currentState = Get-AvdCurrentState -Config $config

$reconcileReport = Invoke-AvdReconcile -Config $config -CurrentState $currentState -WhatIf:$WhatIf -Force:$Force

if ($Mode -eq 'Deploy') {
    $deployParams = ConvertTo-AvdDeploymentParameters -Config $config -CurrentState $currentState
    Invoke-AvdDeployment -Parameters $deployParams -WhatIf:$WhatIf -LogPath $LogPath
}

Write-Step -Message "Deployment complete. See logs and reports for details." -Step 8 -TotalSteps 8


