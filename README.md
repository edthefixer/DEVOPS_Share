# DEVOPS_Share

# Azure Virtual Desktop and Windows 365 PowerShell Scripts

This repository contains a comprehensive collection of PowerShell scripts designed to automate and validate Azure Virtual Desktop (AVD) and Windows 365 deployments. These scripts cover various aspects of AVD lifecycle management, from initial prerequisites validation to ongoing maintenance and migration.

## Overview

The scripts are organized by functionality and numbered for sequential execution where applicable. They provide enterprise-grade automation for AVD environments, including network validation, resource management, security configuration, and operational tasks.

## Scripts List

### Prerequisites and Validation Scripts

- **01_AVD_SubscriptionVMSizeDiscovery_Final.ps1**: Advanced AVD VM size discovery with cost analysis, performance classification, and detailed reporting for Azure Virtual Desktop deployments.

- **02_AVD_Validation_Network_Comprehensive_Final.ps1**: Comprehensive AVD network configuration validation and automated remediation with VNet creation capabilities.

- **03_AVD_Check_Prerequisites_Platform_Final.ps1**: Platform-level AVD prerequisites validation independent of deployment methodology.

- **04_AVD_Check_Prerequisites_Confirmation_Final.ps1**: AVD Accelerator-specific prerequisites confirmation for pre-deployment and post-deployment readiness assessment.

### Enrollment and Configuration Scripts

- **05_AVD_EnrollmentAfterTheFactIntune_Final.ps1**: Validates Intune MDM enrollment and triggers auto-enrollment if needed for AVD session hosts.

- **10_AVD_EntraIDJoinValidation.ps1**: Validates Entra ID join status and triggers Intune auto-enrollment.

### Resource Management Scripts

- **06_AVD_Delete_Orphan_Resources_Final.ps1**: Identifies and cleans up orphan AVD resources from previous implementations.

- **20_AVD_ScallingPlanRBAC_Final.ps1**: Assigns required RBAC permissions for AVD scaling plans.

### Application and Publishing Scripts

- **40_AVD_Unified_Discovery_And_RemoteApp_Publisher_Final.ps1**: Enterprise-grade AVD RemoteApp discovery and publishing tool with security-first design and duplicate prevention.

### Proof of Concept and Reporting Scripts

- **50_AVD_Capture_AVDPoCProof.ps1**: Automates screenshot capture of AVD resources in Azure Portal for proof of concept documentation.

### Migration and Advanced Operations

- **60_AVD_MigrationWizard_00.ps1**: Interactive Azure migration orchestration tool for various migration scenarios with prerequisite validation.

### Accelerator Scripts

- **AVD_Accelerator_Modular.ps1**: Modular AVD Accelerator prerequisite checker with reusable functions. COMING

- **AVD_Accelerator_Single.ps1**: Interactive AVD Accelerator prerequisite checker and configuration tool. COMING

## Prerequisites

- PowerShell 5.1 or higher
- Azure PowerShell modules (Az.Accounts, Az.Resources, etc.)
- Appropriate Azure permissions for the operations being performed
- Administrative privileges on local machines where applicable

## Usage

1. Clone or download the repository
2. Review the script headers for specific prerequisites and parameters
3. Run scripts in order for sequential operations (where numbered)
4. Ensure proper authentication is configured for Azure operations

## Contributing

Please ensure scripts follow PowerShell best practices and include comprehensive comment-based help.

## License

[Add appropriate license information]

## Disclaimer

These scripts are provided as-is for automation purposes. Always test in non-production environments first and review Azure documentation for the latest requirements.
