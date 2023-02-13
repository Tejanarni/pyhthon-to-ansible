<#
.Synopsis
Script for deploying Rescue.

.Description
Deploys Rescue by copying artifacts from a build location (shared folder; e.g. reddog) to a Anible server.

.Parameter RescueBuildArtifacts
The path to a folder containing the build output from Rescue DNS repository. This could be reddog or a local build.
For a local build, run "build" in the root of the repository with an initialized CoreXT environment. The path should
then be: \Path\To\Networking\CloudDns\Rescue\out\debug-AMD64\rescue

.Parameter AnsibleBuildArtifacts
The path to a folder containing the build output from Linux Platform repository containing ansible playbook. This could be reddog or a local build.
For a local build, run "build" in the root of the repository with an initialized CoreXT environment. The path should
then be: \Path\To\Networking\CloudDns\Rescue\out\debug-AMD64\rescue

.Parameter WorkFolder
A local folder used by the script for downloading the necessary artifacts (from RescueBuildArtifacts, AnsibleBuildArtifacts, dSMS, etc.).
In practice, it can be any local path. Useful for debugging if necessary.

.Parameter BootstrapFolder
An optional folder that has pre-fetched bootstrap certificates. These certificates will be merged into
the deployment payload as part of the deployment process.

.Parameter ExcludeSecrets
Add this switch in case DSMS secrets should not be updated

.Parameter ExcludeServiceContainer
Add this switch in case you dont need to pack services

.Parameter ExcludeMonitoring
Add this switch in case you dont need to monitoring packages

.Parameter SkipRescueArtifactsUpload
Add this switch incase if we dont want to upload Rescue binaries from rescue repo
to ansible master like deploying ansible playbook.

.Parameter Env
Add a deployment environment

.Parameter Stage
Add a stage for the deployment environment

.Parameter Inventory
Add inventory file path for ansible deployment for service

.Parameter InventoryLimitParam
Add inventory limit parameter for ansible deployment for service

.Parameter Role
Add a role to be deployed (recursive or auth).

.Parameter AnsibleUser
Use this username to login to ansible masters

.Parameter Action
Determine which ansible playbook commands to run like deploy, rollback etc

.Parameter PlaybookTags
Dermine which tags to run in Ansible playbook

.Parameter DeployUsingTunnel
Deploy from SAW using ssh tunnel. This will be used for breakglass deployment

.Parameter JumpboxIp
IP to the Jumpbox used for creating the tunnel.

.Parameter MaxFailureAllowedPercentage
Maximum failure allowed percentage for ansible deployment.

.Parameter RollingUpdatePercentage
Number of hosts to execute ansible playbook simultaneously.

.Parameter dcname
dcname for DHCP servers Configuration

.Parameter BuildNumber
Build number of rescue/tmmap build

.Parameter ArtifactsUploadToAllServer
Upload ansible and rescue artifacts to all ansible and puppet masters
#>

Param(
    [Parameter(Mandatory = $False)]
    [string] $RescueBuildArtifacts,
    [Parameter(Mandatory = $False)]
    [string] $AnsibleBuildArtifacts,
    [Parameter(Mandatory = $False)]
    [string] $WorkFolder,
    [Parameter(Mandatory = $False)]
    [string] $BootstrapFolder,
    [Parameter(Mandatory = $False)]
    [switch] $ExcludeSecrets,
    [Parameter(Mandatory = $False)]
    [switch] $ExcludeServiceContainer,
    [Parameter(Mandatory = $False)]
    [switch] $ExcludeMonitoring,
    [Parameter(Mandatory = $False)]
    [switch] $SkipRescueArtifactsUpload,
    [Parameter(Mandatory = $False)]
    [System.Management.Automation.PSCredential] $TunnelCredential,
    [ValidateSet("test", "stage", "ppe", "perf", "prod", "fairfax", "mooncake", "usnat", "ussec")]
    [string] $Env = "test",
    [Parameter(Mandatory = $False)]
    [string] $InventoryLimitParam,
    [Parameter(Mandatory = $False)]
    [string] $Inventory,
    [Parameter(Mandatory = $False)]
    [string] $Stage = "stage1",
    [Parameter(Mandatory = $False)]
    [ValidateSet("recursive", "rescuepp", "auth", "tmmap", "ansibleplaybook", "rescuerrdata")]
    [string] $Role = "recursive",
    [ValidateSet("deploy", "rollback", "kernelUpdate", "noop")]
    [string] $Action = "noop",
    [Parameter(Mandatory = $False)]
    [ValidateSet("puppet_upload")]
    [string] $PlaybookTags = "",
    [Parameter(Mandatory = $False)]
    [string] $AnsibleUser = "deployuser",
    [Parameter(Mandatory = $False)]
    [switch] $DeployUsingTunnel,
    [Parameter(Mandatory = $False)]
    [string] $JumpboxIp = "10.20.197.179",
    [Parameter(Mandatory = $False)]
    [string] $MaxFailureAllowedPercentage = "50",
    [Parameter(Mandatory = $False)]
    [string] $RollingUpdatePercentage = "50%",
    [Parameter(Mandatory = $False)]
    [string] $KernelTargetVersion = "NoVersion",
    [Parameter(Mandatory = $False)]
    [string] $dcname = "NoVersion",
    [Parameter(Mandatory = $False)]
    [string] $TMMapPath,
    [Parameter (Mandatory = $False)]
    [string[]] $TMMapConfigFiles = @("geo_map.json", "proximity_configuration_collapsed.json", "proximity_configuration_exchangeonline.json", "proximity_configuration_exchangeonlinevnext.json"),
    [Parameter (Mandatory = $False)]
    [string] $BuildNumber,
    [Parameter(Mandatory = $False)]
    [switch] $ArtifactsUploadToAllServer
)

$ErrorActionPreference = 'stop'

$AnsibleIPHostMap = @{
    '10.64.12.18'          = @{
        hostname = 'bn3phxdnspm01'
        env = 'test'
    }
}

if ($WorkFolder -eq $null -or $WorkFolder -eq "") {
    $WorkFolder = "$env:TEMP\RescueDepTemp"
}

$AnsibleIps = @()
$AnsibleHostNames =  @()
$AnsibleIPHostMap.GetEnumerator() | ForEach-Object { 
    # Env should match and atleast one of the below condition should be saitisfied
    #  1. Upload to all server flag is set to true
    #  2. stage params matches
    #  3. stage is not defined for this env.
    if ($_.Value.env.Split(",").Contains($Env) -and ($ArtifactsUploadToAllServer -or ($Stage -eq $_.Value.stage) -or (-not $_.Value.ContainsKey("stage")))) {
        $AnsibleIps += $_.Key
        $AnsibleHostNames += $_.Value.hostname
    }
}

$PuppetLimitParam = $AnsibleHostNames -join ":"


Write-Host "Ansible Ips = $AnsibleIps"
Write-Host "Puppet limit params = $PuppetLimitParam"
$sshTools = "$AnsibleBuildArtifacts\deptools"

$AnsibleUserKeysFolder = "$WorkFolder\$AnsibleUser\keys"
$AnsibleHostKeysFolder = "$WorkFolder\ansiblemaster\keys"

$auth_test_settings = @{dsms_endpoint = "uswest-dsms.dsms.core.windows.net"; dsms_secrets_path = "/rescuedns/adhocsecrets/auth1804/test/keys"; dsms_certs = "bootstrap:/rescuedns/services/auth/test"; }
$auth_ppe_settings = @{dsms_endpoint = "uswest-dsms.dsms.core.windows.net"; dsms_secrets_path = "/rescuedns/adhocsecrets/auth1804/ppe/keys"; dsms_certs = "bootstrap:/rescuedns/services/auth/ppe"; }
$auth_prod_settings = @{dsms_endpoint = "uswest-dsms.dsms.core.windows.net"; dsms_secrets_path = "/rescuedns/adhocsecrets/auth1804/prod/keys"; dsms_certs = "bootstrap:/rescuedns/services/auth/prod"; }
$auth_mc_settings = @{dsms_endpoint = "chinanorth-dsms.dsms.core.chinacloudapi.cn"; dsms_secrets_path = "/rescuedns/adhocsecrets/auth1804/mooncake/keys"; dsms_certs = "bootstrap:/rescuedns/services/auth/mooncake"; }
$auth_ff_settings = @{dsms_endpoint = "usgoveast-dsms.dsms.core.usgovcloudapi.net"; dsms_secrets_path = "/rescuedns/adhocsecrets/auth1804/prod/keys"; dsms_certs = "bootstrap:/rescuedns/services/auth/fairfax"; }
$auth_usnat_settings = @{dsms_endpoint = "usnate-dsms.dsms.core.eaglex.ic.gov"; dsms_secrets_path = "/rescuedns-prod/adhocsecrets/auth1804/usnat/keys"; dsms_certs = "bootstrap:/rescuedns-prod/services/auth/usnat"; }
$auth_ussec_settings = @{dsms_endpoint = "ussece-dsms.dsms.core.microsoft.scloud"; dsms_secrets_path = "/rescuedns-prod/adhocsecrets/auth1804/ussec/keys"; dsms_certs = "bootstrap:/rescuedns-prod/services/auth/ussec"; }

$ansibleplaybook_test_settings = @{dsms_endpoint = "uswest-dsms.dsms.core.windows.net"; dsms_secrets_path = ""; dsms_certs = ""; }
$ansibleplaybook_ppe_settings = @{dsms_endpoint = "uswest-dsms.dsms.core.windows.net"; dsms_secrets_path = ""; dsms_certs = ""; }
$ansibleplaybook_prod_settings = @{dsms_endpoint = "uswest-dsms.dsms.core.windows.net"; dsms_secrets_path = ""; dsms_certs = ""; }
$ansibleplaybook_mc_settings = @{dsms_endpoint = "chinanorth-dsms.dsms.core.chinacloudapi.cn"; dsms_secrets_path = ""; dsms_certs = ""; }
$ansibleplaybook_ff_settings = @{dsms_endpoint = "usgoveast-dsms.dsms.core.usgovcloudapi.net"; dsms_secrets_path = ""; dsms_certs = ""; }
$ansibleplaybook_usnat_settings = @{dsms_endpoint = "usnate-dsms.dsms.core.eaglex.ic.gov"; dsms_secrets_path = ""; dsms_certs = ""; }
$ansibleplaybook_ussec_settings = @{dsms_endpoint = "ussece-dsms.dsms.core.microsoft.scloud"; dsms_secrets_path = ""; dsms_certs = ""; }

$rr_env_settings = @{}
$rr_env_settings.Add("test", @{dsms_endpoint = "uswest-dsms.dsms.core.windows.net"; })
$rr_env_settings.Add("perf", @{dsms_endpoint = "uswest-dsms.dsms.core.windows.net"; })
$rr_env_settings.Add("stage", @{dsms_endpoint = "uswest-dsms.dsms.core.windows.net"; })
$rr_env_settings.Add("prod", @{dsms_endpoint = "uswest-dsms.dsms.core.windows.net"; })
$rr_env_settings.Add("fairfax", @{dsms_endpoint = "usgoveast-dsms.dsms.core.usgovcloudapi.net"; })
$rr_env_settings.Add("mooncake", @{dsms_endpoint = "chinanorth-dsms.dsms.core.chinacloudapi.cn"; })
$rr_env_settings.Add("usnat", @{dsms_endpoint = "usnate-dsms.dsms.core.eaglex.ic.gov"; })
$rr_env_settings.Add("ussec", @{dsms_endpoint = "ussece-dsms.dsms.core.microsoft.scloud"; })

$auth_env_settings = @{}
$auth_env_settings.Add("test", $auth_test_settings)
$auth_env_settings.Add("stage", $auth_ppe_settings)
$auth_env_settings.Add("perf", $auth_ppe_settings)
$auth_env_settings.Add("prod", $auth_prod_settings)
$auth_env_settings.Add("mooncake", $auth_mc_settings)
$auth_env_settings.Add("fairfax", $auth_ff_settings)
$auth_env_settings.Add("usnat", $auth_usnat_settings)
$auth_env_settings.Add("ussec", $auth_ussec_settings)

$ansibleplaybook_env_settings = @{}
$ansibleplaybook_env_settings.Add("test", $ansibleplaybook_test_settings)
$ansibleplaybook_env_settings.Add("ppe", $ansibleplaybook_ppe_settings)
$ansibleplaybook_env_settings.Add("prod", $ansibleplaybook_prod_settings)
$ansibleplaybook_env_settings.Add("mooncake", $ansibleplaybook_mc_settings)
$ansibleplaybook_env_settings.Add("fairfax", $ansibleplaybook_ff_settings)
$ansibleplaybook_env_settings.Add("usnat", $ansibleplaybook_usnat_settings)
$ansibleplaybook_env_settings.Add("ussec", $ansibleplaybook_ussec_settings)

$auth_pp_env_settings = @{}
$auth_pp_env_settings.Add("test", @{dsms_endpoint = "uswest-dsms.dsms.core.windows.net"; })
$auth_pp_env_settings.Add("perf", @{dsms_endpoint = "uswest-dsms.dsms.core.windows.net"; })
$auth_pp_env_settings.Add("ppe", @{dsms_endpoint = "uswest-dsms.dsms.core.windows.net"; })
$auth_pp_env_settings.Add("prod", @{dsms_endpoint = "uswest-dsms.dsms.core.windows.net"; })
$auth_pp_env_settings.Add("fairfax", @{dsms_endpoint = "usgoveast-dsms.dsms.core.usgovcloudapi.net"; })
$auth_pp_env_settings.Add("mooncake", @{dsms_endpoint = "chinanorth-dsms.dsms.core.chinacloudapi.cn"; })
$auth_pp_env_settings.Add("usnat", @{dsms_endpoint = "usnate-dsms.dsms.core.eaglex.ic.gov"; })
$auth_pp_env_settings.Add("ussec", @{dsms_endpoint = "ussece-dsms.dsms.core.microsoft.scloud"; })

$env_settings = @{}
$env_settings.Add("auth", $auth_env_settings)
$env_settings.Add("recursive", $rr_env_settings)
$env_settings.Add("ansibleplaybook", $ansibleplaybook_env_settings)
$env_settings.Add("rescuepp", $auth_pp_env_settings)
$env_settings.Add("tmmap", $auth_pp_env_settings)

#TODO: convert all stage to PPE when we move to ansible repo
switch ($Env) {
    "test" { $Dsms_Root_Folder = "/rescuedns-test" }
    "ppe" { $Dsms_Root_Folder = "/rescuedns-ppe-prod" }
    "stage" { $Dsms_Root_Folder = "/rescuedns-ppe-prod" }
    "perf" { $Dsms_Root_Folder = "/rescuedns-ppe-prod" }
    "ussec" {$Dsms_Root_Folder = "/rescuedns-prod"}
    "usnat" {$Dsms_Root_Folder = "/rescuedns-prod"}
    default { $Dsms_Root_Folder = "/rescuedns" }


$dep_env_setting = $env_settings[$Role][$Env]
$dep_env_setting["dsms_hostkeys_path"] = $Dsms_Root_Folder + "/global/adhocsecrets/host/keys"
$dep_env_setting["dsms_loginkeys_path"] = $Dsms_Root_Folder + "/global/adhocsecrets/$Env/keys"

Write-Host "DE jump box IP: " ( Get-NetIPConfiguration | Where-Object { $_.IPv4DefaultGateway -ne $null -and $_.NetAdapter.Status -ne "Disconnected" }).IPv4Address.IPAddress

if ($DeployUsingTunnel) {
    if ($TunnelCredential -ne $null) {
        $TunnelUserName = $TunnelCredential.UserName
        $TunnelPassword = $TunnelCredential.GetNetworkCredential().Password
    }

    if ("" -eq $TunnelUserName) {
        $TunnelUserName = $UserName
    }

    if ("" -eq $TunnelPassword) {
        if ($TunnelUserName -eq $UserName) {
            $TunnelPassword = $Password
        }
        else {
            $tunnelCred = $(Get-Credential -Message "Please provide your GME password" -UserName $TunnelUserName)

            $TunnelUserName = $tunnelCred.UserName
            $TunnelPassword = $tunnelCred.GetNetworkCredential().Password
        }
    }
}

function Get_Build_Number {
    Write-Host "Validating deployment" -ForegroundColor Green
    if ("" -eq $BuildNumber) {
        $version_line = Get-Content $RescueBuildArtifacts\code\modules\config\files\version.htm
        $match = [regex]::Match($version_line, 'Version[ ]*([0-9.]*)[^0-9.]*([0-9.]*)')
        $BuildNumber = $match.Captures.groups[1].value + "." + $match.Captures.groups[2].value
    }
    return $BuildNumber.replace('.', '_')
}

$build_version = Get_Build_Number
$envstage = "$Role`_$Env`_$build_version".ToLower()
if ([System.String]::IsNullOrEmpty($BackupName)) {
    $BackupName = $envstage
}

Remove-Item -Path $AnsibleHostKeysFolder -Recurse -Force -ErrorAction SilentlyContinue
mkdir -Force $AnsibleHostKeysFolder

Write-Host "Getting host keys from dSMS..."
Write-Host Executing "$AnsibleBuildArtifacts\DsmsHelper\DsmsHelper.exe" -Command:download -DsmsName:$dep_env_setting['dsms_endpoint'] -ReadAsBytes:false -folder:$AnsibleHostKeysFolder -DsmsPrefix:$dep_env_setting['dsms_hostkeys_path']
& "$AnsibleBuildArtifacts\DsmsHelper\DsmsHelper.exe" -Command:download -DsmsName:$dep_env_setting['dsms_endpoint'] -ReadAsBytes:false -folder:$AnsibleHostKeysFolder -DsmsPrefix:$dep_env_setting['dsms_hostkeys_path']

if ( $LastExitCode -ne 0 ) {
    Write-Host "Error $LastExitCode returned from by dsmshelper"
    exit 1
}

Remove-Item -Path $AnsibleUserKeysFolder -Recurse -Force -ErrorAction SilentlyContinue
mkdir -Force $AnsibleUserKeysFolder

Write-Host "Getting $AnsibleUser keys from dSMS..."
Write-Host Executing "$AnsibleBuildArtifacts\DsmsHelper\DsmsHelper.exe" -Command:download -DsmsName:$dep_env_setting['dsms_endpoint'] -ReadAsBytes:false -folder:$AnsibleUserKeysFolder -DsmsPrefix:$dep_env_setting['dsms_loginkeys_path']
& "$AnsibleBuildArtifacts\DsmsHelper\DsmsHelper.exe" -Command:download -DsmsName:$dep_env_setting['dsms_endpoint'] -ReadAsBytes:false -folder:$AnsibleUserKeysFolder -DsmsPrefix:$dep_env_setting['dsms_loginkeys_path']

if ( $LastExitCode -ne 0 ) {
    Write-Host "Error $LastExitCode returned from by dsmshelper"
    exit 1
}

# Clean up last deployment

Write-Host "Cleaning up last deployment"
# The -Exclude flag is to ensure we're not accidentally deleting previously
# downloaded ansible user and host keys needed to connect to ansible master
Get-ChildItem -Path $WorkFolder -Force -Exclude ansiblemaster, $AnsibleUser | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
$_ = mkdir -Force $WorkFolder
Write-Host "Done"

# Compress
$toCompress = @()

if ($ArtifactsUploadToAllServer)
{
    if ($Role -ne "tmmap") {
        Write-Host "Adding all the folders except images to $WorkFolder\$envstage.zip"
        $toCompress += gci $RescueBuildArtifacts -Directory | ? { $_.Name -notin @("images", "global") }

        if ($IncludeGlobal) {
            Write-Host "Adding global configuration to $WorkFolder\$envstage.zip"
            $toCompress += Get-Item $RescueBuildArtifacts\global
        }
    }
    else {
        Write-Host "Adding all the TM Map resources to $WorkFolder\$envstage.zip"
        $toCompress += gci $TMMapPath -Directory
    }
}

# Compress
$toCompressAnsibleData = @()

if ($ArtifactsUploadToAllServer)
{
    $toCompressAnsibleData += Get-Item $AnsibleBuildArtifacts\ansible
    $toCompressAnsibleData += Get-Item $RescueBuildArtifacts\code\modules\config\lib\facter
    $toCompressAnsibleData += Get-Item $RescueBuildArtifacts\code\data
}

if ((-not $ExcludeServiceContainer) -and $ArtifactsUploadToAllServer) {
    if ("auth" -eq $Role -or "recursive" -eq $Role) {
        Write-Host "Adding resolver container image to $WorkFolder\$envstage.zip"
        $toCompress += gci $RescueBuildArtifacts\images\rescuerr_resolver.tar.gz
        $toCompress += gci $RescueBuildArtifacts\images\exabgp.tar.gz
    }
    if ("recursive" -eq $Role) {
        Write-Host "Adding unbound container image to $WorkFolder\$envstage.zip"
        $toCompress += gci $RescueBuildArtifacts\images\unbound.tar.gz
        $toCompress += gci $RescueBuildArtifacts\images\dnstap2mds.tar.gz
    }
    if ("rescuepp" -eq $Role) {
        Write-Host "Adding rescuepp container image to $WorkFolder\$envstage.zip"
        $toCompress += gci $RescueBuildArtifacts\images\zookeeper.tar.gz
        $toCompress += gci $RescueBuildArtifacts\images\kafka.tar.gz
        $toCompress += gci $RescueBuildArtifacts\images\kafkamon.tar.gz
        $toCompress += gci $RescueBuildArtifacts\images\changefeedreader.tar.gz
        $toCompress += gci $RescueBuildArtifacts\images\syncagent.tar.gz
        $toCompress += gci $RescueBuildArtifacts\images\knot-resolver.tar.gz
        $toCompress += gci $RescueBuildArtifacts\images\prometheus.tar.gz
        $toCompress += gci $RescueBuildArtifacts\images\prom-mdm-converter.tar.gz
        $toCompress += gci $RescueBuildArtifacts\images\dnstap2mds.tar.gz
        $toCompress += gci $RescueBuildArtifacts\images\exabgp.tar.gz
        $toCompress += gci $RescueBuildArtifacts\images\health_agent.tar.gz
        $toCompress += gci $RescueBuildArtifacts\images\syncmanager.tar.gz
        $toCompress += gci $RescueBuildArtifacts\images\billingpublisher.tar.gz
    }
}

if ((-not $ExcludeMonitoring) -and $ArtifactsUploadToAllServer) {
    Write-Host "Adding monitoring mdm, mdsd, fluentd container images and dreamon package to $WorkFolder\$envstage.zip"
    $toCompress += gci $RescueBuildArtifacts\images | ? { $_.Name -in @("mdm.tar.gz", "mdsd.tar.gz", "fluentd.tar.gz", "azsecpack.tar.gz") -or $_.Name -match "dreamon.*.deb" }
}

if ((-not $ExcludeSecrets) -and $ArtifactsUploadToAllServer) {
    echo $WorkFolder
    mkdir -Force $WorkFolder\keys

    if (![String]::IsNullOrEmpty($dep_env_setting['dsms_certs']) -or ![String]::IsNullOrEmpty($dep_env_setting['dsms_secrets_path'])) {
        Write-Host "Getting key from dSMS..."
        Write-Host Executing "$AnsibleBuildArtifacts\DsmsHelper\DsmsHelper.exe" -command:download -dsmsName:$dep_env_setting['dsms_endpoint'] -interactive:true -folder:$WorkFolder\keys -dsmsprefix:$dep_env_setting['dsms_secrets_path'] -certs:$dep_env_setting['dsms_certs']
        & "$AnsibleBuildArtifacts\DsmsHelper\DsmsHelper.exe" -command:download -dsmsName:$dep_env_setting['dsms_endpoint'] -interactive:true -folder:$WorkFolder\keys -dsmsprefix:$dep_env_setting['dsms_secrets_path'] -certs:$dep_env_setting['dsms_certs']

        if ($dep_env_setting['dsms_certs'].Contains("bootstrap:")) {
            mkdir $WorkFolder\keys\bootstrap
            $certList = $dep_env_setting['dsms_certs'].Split(";")

            foreach ($cert in $certList) {
                $certKv = $cert.Split(":")
                if ($certKv[0] -ieq "bootstrap") {
                    $certNameSplit = $certKv[1].Split("/")
                    $certName = $certNameSplit[$certNameSplit.Length - 1]
                    Move-Item $WorkFolder\keys\$certName $WorkFolder\keys\bootstrap
                }
            }
        }

        if ( $LastExitCode -ne 0 ) {
            Write-Host "Error $LastExitCode returned from by dsmshelper"
            exit 1
        }
    }
}

if ($ArtifactsUploadToAllServer)
{
    if ($BootstrapFolder) {
        mkdir -Force $WorkFolder\keys\bootstrap
        Copy-Item -Path $BootstrapFolder\* -Destination $WorkFolder\keys\bootstrap -Recurse
    }

    if (Test-Path -Path "$WorkFolder\keys") {
        Write-Host "Adding dsms keys to $WorkFolder\$envstage.zip"
        $toCompress += gci $WorkFolder | ? Name -eq keys
    }

    # Make sure there is no zip file since -Update is being used.
    rm $WorkFolder\$envstage.tmp.zip -ErrorAction SilentlyContinue
    rm $WorkFolder\$envstage.ansible.tmp.zip -ErrorAction SilentlyContinue
    Write-Host "Compressing..."

    Import-Module Microsoft.PowerShell.Archive -ErrorAction SilentlyContinue

    if ($?) {
        if (-not $SkipRescueArtifactsUpload) {
            Write-Host "Using PowerShell module Compress-Archive to compress envstage.tmp.zip"
            $toCompress | Compress-Archive -DestinationPath $WorkFolder\$envstage.tmp.zip -Update
        }
        Write-Host "Using PowerShell module Compress-Archive to compress envstage.ansible.tmp.zip"
        $toCompressAnsibleData | Compress-Archive -DestinationPath $WorkFolder\$envstage.ansible.tmp.zip -Update
    }
    else {
        if (-not $SkipRescueArtifactsUpload) {
            Write-Host "Using 7z.exe to compress envstage.tmp.zip"
            $toCompress | % { Invoke-Expression "$AnsibleBuildArtifacts\deptools\7z.exe a $WorkFolder\$envstage.tmp.zip $($_.FullName)" }
        }
        Write-Host "Using 7z.exe to compress envstage.ansible.tmp.zip"
        $toCompressAnsibleData | % { Invoke-Expression "$AnsibleBuildArtifacts\deptools\7z.exe a $WorkFolder\$envstage.ansible.tmp.zip $($_.FullName)" }
    }

    # Allows for cancelling mid compression without losing the previous build.
    if (-not $SkipRescueArtifactsUpload) {
        Move-Item -Force $WorkFolder\$envstage.tmp.zip $WorkFolder\$envstage.zip
        Write-Host "Compressed zip created $WorkFolder\$envstage.zip"
    }

    Move-Item -Force $WorkFolder\$envstage.ansible.tmp.zip $WorkFolder\$envstage.ansible.zip
    Write-Host "Compressed zip created $WorkFolder\$envstage.ansible.zip"

    Write-Host "Removing dSMS secrets from work folder"
    rm -Recurse -Force $WorkFolder\keys -ErrorAction Ignore
    Write-Host "Done"
}
function TunnelIsSetup {
    if ($null -eq $Global:RescueTunnelPid -or
        $null -eq (Get-Process -Id $Global:RescueTunnelPid -ErrorAction SilentlyContinue) -or
        "PLINK" -ine (Get-Process -Id $Global:RescueTunnelPid -ErrorAction SilentlyContinue).ProcessName) {
        Write-Host "Last known tunnel is not running"
        return $False
    }

    if ($null -eq $Global:RescueAnsibleAddresses -or
        $Global:RescueAnsibleAddresses.Length -ne $AnsibleIps.Length) {
        Write-Host "Last known ansible Addresses are different from current"
        return $False
    }

    foreach ($_ in $Global:RescueAnsibleAddresses) {
        if ($_.AnsibleIp -notin $AnsibleIps) {
            Write-Host "Previous ansible IP $($_.AnsibleIp) not in current list"
            return $False
        }

        if ($null -eq (Invoke-Expression "$sshTools\plink.exe -v -no-antispoof -t -pw '$Password' $UserName@localhost -P $($_.TunnelPort) 'ip -o a | grep -F $($_.AnsibleIp)'")) {
            Write-Host "Could not verify ansible $($_.AnsibleIp)"
            return $False
        }
    }

    Write-Host "Tunnel setup correctly"
    return $True
}


$AnsibleConnectAddresses = @()

if (-not $DeployUsingTunnel) {
    $AnsibleIps | % {
        $AnsibleConnectAddresses += @{ Ip = $_; Port = 22; AnsibleIp = $_; HostKey = Get-Content -Path "$AnsibleHostKeysFolder\$($AnsibleIPHostMap[$_]['hostname']).ssh.pub" }
    }
}
else {
    if (TunnelIsSetup) {
        Write-Host "Tunnel is already open"
        $Global:RescueAnsibleAddresses | % {
            $AnsibleConnectAddresses += @{ Ip = "localhost"; Port = $_.TunnelPort; AnsibleIp = $_.AnsibleIp }
            $tunnelPuppetPort--
        }
    }
    else {
        $arguments = ""
        $Global:RescueAnsibleAddresses = @()
        $tunnelPuppetPort = 7999

        $AnsibleIps | % {
            $Global:RescueAnsibleAddresses += @{ AnsibleIp = $_; TunnelPort = $tunnelPuppetPort }
            $arguments += "-L $tunnelPuppetPort`:$_`:22 "
            $AnsibleConnectAddresses += @{ Ip = "localhost"; Port = $tunnelPuppetPort; AnsibleIp = $_; HostKey = Get-Content -Path "$AnsibleHostKeysFolder\$($AnsibleIPHostMap[$_]['hostname']).ssh.pub" }
            $tunnelPuppetPort--
        }

        $arguments += "-no-antispoof -T -C $TunnelUserName@$JumpboxIp"
        Write-Host "Starting tunnel..."
        Write-Host "Start-Process $sshTools\plink.exe -ArgumentList -v $arguments"
        taskkill /IM plink.exe
        $tunnel = Start-Process "$sshTools\plink.exe" -ArgumentList "-v $arguments -pw $TunnelPassword" -PassThru
        $Global:RescueTunnelPid = $tunnel.Id
        Write-Host "Waiting 15s while tunnel is setup"
        Sleep 15
        Write-Host "Done"
    }
}
Write-Host "Pageant process init"

taskkill /IM PAGEANT.EXE /F /FI "STATUS eq RUNNING"
Write-Host "Killed Pageant process"

Invoke-Expression "$sshTools\PAGEANT.EXE $AnsibleUserKeysFolder\$AnsibleUser.ssh.ppk"
Write-Host "Started Pageant process for ssh key forwarding"
Sleep 15

if ($ArtifactsUploadToAllServer -and ($Action -ne "rollback"))
{
    #upload artifacts to all servers
    foreach ($AnsibleConnectAddress in $AnsibleConnectAddresses) {
        Write-Host "Ansible IP: $AnsibleConnectAddress.AnsibleIp; Connect IP: $($AnsibleConnectAddress.Ip); Connect Port: $($AnsibleConnectAddress.Port)"

        $remote_deploy_folder = "~/ansible/deploy/$envstage"
        $scp_files_to_copy = "$WorkFolder\$envstage.zip $WorkFolder\$envstage.ansible.zip"

        if ($SkipRescueArtifactsUpload) {
            $scp_files_to_copy = "$WorkFolder\$envstage.ansible.zip"
        }

        if ( $Role -ne "tmmap") {
            $scp_files_to_copy = "$scp_files_to_copy $RescueBuildArtifacts\scripts\deploy\deploy.sh"
        }
    
        Write-Host "Removing old deployment from Ansible Master"
        Invoke-Expression "$sshTools\plink.exe -hostkey '$($AnsibleConnectAddress.HostKey)' -no-antispoof -t $AnsibleUser@$($AnsibleConnectAddress.Ip) -P $($AnsibleConnectAddress.Port) 'sudo rm -rf $remote_deploy_folder && mkdir -p $remote_deploy_folder'"

        if ( $LastExitCode -ne 0 ) {
            Write-Host "Error $LastExitCode returned by plink"
            continue
        }

        Write-Host "Done"

        Write-Host "Copying new deployment to Ansible Master $scp_files_to_copy"
        Invoke-Expression "$sshTools\pscp.exe -q -hostkey '$($AnsibleConnectAddress.HostKey)' -P $($AnsibleConnectAddress.Port) -scp $scp_files_to_copy $AnsibleUser@$($AnsibleConnectAddress.Ip):$remote_deploy_folder"

        if ( $LastExitCode -ne 0 ) {
            Write-Host "Error $LastExitCode returned from pscp"
            continue
        }

        Write-Host "Done"
        Write-Host "Unzipping deployment artifacts"
        Invoke-Expression "$sshTools\plink.exe -A -hostkey '$($AnsibleConnectAddress.HostKey)' -no-antispoof $AnsibleUser@$($AnsibleConnectAddress.Ip) -P $($AnsibleConnectAddress.Port) 'unzip -q -d $remote_deploy_folder $remote_deploy_folder/$envstage.ansible.zip'"

        if ( $LastExitCode -gt 1 ) {
            Write-Host "Error $LastExitCode returned from by plink"
            continue
        }

        if ( $Role -eq "tmmap") {
            Invoke-Expression "$sshTools\plink.exe -A -hostkey '$($AnsibleConnectAddress.HostKey)' -no-antispoof $AnsibleUser@$($AnsibleConnectAddress.Ip) -P $($AnsibleConnectAddress.Port) 'unzip -q -d $remote_deploy_folder $remote_deploy_folder/$envstage.zip'"
        }

        if ( $LastExitCode -gt 1 ) {
            Write-Host "Error $LastExitCode returned from by plink"
            continue
        }

        Write-Host "unzip completes"

        Invoke-Expression "$sshTools\plink.exe -A -hostkey '$($AnsibleConnectAddress.HostKey)' -no-antispoof $AnsibleUser@$($AnsibleConnectAddress.Ip) -P $($AnsibleConnectAddress.Port) 'chmod u+x -R $remote_deploy_folder && find $remote_deploy_folder -type f -print0 | xargs -0 dos2unix  '"

        if ( $LastExitCode -ne 0 ) {
            Write-Host "Error $LastExitCode returned from by plink"
            continue
        }
    }
}

if ($Action -ne "noop")
{
    $IsDeploymentSuccessfull = $False
    foreach ($AnsibleConnectAddress in $AnsibleConnectAddresses) {
    $ssh_command_to_invoke = "ansible/deploy/$envstage/ansible/scripts/config_migration.py"
    Write-host "Executing config migration script $ssh_command_to_invoke"
    Invoke-Expression "$sshTools\plink.exe -A -hostkey '$($AnsibleConnectAddress.HostKey)' -no-antispoof $AnsibleUser@$($AnsibleConnectAddress.Ip) -P $($AnsibleConnectAddress.Port) 'python3 $ssh_command_to_invoke'"

    if ( $LastExitCode -ne 0 ) {
        Write-Host "Error $LastExitCode returned from by plink for configuration manager scripts"
        continue
}
    
    
    $ssh_command_to_invoke = "ansible/deploy/$envstage/ansible/scripts/execute_ansible_playbook.py"

    $DeploymentArguments = "--role $Role --env $Env --max_failure_allowed_percentage $MaxFailureAllowedPercentage --rolling_update_percentage $RollingUpdatePercentage --inventory $Inventory"

    if ( $Role -eq "tmmap") {
        $DeploymentArguments = "$DeploymentArguments --local_map_location $remote_deploy_folder/Resources"
        $TMMapConfigFiles | ForEach { $DeploymentArguments = "$DeploymentArguments --map_config_files $_" }
    }
    else {
        $DeploymentArguments = "$DeploymentArguments --build_version $build_version --KernelTargetVersion $KernelTargetVersion"

        if ($PlaybookTags) {
            $DeploymentArguments = "$DeploymentArguments --playbook_tags $PlaybookTags"
        }
    }

    if ($ArtifactsUploadToAllServer) {
        Write-host "Running command $ssh_command_to_invoke $DeploymentArguments --inv_limit $PuppetLimitParam --action puppet_upload"
        Invoke-Expression "$sshTools\plink.exe -A -hostkey '$($AnsibleConnectAddress.HostKey)' -no-antispoof $AnsibleUser@$($AnsibleConnectAddress.Ip) -P $($AnsibleConnectAddress.Port) 'rm -rf $remote_deploy_folder/ansible/env && rm -rf $remote_deploy_folder/ansible/inventory/hosts && python3 $ssh_command_to_invoke $DeploymentArguments --inv_limit $PuppetLimitParam --action puppet_upload'"
    }

    Write-host "Running command $ssh_command_to_invoke $DeploymentArguments --inv_limit `"$InventoryLimitParam`" --action $Action" 
    Invoke-Expression "$sshTools\plink.exe -A -hostkey '$($AnsibleConnectAddress.HostKey)' -no-antispoof $AnsibleUser@$($AnsibleConnectAddress.Ip) -P $($AnsibleConnectAddress.Port) 'rm -rf $remote_deploy_folder/ansible/env && rm -rf $remote_deploy_folder/ansible/inventory/hosts && python3 $ssh_command_to_invoke $DeploymentArguments --inv_limit $InventoryLimitParam  --action $Action'"

    if ( $LastExitCode -ne 0 ) {
        Write-Host "Error $LastExitCode returned from by plink"
        continue
    }

    $IsDeploymentSuccessfull = $True
    Write-Host "Done"
    break
    }

    if (-not $IsDeploymentSuccessfull) {
        Write-Host "Deployment failed in all ansible master"
        exit 1
    }
}

taskkill /F /IM PAGEANT.EXE
Write-Host "Kill Pageant process"

Write-Host "Removing $AnsibleUser keys..."
Remove-Item -Path $AnsibleUserKeysFolder -Recurse -Force -ErrorAction SilentlyContinue
Write-Host "Done"


Write-Host "Removing ansiblemaster host keys..."
Remove-Item -Path $AnsibleHostKeysFolder -Recurse -Force -ErrorAction SilentlyContinue
Write-Host "Done"
