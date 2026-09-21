<#
.SYNOPSIS
    Prépare un hôte Windows pour la virtualisation imbriquée (VMware Workstation, VirtualBox, EVE-NG, GNS3...).

.DESCRIPTION
    Désactive les mécanismes qui monopolisent la virtualisation matérielle : Hyper-V et plateformes associées,
    VBS (Virtualization-Based Security), HVCI (Intégrité de la mémoire) et Credential Guard.

    Avant toute modification, le script enregistre l'état initial de la machine dans un fichier JSON
    (utilisé plus tard par rollback.ps1 pour restaurer exactement cet état).

    Le script se déroule en deux temps :
      1. Exécution normale  -> applique les modifications, puis propose un redémarrage.
      2. Exécution -Verify  -> APRÈS redémarrage, contrôle que VBS est bien désactivé.

.PARAMETER Verify
    Ne modifie rien. Contrôle l'état actuel (à lancer après le redémarrage).

.PARAMETER Force
    Ne demande pas de confirmation avant de modifier la machine (pour l'automatisation).

.PARAMETER SkipReboot
    Ne propose pas de redémarrage à la fin.

.PARAMETER NoTranscript
    Ne crée pas de fichier journal.

.PARAMETER IncludeContainers
    Désactive aussi la fonctionnalité Windows "Containers", non nécessaire dans la plupart des cas.

.PARAMETER DisableServices
    Arrête et désactive aussi les services vmms / vmcompute / HvHost / lxssmanager.

.EXAMPLE
    .\activation.ps1 -WhatIf
    Simule l'exécution en affichant ce qui serait modifié, sans rien changer.

.EXAMPLE
    .\activation.ps1
    Exécution normale avec confirmation, sauvegarde de l'état initial et proposition de redémarrage.

.EXAMPLE
    .\activation.ps1 -Verify
    À lancer après le redémarrage pour valider le résultat.

.NOTES
    Codes de sortie : 0 = OK, 1 = au moins une erreur, 2 = annulé par l'utilisateur,
                      3 = (-Verify) la virtualisation imbriquée n'est pas encore possible.
#>

#Requires -Version 5.1
#Requires -RunAsAdministrator

# [CmdletBinding(SupportsShouldProcess)] ajoute automatiquement les options -WhatIf et -Confirm
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [switch]$Verify,             # Mode contrôle seul, aucune modification
    [switch]$Force,              # Saute la question de confirmation
    [switch]$SkipReboot,         # Ne propose pas de redémarrage
    [switch]$NoTranscript,       # Pas de fichier journal
    [switch]$IncludeContainers,  # Inclut la fonctionnalité "Containers"
    [switch]$DisableServices     # Désactive aussi les services Hyper-V / WSL
)

# Toute erreur non gérée arrête le script (les blocs try/catch décident ensuite quoi faire)
$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------------------
# Fonctions d'affichage (couleurs pour distinguer étapes, succès, infos, alertes)
# ---------------------------------------------------------------------------
function Write-Step { param([string]$Message) Write-Host "`n=== $Message ===" -ForegroundColor Cyan }      # Titre d'étape
function Write-Ok   { param([string]$Message) Write-Host "[OK] $Message"   -ForegroundColor Green }       # Action réussie
function Write-Info { param([string]$Message) Write-Host "[INFO] $Message" -ForegroundColor Gray }        # Information neutre
function Write-Warn { param([string]$Message) Write-Host "[ATTENTION] $Message" -ForegroundColor Yellow } # Point de vigilance

# ---------------------------------------------------------------------------
# Emplacements des fichiers produits par le script
# ---------------------------------------------------------------------------
# ProgramData n'est pas redirigé par OneDrive contrairement au Bureau et convient aux fichiers système
$WorkDir           = Join-Path $env:ProgramData 'nested-virt-enabling'
# Fichier "état d'origine" : écrit une seule fois, à la toute première exécution, jamais écrasé
$OriginalStatePath = Join-Path $WorkDir 'original-state.json'
# Instantané horodaté de CHAQUE exécution (utile pour l'historique et le diagnostic)
$SnapshotPath      = Join-Path $WorkDir ("snapshot-{0:yyyyMMdd-HHmmss}.json" -f (Get-Date))
# Fichier journal (transcription de tout ce qui s'affiche à l'écran)
$LogPath           = Join-Path $WorkDir 'nested-virt-enabling.log'

# ---------------------------------------------------------------------------
# Éléments à traiter
# ---------------------------------------------------------------------------
# Fonctionnalités Windows qui gardent l'hyperviseur Windows actif
$featuresToDisable = @(
    'Microsoft-Hyper-V-All',          # Tous les composants Hyper-V
    'HypervisorPlatform',             # Windows Hypervisor Platform (WHP)
    'VirtualMachinePlatform',         # Plateforme de VM (WSL2, Docker Desktop)
    'Containers-DisposableClientVM'   # Windows Sandbox
)
# "Containers" n'est désactivée que sur demande explicite (-IncludeContainers)
if ($IncludeContainers) { $featuresToDisable += 'Containers' }
# Liste complète suivie dans l'instantané (même si non modifiée, pour un rollback fidèle)
$featuresTracked = @($featuresToDisable + 'Containers') | Select-Object -Unique

# Services liés à Hyper-V / WSL (touchés seulement avec -DisableServices)
$serviceList = @('vmms', 'vmcompute', 'HvHost', 'lxssmanager')

# Valeurs de registre à mettre à 0.
#  Mode 'Force'    : la valeur est créée si elle n'existe pas.
#  Mode 'IfExists' : la valeur n'est modifiée que si elle existe déjà (évite de créer de fausses "stratégies").
$registryTargets = @(
    # VBS activé/désactivé au niveau du système
    @{ Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard'; Name = 'EnableVirtualizationBasedSecurity'; Value = 0; Mode = 'Force' },
    # Exigences de sécurité de plateforme (Secure Boot, DMA...)
    @{ Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard'; Name = 'RequirePlatformSecurityFeatures'; Value = 0; Mode = 'Force' },
    # HVCI / Intégrité de la mémoire
    @{ Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity'; Name = 'Enabled'; Value = 0; Mode = 'Force' },
    # Credential Guard (scénario dédié)
    @{ Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\CredentialGuard'; Name = 'Enabled'; Value = 0; Mode = 'IfExists' },
    # Credential Guard côté LSA (0 = désactivé ; ne retire PAS un éventuel verrou UEFI)
    @{ Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'; Name = 'LsaCfgFlags'; Value = 0; Mode = 'IfExists' },
    # Stratégies (GPO locale ou de domaine) : neutralisées uniquement si elles existent déjà
    @{ Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard'; Name = 'EnableVirtualizationBasedSecurity'; Value = 0; Mode = 'IfExists' },
    @{ Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard'; Name = 'RequirePlatformSecurityFeatures'; Value = 0; Mode = 'IfExists' },
    @{ Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard'; Name = 'LsaCfgFlags'; Value = 0; Mode = 'IfExists' }
)

# ---------------------------------------------------------------------------
# Fonctions utilitaires
# ---------------------------------------------------------------------------

# Exécute bcdedit et renvoie son code de sortie + sa sortie texte.
# Nécessaire car try/catch ne capte pas l'échec d'un programme externe : il faut lire $LASTEXITCODE.
function Invoke-Bcdedit {
    param([string[]]$Arguments)
    $previous = $ErrorActionPreference          # Mémorise le comportement d'erreur actuel
    $ErrorActionPreference = 'Continue'         # Évite qu'un message d'erreur de bcdedit (stderr) arrête le script
    try {
        $output = & bcdedit.exe @Arguments 2>&1 | ForEach-Object { $_.ToString() }   # Lance bcdedit, fusionne stderr dans la sortie
        $code = $LASTEXITCODE                                                         # Code de retour réel du programme
    }
    finally {
        $ErrorActionPreference = $previous      # Restaure le comportement d'erreur d'origine
    }
    return [pscustomobject]@{ ExitCode = $code; Output = ($output -join "`n") }
}

# Lit la valeur actuelle de hypervisorlaunchtype dans l'entrée de démarrage courante
function Get-BcdHypervisorLaunchType {
    $result = Invoke-Bcdedit -Arguments @('/enum', '{current}')    # '{current}' entre quotes : sinon PowerShell l'interprète mal
    if ($result.ExitCode -ne 0) { return '(indéterminé)' }          # bcdedit a échoué
    $line = $result.Output -split "`n" | Where-Object { $_ -match 'hypervisorlaunchtype' } | Select-Object -First 1
    if ($line) { return (($line -replace '\s+', ' ').Trim()) }      # Ex. "hypervisorlaunchtype Auto"
    return '(non défini)'                                           # Ligne absente = valeur par défaut de Windows
}

# Lit l'état de la sécurité basée sur la virtualisation (VBS) via WMI/CIM
function Get-VbsState {
    try {
        $dg = Get-CimInstance -Namespace 'root\Microsoft\Windows\DeviceGuard' -ClassName Win32_DeviceGuard
        $running = @(); if ($dg.SecurityServicesRunning) { $running = @($dg.SecurityServicesRunning) }   # Services de sécurité actifs
        return [pscustomobject]@{ Available = $true; Status = [int]$dg.VirtualizationBasedSecurityStatus; Running = $running }
    }
    catch {
        # L'API peut être absente (éditions Windows limitées) : on le signale sans planter
        return [pscustomobject]@{ Available = $false; Status = $null; Running = @() }
    }
}

# Affiche l'état VBS de façon lisible
function Show-VbsState {
    param($State)
    if (-not $State.Available) { Write-Info 'API Win32_DeviceGuard indisponible sur ce système.'; return }
    $statusText = @{ 0 = 'désactivé'; 1 = 'configuré mais non actif'; 2 = 'ACTIF' }[$State.Status]           # Traduit le code numérique
    Write-Info "VirtualizationBasedSecurityStatus : $($State.Status) ($statusText)"
    $labels = @{ 0 = 'Aucun'; 1 = 'Credential Guard'; 2 = 'HVCI (intégrité de la mémoire)'; 3 = 'System Guard Secure Launch'; 4 = 'Mesure du firmware SMM' }
    $names = @($State.Running | ForEach-Object { if ($labels.ContainsKey([int]$_)) { $labels[[int]$_] } else { "Inconnu ($_)" } })
    if ($names.Count -eq 0) { $names = @('Aucun') }
    Write-Info "Services de sécurité actifs        : $($names -join ', ')"
}

# Lit une valeur de registre et indique si la clé et la valeur existaient (pour l'instantané)
function Get-RegSnapshot {
    param([string]$Path, [string]$Name)
    $keyExists = Test-Path -LiteralPath $Path                              # La clé existe-t-elle ?
    $valueExists = $false; $value = $null
    if ($keyExists) {
        $prop = Get-ItemProperty -LiteralPath $Path -Name $Name -ErrorAction SilentlyContinue   # Lecture silencieuse
        if ($null -ne $prop -and $null -ne $prop.PSObject.Properties[$Name]) {
            $valueExists = $true                                            # La valeur existe
            $value = $prop.$Name                                            # Et voici son contenu
        }
    }
    return [pscustomobject]@{ Path = $Path; Name = $Name; KeyExisted = $keyExists; ValueExisted = $valueExists; Value = $value }
}

# Écrit une valeur DWORD dans le registre. Renvoie $true si une modification a eu lieu.
function Set-RegValue {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([string]$Path, [string]$Name, [int]$Value, [switch]$OnlyIfExists)

    $snap = Get-RegSnapshot -Path $Path -Name $Name                                          # État actuel de la valeur
    if ($OnlyIfExists -and -not $snap.ValueExisted) { Write-Info "Ignoré (absent) : $Path\$Name"; return $false }   # Mode IfExists
    if ($snap.ValueExisted -and $snap.Value -eq $Value) { Write-Info "Déjà à $Value : $Path\$Name"; return $false } # Rien à faire

    if ($PSCmdlet.ShouldProcess("$Path\$Name", "Définir la valeur à $Value")) {              # Respecte -WhatIf
        if (-not (Test-Path -LiteralPath $Path)) { New-Item -Path $Path -Force | Out-Null }  # Crée la clé si nécessaire
        New-ItemProperty -LiteralPath $Path -Name $Name -Value $Value -PropertyType DWord -Force | Out-Null   # Écrit la valeur
        Write-Ok "$Path\$Name = $Value"
        return $true
    }
    return $false
}

# Vérifie si BitLocker protège le disque système (un changement de démarrage peut réclamer la clé de récupération)
function Test-BitLockerProtection {
    if (-not (Get-Command Get-BitLockerVolume -ErrorAction SilentlyContinue)) {
        Write-Info 'Module BitLocker indisponible : contrôle ignoré.'; return $false      # Ex. édition Famille
    }
    try {
        $volume = Get-BitLockerVolume -MountPoint $env:SystemDrive                         # Disque système (généralement C:)
        if ("$($volume.ProtectionStatus)" -eq 'On') { return $true }                       # Protégé par BitLocker
    }
    catch { Write-Info "Contrôle BitLocker impossible : $($_.Exception.Message)" }
    return $false
}

# ---------------------------------------------------------------------------
# Programme principal
# ---------------------------------------------------------------------------
$transcriptStarted = $false   # Sert à n'arrêter la transcription que si elle a démarré
$restartNeeded     = $false   # Passe à $true dès qu'une modification exige un redémarrage
$changes           = 0        # Nombre de modifications appliquées
$failures          = 0        # Nombre d'échecs rencontrés

try {
    # Journal : créé sauf demande contraire ; ignoré en simulation (-WhatIf) pour ne rien écrire sur le disque
    if (-not $NoTranscript -and -not $WhatIfPreference) {
        if (-not (Test-Path -LiteralPath $WorkDir)) { New-Item -ItemType Directory -Path $WorkDir -Force | Out-Null }   # Crée le dossier de travail
        Start-Transcript -Path $LogPath -Append | Out-Null                                                             # Démarre l'enregistrement
        $transcriptStarted = $true
    }

    Write-Host 'Virtualisation imbriquée : préparation de l''hôte Windows' -ForegroundColor Cyan

    # =======================================================================
    # MODE -Verify : contrôle seul, à lancer après redémarrage
    # =======================================================================
    if ($Verify) {
        Write-Step 'Contrôle de l''état actuel (après redémarrage)'
        $state = Get-VbsState                                                       # Lit l'état VBS
        Show-VbsState -State $state                                                 # L'affiche
        $hypervisorPresent = [bool](Get-CimInstance -ClassName Win32_ComputerSystem).HypervisorPresent   # Un hyperviseur tourne-t-il ?
        Write-Info "Hyperviseur Windows présent : $hypervisorPresent"
        Write-Info "BCD : $(Get-BcdHypervisorLaunchType)"                          # Valeur hypervisorlaunchtype

        if ($state.Available -and $state.Status -eq 0 -and -not $hypervisorPresent) {
            Write-Ok 'VBS est désactivé et aucun hyperviseur Windows ne tourne : la virtualisation imbriquée est possible.'
            exit 0
        }
        if ($hypervisorPresent) { Write-Warn 'Un hyperviseur Windows est encore actif (fonctionnalité Hyper-V/WHP restante, ou VBS toujours actif).' }
        if ($state.Available -and $state.Status -ne 0) { Write-Warn 'VBS est toujours actif : verrou UEFI, stratégie de groupe ou sécurité constructeur probable.' }
        Write-Host "`nPistes :" -ForegroundColor Yellow
        Write-Host '  1. Vérifier les GPO : gpresult /h "$env:TEMP\gpo.html"' -ForegroundColor Yellow
        Write-Host '  2. Utiliser l''outil Microsoft : .\dgreadiness_v3.6\DG_Readiness_Tool_v3.6.ps1 -Capable, puis -Disable, puis -Ready' -ForegroundColor Yellow
        Write-Host '  3. Chercher dans le BIOS/UEFI une option "Virtualization-based Security" ou équivalente' -ForegroundColor Yellow
        exit 3
    }

    # =======================================================================
    # ÉTAPE 1 : Analyse du contexte
    # =======================================================================
    Write-Step '1. Analyse du contexte'
    $os = Get-CimInstance -ClassName Win32_OperatingSystem                           # Informations sur Windows
    Write-Info "Système : $($os.Caption) (build $($os.BuildNumber))"
    $cs = Get-CimInstance -ClassName Win32_ComputerSystem                            # Informations sur la machine
    if ($cs.PartOfDomain) {
        Write-Warn 'Machine jointe à un domaine : une GPO peut réactiver VBS après un gpupdate. Validez avec votre service IT/sécurité.'
        Write-Info 'Diagnostic conseillé : gpresult /h rapport.html'
    }
    else { Write-Ok 'Machine hors domaine : seule la configuration locale est en jeu.' }

    # Test du BIOS/UEFI : faussé si un hyperviseur tourne déjà, donc effectué uniquement dans le cas contraire
    if ($cs.HypervisorPresent) {
        Write-Info 'Hyperviseur déjà présent : le test VT-x/AMD-V via WMI serait faussé, il est ignoré.'
    }
    else {
        $cpu = Get-CimInstance -ClassName Win32_Processor | Select-Object -First 1   # Premier processeur
        if ($cpu.VirtualizationFirmwareEnabled -eq $false) { Write-Warn 'VT-x/AMD-V semble désactivé dans le BIOS/UEFI : activez-le dans le firmware.' }
        else { Write-Ok 'Virtualisation matérielle activée dans le BIOS/UEFI.' }
    }

    $bitLockerOn = Test-BitLockerProtection                                          # BitLocker actif sur le disque système ?
    if ($bitLockerOn) { Write-Warn 'BitLocker protège le disque système : sauvegardez votre clé de récupération avant de continuer (manage-bde -protectors -get C:).' }

    Write-Info 'État initial de la sécurité basée sur la virtualisation :'
    $stateBefore = Get-VbsState                                                      # État VBS avant modification
    Show-VbsState -State $stateBefore
    $bcdBefore = Get-BcdHypervisorLaunchType                                         # Valeur BCD avant modification
    Write-Info "BCD : $bcdBefore"

    # =======================================================================
    # ÉTAPE 2 : Confirmation explicite
    # =======================================================================
    if (-not $Force -and -not $WhatIfPreference) {
        Write-Warn 'Ce script va RÉDUIRE la sécurité de cet hôte (VBS, HVCI, Credential Guard, Hyper-V).'
        Write-Info "L'état initial sera sauvegardé dans : $WorkDir"
        $answer = Read-Host 'Tapez OUI pour continuer'                                # Demande de confirmation
        if ($answer -notmatch '^(oui|o|yes|y)$') { Write-Info 'Opération annulée.'; exit 2 }
    }

    # =======================================================================
    # ÉTAPE 3 : Sauvegarde de l'état initial (avant TOUTE modification)
    # =======================================================================
    Write-Step '3. Sauvegarde de l''état initial'

    # Table des fonctionnalités Windows (lue une seule fois : indépendant de la langue du système)
    $allFeatures = @{}
    try { foreach ($f in (Get-WindowsOptionalFeature -Online)) { $allFeatures[$f.FeatureName] = [string]$f.State } }
    catch { Write-Warn "Lecture des fonctionnalités Windows impossible : $($_.Exception.Message)" }

    # Photographie des fonctionnalités suivies
    $featureSnapshot = @($featuresTracked | ForEach-Object {
        [pscustomobject]@{ Name = $_; State = $(if ($allFeatures.ContainsKey($_)) { $allFeatures[$_] } else { 'NotPresent' }) }
    })
    # Photographie des valeurs de registre ciblées
    $registrySnapshot = @($registryTargets | ForEach-Object { Get-RegSnapshot -Path $_.Path -Name $_.Name })
    # Photographie des services (type de démarrage et état)
    $serviceSnapshot = @($serviceList | ForEach-Object {
        $svc = Get-Service -Name $_ -ErrorAction SilentlyContinue
        [pscustomobject]@{ Name = $_; Present = [bool]$svc; StartType = $(if ($svc) { "$($svc.StartType)" } else { $null }); Status = $(if ($svc) { "$($svc.Status)" } else { $null }) }
    })

    # Regroupe tout dans un objet unique, écrit ensuite en JSON
    $snapshot = [ordered]@{
        SchemaVersion        = 1                                                    # Version du format (utile au rollback)
        CreatedAt            = (Get-Date).ToString('o')                             # Date/heure ISO 8601
        ComputerName         = $env:COMPUTERNAME
        OSCaption            = $os.Caption
        OSBuild              = $os.BuildNumber
        VbsStatusBefore      = $stateBefore.Status
        SecurityServicesBefore = @($stateBefore.Running)
        HypervisorLaunchType = $bcdBefore
        Features             = $featureSnapshot
        Registry             = $registrySnapshot
        Services             = $serviceSnapshot
    }
    $json = $snapshot | ConvertTo-Json -Depth 6                                     # Conversion en JSON

    if ($PSCmdlet.ShouldProcess($SnapshotPath, 'Écrire l''instantané de l''état initial')) {
        if (-not (Test-Path -LiteralPath $WorkDir)) { New-Item -ItemType Directory -Path $WorkDir -Force | Out-Null }   # Dossier de travail
        Set-Content -LiteralPath $SnapshotPath -Value $json -Encoding UTF8          # Instantané horodaté de cette exécution
        Write-Ok "Instantané : $SnapshotPath"
        # "État d'origine" : conservé uniquement s'il n'existe pas encore, pour ne jamais enregistrer un état déjà modifié
        if (-not (Test-Path -LiteralPath $OriginalStatePath)) {
            Copy-Item -LiteralPath $SnapshotPath -Destination $OriginalStatePath
            Write-Ok "État d'origine conservé : $OriginalStatePath"
        }
        else { Write-Info "État d'origine déjà présent (conservé tel quel) : $OriginalStatePath" }
    }

    # =======================================================================
    # ÉTAPE 4 : Désactivation des fonctionnalités Windows
    # =======================================================================
    Write-Step '4. Désactivation des fonctionnalités Windows'
    foreach ($feature in $featuresToDisable) {
        if (-not $allFeatures.ContainsKey($feature)) { Write-Info "$feature : absente de ce système."; continue }      # Fonctionnalité inexistante
        if ($allFeatures[$feature] -notin @('Enabled', 'EnablePending')) { Write-Info "$feature : déjà désactivée."; continue }   # Rien à faire
        if ($PSCmdlet.ShouldProcess($feature, 'Désactiver la fonctionnalité Windows')) {
            try {
                Disable-WindowsOptionalFeature -Online -FeatureName $feature -NoRestart -ErrorAction Stop | Out-Null   # Désactive sans redémarrer
                Write-Ok "$feature désactivée."
                $changes++; $restartNeeded = $true
            }
            catch { Write-Warn "$feature : échec ($($_.Exception.Message))"; $failures++ }                             # Vrai échec (≠ absente)
        }
    }

    # =======================================================================
    # ÉTAPE 5 : Registre (VBS, Credential Guard, HVCI)
    # =======================================================================
    Write-Step '5. Registre : VBS, Credential Guard, HVCI'
    foreach ($target in $registryTargets) {
        try {
            $changed = Set-RegValue -Path $target.Path -Name $target.Name -Value $target.Value -OnlyIfExists:($target.Mode -eq 'IfExists')
            if ($changed) { $changes++; $restartNeeded = $true }
        }
        catch { Write-Warn "$($target.Path)\$($target.Name) : échec ($($_.Exception.Message))"; $failures++ }
    }

    # =======================================================================
    # ÉTAPE 6 : Empêcher le lancement de l'hyperviseur au démarrage (BCD)
    # =======================================================================
    Write-Step '6. Démarrage : hypervisorlaunchtype off'
    if ($bcdBefore -match '(?i)\boff\b') { Write-Info "Déjà configuré : $bcdBefore" }       # Déjà sur "off"
    elseif ($PSCmdlet.ShouldProcess('BCD {current}', 'hypervisorlaunchtype off')) {
        $bcd = Invoke-Bcdedit -Arguments @('/set', 'hypervisorlaunchtype', 'off')           # Applique la valeur
        if ($bcd.ExitCode -eq 0) {                                                          # Succès uniquement si code de retour = 0
            Write-Ok "BCD : $(Get-BcdHypervisorLaunchType)"                                 # Relit pour confirmer
            $changes++; $restartNeeded = $true
        }
        else { Write-Warn "bcdedit a échoué (code $($bcd.ExitCode)) : $($bcd.Output)"; $failures++ }
    }

    # =======================================================================
    # ÉTAPE 7 : Services Hyper-V / WSL (facultatif)
    # =======================================================================
    Write-Step '7. Services Hyper-V / WSL'
    if (-not $DisableServices) { Write-Info 'Ignorée (utilisez -DisableServices pour l''activer) : la désactivation des fonctionnalités suffit généralement.' }
    else {
        foreach ($svcName in $serviceList) {
            $svc = Get-Service -Name $svcName -ErrorAction SilentlyContinue                 # Le service existe-t-il ?
            if (-not $svc) { Write-Info "$svcName : absent de cet hôte."; continue }
            if ($PSCmdlet.ShouldProcess($svcName, 'Arrêter et désactiver le service')) {
                try {
                    if ($svc.Status -eq 'Running') { Stop-Service -Name $svcName -Force -ErrorAction Stop }   # Arrête s'il tourne
                    Set-Service -Name $svcName -StartupType Disabled -ErrorAction Stop                          # Empêche le démarrage automatique
                    Write-Ok "$svcName arrêté et désactivé."
                    $changes++
                }
                catch { Write-Warn "$svcName : échec ($($_.Exception.Message))"; $failures++ }
            }
        }
    }

    # =======================================================================
    # ÉTAPE 8 : Bilan (avant redémarrage)
    # =======================================================================
    Write-Step '8. Bilan'
    Write-Info "Modifications appliquées : $changes | Échecs : $failures"
    Write-Info "État de sauvegarde        : $SnapshotPath"
    # L'état VBS lu maintenant est celui d'AVANT le redémarrage : il n'a pas encore changé et n'est donc pas concluant
    Write-Warn 'La vérification de VBS n''est fiable qu''APRÈS redémarrage. Relancez : .\activation.ps1 -Verify'

    # =======================================================================
    # ÉTAPE 9 : Redémarrage (proposé, avec délai)
    # =======================================================================
    if ($restartNeeded -and -not $SkipReboot -and -not $WhatIfPreference) {
        $answer = Read-Host 'Un redémarrage est nécessaire. Redémarrer dans 60 secondes ? [O/N]'
        if ($answer -match '^(o|oui|y|yes)$') {
            & shutdown.exe /r /t 60 /c 'Redémarrage : activation de la virtualisation imbriquée'   # Délai de 60 s pour enregistrer son travail
            Write-Info 'Redémarrage programmé. Pour annuler : shutdown /a'
        }
        else { Write-Info 'Pensez à redémarrer manuellement avant de tester VMware, VirtualBox, EVE-NG ou GNS3.' }
    }
    if ($transcriptStarted) { Write-Host "`nJournal : $LogPath" -ForegroundColor Gray }

    if ($failures -gt 0) { exit 1 }   # Code de sortie non nul si au moins une étape a échoué
    exit 0
}
finally {
    # Arrête la transcription proprement, même en cas d'erreur ou de sortie anticipée
    if ($transcriptStarted) { Stop-Transcript | Out-Null }
}