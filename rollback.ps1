<#
.SYNOPSIS
    Restaure l'état d'origine de l'hôte Windows sauvegardé par activation.ps1.

.DESCRIPTION
    Lit le fichier d'état d'origine (original-state.json, écrit par activation.ps1 avant toute
    modification) et compare cet état à l'état actuel de la machine. Il ne restaure que les
    ÉLÉMENTS QUI DIFFÈRENT, après avoir affiché le plan et demandé confirmation.

    Contrairement à une "réactivation de la sécurité" générique, ce script ne force rien :
      - un réglage absent à l'origine est supprimé, pas mis à 1 ;
      - un réglage qui valait X à l'origine reprend la valeur X ;
      - Credential Guard n'est jamais réactivé avec verrou UEFI.

    Le script se déroule en deux temps :
      1. Exécution normale  -> applique le plan de restauration, puis propose un redémarrage.
      2. Exécution -Verify  -> APRÈS redémarrage, contrôle la conformité avec l'état d'origine.

.PARAMETER StatePath
    Chemin du fichier d'état à restaurer.
    Par défaut : %ProgramData%\nested-virt-enabling\original-state.json

.PARAMETER Verify
    Ne modifie rien. Compare l'état actuel à l'état d'origine (à lancer après le redémarrage).
    Si tout est conforme, le fichier d'état d'origine est archivé.

.PARAMETER Force
    Ne demande pas de confirmation et accepte un fichier d'état issu d'une autre machine.

.PARAMETER SkipReboot
    Ne propose pas de redémarrage à la fin.

.PARAMETER NoTranscript
    Ne crée pas de fichier journal.

.EXAMPLE
    .\rollback.ps1 -WhatIf
    Affiche ce qui serait restauré, sans rien modifier.

.EXAMPLE
    .\rollback.ps1
    Restauration avec plan affiché et confirmation.

.EXAMPLE
    .\rollback.ps1 -Verify
    À lancer après le redémarrage pour valider la restauration.

.NOTES
    Codes de sortie : 0 = OK, 1 = erreur, 2 = annulé par l'utilisateur,
                      3 = (-Verify) l'état actuel diffère encore de l'état d'origine.
#>

#Requires -Version 5.1
#Requires -RunAsAdministrator

# [CmdletBinding(SupportsShouldProcess)] ajoute automatiquement les options -WhatIf et -Confirm
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    # Fichier d'état à restaurer (par défaut : l'état d'origine écrit par activation.ps1)
    [string]$StatePath = (Join-Path $env:ProgramData 'nested-virt-enabling\original-state.json'),
    [switch]$Verify,        # Mode contrôle seul, aucune modification
    [switch]$Force,         # Saute la confirmation et accepte un état d'une autre machine
    [switch]$SkipReboot,    # Ne propose pas de redémarrage
    [switch]$NoTranscript   # Pas de fichier journal
)

# Toute erreur non gérée arrête le script (les blocs try/catch décident ensuite quoi faire)
$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------------------
# Fonctions d'affichage (mêmes conventions que activation.ps1)
# ---------------------------------------------------------------------------
function Write-Step { param([string]$Message) Write-Host "`n=== $Message ===" -ForegroundColor Cyan }      # Titre d'étape
function Write-Ok   { param([string]$Message) Write-Host "[OK] $Message"   -ForegroundColor Green }       # Action réussie
function Write-Info { param([string]$Message) Write-Host "[INFO] $Message" -ForegroundColor Gray }        # Information neutre
function Write-Warn { param([string]$Message) Write-Host "[ATTENTION] $Message" -ForegroundColor Yellow } # Point de vigilance

# ---------------------------------------------------------------------------
# Emplacements des fichiers
# ---------------------------------------------------------------------------
$WorkDir           = Join-Path $env:ProgramData 'nested-virt-enabling'                # Dossier de travail commun aux deux scripts
$OriginalStatePath = Join-Path $WorkDir 'original-state.json'                         # Fichier d'état d'origine (référence)
$LogPath           = Join-Path $WorkDir 'nested-virt-enabling-rollback.log'           # Journal de ce script

# ---------------------------------------------------------------------------
# Fonctions utilitaires
# ---------------------------------------------------------------------------

# Exécute bcdedit et renvoie son code de sortie + sa sortie texte.
# try/catch ne capte pas l'échec d'un programme externe : il faut lire $LASTEXITCODE.
function Invoke-Bcdedit {
    param([string[]]$Arguments)
    $previous = $ErrorActionPreference          # Mémorise le comportement d'erreur actuel
    $ErrorActionPreference = 'Continue'         # Évite qu'un message d'erreur de bcdedit (stderr) arrête le script
    try {
        $output = & bcdedit.exe @Arguments 2>&1 | ForEach-Object { $_.ToString() }    # Lance bcdedit, fusionne stderr dans la sortie
        $code = $LASTEXITCODE                                                         # Code de retour réel du programme
    }
    finally {
        $ErrorActionPreference = $previous      # Restaure le comportement d'erreur d'origine
    }
    return [pscustomobject]@{ ExitCode = $code; Output = ($output -join "`n") }
}

# Lit la valeur actuelle de hypervisorlaunchtype dans l'entrée de démarrage courante
function Get-BcdHypervisorLaunchType {
    $result = Invoke-Bcdedit -Arguments @('/enum', '{current}')     # '{current}' entre quotes : sinon PowerShell l'interprète mal
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

# Lit une valeur de registre et indique si la clé et la valeur existent
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

# Compare l'état sauvegardé à l'état actuel et renvoie la liste des actions de restauration à effectuer.
# Ne modifie RIEN : elle ne fait que construire le plan.
function New-RestorePlan {
    param(
        $State,                        # Contenu du fichier JSON d'état d'origine
        [hashtable]$CurrentFeatures    # Fonctionnalités Windows actuelles : nom -> état
    )
    $actions = New-Object System.Collections.Generic.List[object]    # Liste des actions à effectuer

    # --- Registre : on restaure dans les deux sens (valeur d'origine, ou suppression si absente à l'origine) ---
    foreach ($r in @($State.Registry)) {
        $current = Get-RegSnapshot -Path $r.Path -Name $r.Name                 # État actuel de la valeur
        if ($r.ValueExisted) {
            # La valeur existait à l'origine : on la remet si elle est absente ou différente
            if (-not ($current.ValueExisted -and $current.Value -eq $r.Value)) {
                $now = if ($current.ValueExisted) { $current.Value } else { 'absente' }
                $actions.Add([pscustomobject]@{
                    Type = 'Registry'; Action = 'Set'; Path = $r.Path; Name = $r.Name; Value = [int]$r.Value; KeyExisted = $r.KeyExisted
                    Label = "Registre : $($r.Path)\$($r.Name) -> $($r.Value) (actuellement : $now)"
                })
            }
        }
        elseif ($current.ValueExisted) {
            # La valeur n'existait pas à l'origine mais existe maintenant : on la supprime
            $actions.Add([pscustomobject]@{
                Type = 'Registry'; Action = 'Remove'; Path = $r.Path; Name = $r.Name; Value = $null; KeyExisted = $r.KeyExisted
                Label = "Registre : suppression de $($r.Path)\$($r.Name) (actuellement : $($current.Value), absente à l'origine)"
            })
        }
    }

    # --- Démarrage (BCD) : hypervisorlaunchtype ---
    $bcdOriginal = [string]$State.HypervisorLaunchType                          # Valeur sauvegardée (texte)
    $bcdCurrent  = Get-BcdHypervisorLaunchType                                  # Valeur actuelle
    if ($bcdOriginal -match '(?i)hypervisorlaunchtype\s+(off|auto)\b') {
        $wanted = $Matches[1].ToLower()                                         # 'off' ou 'auto' (capturé avant le prochain -match)
        if ($bcdCurrent -notmatch "(?i)hypervisorlaunchtype\s+$wanted\b") {
            $actions.Add([pscustomobject]@{
                Type = 'BCD'; Action = 'Set'; Value = $wanted
                Label = "Démarrage : hypervisorlaunchtype -> $wanted (actuellement : $bcdCurrent)"
            })
        }
    }
    elseif ($bcdOriginal -eq '(non défini)') {
        # À l'origine la valeur n'était pas définie : on la supprime pour retrouver le comportement par défaut
        if ($bcdCurrent -ne '(non défini)' -and $bcdCurrent -ne '(indéterminé)') {
            $actions.Add([pscustomobject]@{
                Type = 'BCD'; Action = 'Delete'; Value = $null
                Label = "Démarrage : suppression de hypervisorlaunchtype (actuellement : $bcdCurrent)"
            })
        }
    }
    else { Write-Info "Démarrage : valeur d'origine ($bcdOriginal) non restaurable automatiquement, ignorée." }

    # --- Fonctionnalités Windows : réactivées seulement si elles étaient activées à l'origine ---
    foreach ($f in @($State.Features)) {
        $now = if ($CurrentFeatures.ContainsKey($f.Name)) { $CurrentFeatures[$f.Name] } else { 'NotPresent' }   # État actuel
        if ($f.State -in @('Enabled', 'EnablePending')) {
            if ($now -eq 'NotPresent') { Write-Info "Fonctionnalité $($f.Name) : absente de ce système, ignorée." }
            elseif ($now -notin @('Enabled', 'EnablePending')) {
                $actions.Add([pscustomobject]@{
                    Type = 'Feature'; Action = 'Enable'; Name = $f.Name
                    Label = "Fonctionnalité Windows : réactivation de $($f.Name) (actuellement : $now)"
                })
            }
        }
        elseif ($f.State -ne 'NotPresent' -and $now -in @('Enabled', 'EnablePending')) {
            # Activée depuis la sauvegarde (ex. WSL2, Docker) : on ne la désactive JAMAIS pour ne rien casser
            Write-Info "Fonctionnalité $($f.Name) : activée depuis la sauvegarde, conservée telle quelle."
        }
    }

    # --- Services : on restaure uniquement le type de démarrage (le démarrage se fera au redémarrage) ---
    foreach ($s in @($State.Services)) {
        if (-not $s.Present) { continue }                                       # Service absent à l'origine : rien à faire
        $svc = Get-Service -Name $s.Name -ErrorAction SilentlyContinue          # Le service existe-t-il maintenant ?
        if (-not $svc) { Write-Info "Service $($s.Name) : absent de ce système, ignoré."; continue }
        if ($s.StartType -notin @('Automatic', 'Manual', 'Disabled')) {
            Write-Info "Service $($s.Name) : type de démarrage d'origine '$($s.StartType)' non restaurable automatiquement, ignoré."; continue
        }
        if ("$($svc.StartType)" -ne $s.StartType) {
            $actions.Add([pscustomobject]@{
                Type = 'Service'; Action = 'SetStartType'; Name = $s.Name; Value = $s.StartType
                Label = "Service : $($s.Name) -> démarrage $($s.StartType) (actuellement : $($svc.StartType))"
            })
        }
    }

    return $actions.ToArray()
}

# ---------------------------------------------------------------------------
# Programme principal
# ---------------------------------------------------------------------------
$transcriptStarted = $false   # Sert à n'arrêter la transcription que si elle a démarré
$restartNeeded     = $false   # Passe à $true dès qu'une modification exige un redémarrage
$applied           = 0        # Nombre d'actions appliquées
$failures          = 0        # Nombre d'échecs rencontrés

try {
    # Journal : créé sauf demande contraire ; ignoré en simulation (-WhatIf) pour ne rien écrire sur le disque
    if (-not $NoTranscript -and -not $WhatIfPreference) {
        if (-not (Test-Path -LiteralPath $WorkDir)) { New-Item -ItemType Directory -Path $WorkDir -Force | Out-Null }   # Crée le dossier de travail
        Start-Transcript -Path $LogPath -Append | Out-Null                                                             # Démarre l'enregistrement
        $transcriptStarted = $true
    }

    Write-Host 'Restauration de l''état d''origine de l''hôte Windows' -ForegroundColor Cyan

    # =======================================================================
    # ÉTAPE 1 : Chargement et validation du fichier d'état
    # =======================================================================
    Write-Step '1. Chargement de l''état d''origine'
    if (-not (Test-Path -LiteralPath $StatePath)) {
        Write-Warn "Fichier d'état introuvable : $StatePath"
        Write-Info 'Il est créé par activation.ps1. Sans lui, aucune restauration fiable n''est possible (relancez avec -StatePath <fichier> si besoin).'
        exit 1
    }
    try { $state = Get-Content -LiteralPath $StatePath -Raw -Encoding UTF8 | ConvertFrom-Json }     # Lit le JSON
    catch { Write-Warn "Fichier d'état illisible : $($_.Exception.Message)"; exit 1 }
    if ($state.SchemaVersion -ne 1) { Write-Warn "Version de format non prise en charge : $($state.SchemaVersion)"; exit 1 }   # Format inconnu
    Write-Info "Fichier : $StatePath"
    Write-Info "Créé le : $($state.CreatedAt) sur $($state.ComputerName) ($($state.OSCaption), build $($state.OSBuild))"

    # Refuse de restaurer l'état d'une AUTRE machine (sauf -Force) : les valeurs pourraient être inadaptées
    if ($state.ComputerName -ne $env:COMPUTERNAME -and -not $Force) {
        Write-Warn "Cet état provient d'une autre machine ($($state.ComputerName)). Utilisez -Force pour l'appliquer quand même."
        exit 1
    }
    # Une mise à jour majeure de Windows depuis la sauvegarde peut avoir modifié ces réglages : simple avertissement
    $osNow = Get-CimInstance -ClassName Win32_OperatingSystem                        # Informations sur Windows actuel
    if ("$($osNow.BuildNumber)" -ne "$($state.OSBuild)") {
        Write-Warn "Le build Windows a changé depuis la sauvegarde ($($state.OSBuild) -> $($osNow.BuildNumber)) : vérifiez le résultat après restauration."
    }

    # =======================================================================
    # ÉTAPE 2 : Comparaison avec l'état actuel (construction du plan)
    # =======================================================================
    Write-Step '2. Comparaison avec l''état actuel'
    # Table des fonctionnalités Windows actuelles (lue une seule fois : indépendant de la langue du système)
    $currentFeatures = @{}
    try { foreach ($f in (Get-WindowsOptionalFeature -Online)) { $currentFeatures[$f.FeatureName] = [string]$f.State } }
    catch { Write-Warn "Lecture des fonctionnalités Windows impossible : $($_.Exception.Message)" }

    $plan = @(New-RestorePlan -State $state -CurrentFeatures $currentFeatures)       # Liste des différences à corriger
    $vbsNow = Get-VbsState                                                           # État VBS actuel

    # =======================================================================
    # MODE -Verify : contrôle seul, à lancer après redémarrage
    # =======================================================================
    if ($Verify) {
        Write-Step 'Contrôle de conformité (après redémarrage)'
        Show-VbsState -State $vbsNow                                                 # Affiche l'état VBS actuel
        $deviations = $plan.Count                                                    # Chaque action restante = un écart
        foreach ($a in $plan) { Write-Warn "Écart : $($a.Label)" }                   # Détaille chaque écart
        # VBS : comparaison avec l'état d'origine (peut différer à cause d'un verrou UEFI, d'une GPO ou d'un outil externe)
        if ($vbsNow.Available -and $null -ne $state.VbsStatusBefore -and $vbsNow.Status -ne [int]$state.VbsStatusBefore) {
            Write-Warn "VBS : statut actuel $($vbsNow.Status), statut d'origine $($state.VbsStatusBefore)."
            $deviations++
        }
        if ($deviations -eq 0) {
            Write-Ok 'L''état actuel est conforme à l''état d''origine.'
            # Archive le fichier d'origine pour que la prochaine exécution d'activation.ps1 en crée un nouveau
            if ((Resolve-Path -LiteralPath $StatePath).Path -eq $OriginalStatePath) {
                $archive = Join-Path $WorkDir ("original-state.restored-{0:yyyyMMdd-HHmmss}.json" -f (Get-Date))
                if ($PSCmdlet.ShouldProcess($StatePath, "Archiver vers $archive")) {
                    Move-Item -LiteralPath $StatePath -Destination $archive               # Renomme (ne supprime rien)
                    Write-Ok "État d'origine archivé : $archive"
                }
            }
            exit 0
        }
        Write-Warn "$deviations écart(s) avec l'état d'origine."
        Write-Info 'Si un outil externe a été utilisé (ex. DG_Readiness_Tool -Disable), sa restauration se fait avec cet outil (voir README).'
        exit 3
    }

    # =======================================================================
    # ÉTAPE 3 : Affichage du plan
    # =======================================================================
    Write-Step '3. Plan de restauration'
    if ($plan.Count -eq 0) {
        Write-Ok 'Rien à restaurer : l''état actuel correspond déjà à l''état d''origine.'
        exit 0
    }
    foreach ($a in $plan) { Write-Host "  - $($a.Label)" -ForegroundColor White }      # Une ligne par action prévue
    Write-Info "$($plan.Count) action(s) prévue(s)."
    if (Test-BitLockerProtection) {
        Write-Warn 'BitLocker protège le disque système : sauvegardez votre clé de récupération avant de continuer (manage-bde -protectors -get C:).'
    }

    # =======================================================================
    # ÉTAPE 4 : Confirmation explicite
    # =======================================================================
    if (-not $Force -and -not $WhatIfPreference) {
        $answer = Read-Host 'Tapez OUI pour appliquer ce plan'                        # Demande de confirmation
        if ($answer -notmatch '^(oui|o|yes|y)$') { Write-Info 'Opération annulée.'; exit 2 }
    }

    # =======================================================================
    # ÉTAPE 5 : Application du plan (registre -> démarrage -> fonctionnalités -> services)
    # =======================================================================
    Write-Step '4. Application du plan'
    foreach ($type in @('Registry', 'BCD', 'Feature', 'Service')) {
        foreach ($a in @($plan | Where-Object { $_.Type -eq $type })) {
            if (-not $PSCmdlet.ShouldProcess($a.Label, 'Restaurer')) { continue }     # Respecte -WhatIf
            try {
                switch ($a.Type) {
                    'Registry' {
                        if ($a.Action -eq 'Set') {
                            if (-not (Test-Path -LiteralPath $a.Path)) { New-Item -Path $a.Path -Force | Out-Null }   # Recrée la clé si besoin
                            New-ItemProperty -LiteralPath $a.Path -Name $a.Name -Value $a.Value -PropertyType DWord -Force | Out-Null   # Remet la valeur d'origine
                        }
                        else {
                            Remove-ItemProperty -LiteralPath $a.Path -Name $a.Name -Force        # Supprime la valeur ajoutée après la sauvegarde
                            # Supprime aussi la clé si elle n'existait pas à l'origine ET si elle est maintenant totalement vide
                            if (-not $a.KeyExisted -and (Test-Path -LiteralPath $a.Path)) {
                                $key = Get-Item -LiteralPath $a.Path
                                if ($key.ValueCount -eq 0 -and $key.SubKeyCount -eq 0) { Remove-Item -LiteralPath $a.Path -Force }
                            }
                        }
                    }
                    'BCD' {
                        # Set -> bcdedit /set hypervisorlaunchtype <valeur> ; Delete -> bcdedit /deletevalue hypervisorlaunchtype
                        $bcdArgs = if ($a.Action -eq 'Set') { @('/set', 'hypervisorlaunchtype', $a.Value) } else { @('/deletevalue', 'hypervisorlaunchtype') }
                        $r = Invoke-Bcdedit -Arguments $bcdArgs
                        if ($r.ExitCode -ne 0) { throw "bcdedit a échoué (code $($r.ExitCode)) : $($r.Output)" }   # Échec = code de retour non nul
                    }
                    'Feature' {
                        # -All active aussi les fonctionnalités parentes/enfants nécessaires (ex. sous-composants de Hyper-V)
                        Enable-WindowsOptionalFeature -Online -FeatureName $a.Name -All -NoRestart -ErrorAction Stop | Out-Null
                    }
                    'Service' {
                        Set-Service -Name $a.Name -StartupType $a.Value -ErrorAction Stop      # Restaure le type de démarrage d'origine
                    }
                }
                Write-Ok $a.Label                                                            # Action réussie
                $applied++; $restartNeeded = $true
            }
            catch { Write-Warn "Échec : $($a.Label) -> $($_.Exception.Message)"; $failures++ }
        }
    }

    # =======================================================================
    # ÉTAPE 6 : Bilan
    # =======================================================================
    Write-Step '5. Bilan'
    Write-Info "Actions appliquées : $applied | Échecs : $failures"
    Write-Warn 'La restauration n''est effective qu''APRÈS redémarrage. Ensuite, relancez : .\rollback.ps1 -Verify'
    Write-Info 'Ce script ne restaure pas les réglages UEFI/firmware modifiés par un outil externe (ex. DG_Readiness_Tool -Disable).'

    # Redémarrage proposé avec délai
    if ($restartNeeded -and -not $SkipReboot -and -not $WhatIfPreference) {
        $answer = Read-Host 'Un redémarrage est nécessaire. Redémarrer dans 60 secondes ? [O/N]'
        if ($answer -match '^(o|oui|y|yes)$') {
            & shutdown.exe /r /t 60 /c 'Redémarrage : restauration de l''état d''origine'    # Délai de 60 s pour enregistrer son travail
            Write-Info 'Redémarrage programmé. Pour annuler : shutdown /a'
        }
        else { Write-Info 'Pensez à redémarrer manuellement pour terminer la restauration.' }
    }
    if ($transcriptStarted) { Write-Host "`nJournal : $LogPath" -ForegroundColor Gray }

    if ($failures -gt 0) { exit 1 }   # Code de sortie non nul si au moins une action a échoué
    exit 0
}
finally {
    # Arrête la transcription proprement, même en cas d'erreur ou de sortie anticipée
    if ($transcriptStarted) { Stop-Transcript | Out-Null }
}