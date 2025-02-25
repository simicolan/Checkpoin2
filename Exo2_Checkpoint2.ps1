# Fonction pour gérer les accents et les majuscules
Function ManageAccentsAndCapitalLetters {
    param ([String]$String)
    
    $StringWithoutAccent = $String -replace '[éèêë]', 'e' -replace '[àâä]', 'a' -replace '[îï]', 'i' -replace '[ôö]', 'o' -replace '[ùûü]', 'u' `
 	-replace '[ÉÈÊË]', 'E' -replace '[ÀÂÄ]', 'A' -replace '[ÎÏ]', 'I' -replace '[ÔÖ]', 'O' -replace '[ÙÛÜ]', 'U'

    $StringWithoutAccentAndCapitalLetters = $StringWithoutAccent.ToLower()
    return $StringWithoutAccentAndCapitalLetters
}

# Fonction pour générer un mot de passe aléatoire avec des exigences de complexité
Function Random-Password ($length = 8) {
    $upperCase = 65..90
    $lowerCase = 97..122
    $digits = 48..57
    $special = 33..47 + 58..64 + 91..96 + 123..126

    $allChars = $upperCase + $lowerCase + $digits + $special

    # Générez un mot de passe qui respecte les critères de complexité
    $passwordArray = Get-Random -Count $length -InputObject $allChars
    
    # Joindre les caractères générés pour obtenir le mot de passe
    $password = -join ($passwordArray | ForEach-Object { [char]$_ })

    return $password
}

# Fonction pour enregistrer dans un fichier journal
Function Log {
    param([string]$FilePath,[string]$Content)

    If (-not (Test-Path -Path $FilePath)) {
        New-Item -ItemType File -Path $FilePath | Out-Null
    }

    $Date = Get-Date -Format "dd/MM/yyyy-HH:mm:ss"
    $User = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
    $logLine = "$Date;$User;$Content"
    Add-Content -Path $FilePath -Value $logLine
}

# Définir les chemins
$Path = "C:\Scripts"
$CsvFile = "$Path\Users.csv"
$LogFile = "$Path\Log.log"

# Importer le CSV
$Users = Import-Csv -Path $CsvFile -Delimiter ";" -Header "prenom","nom","societe","fonction","service","description","mail","mobile","scriptPath","telephoneNumber" -Encoding UTF8

# Vérifier si le groupe "Utilisateur" existe, sinon le créer
$groupName = "Utilisateur"
if (-not (Get-LocalGroup -Name $groupName -ErrorAction SilentlyContinue)) {
    New-LocalGroup -Name $groupName -Description "Groupe d'utilisateurs standard"
    Write-Host "Groupe $groupName créé."
} else {
    Write-Host "Le groupe $groupName existe déjà."
}

# Parcourir chaque utilisateur
foreach ($User in $Users) {
    $Prenom = ManageAccentsAndCapitalLetters -String $User.prenom
    $Nom = ManageAccentsAndCapitalLetters -String $User.nom
    $Name = "$Prenom.$Nom"
    
    # Vérifier si l'utilisateur existe déjà
    If (-not (Get-LocalUser -Name $Name -ErrorAction SilentlyContinue)) {
        $Pass = Random-Password
        
        # Vérifier si le mot de passe généré est valide avant la conversion
        if ($Pass) {
            $Password = ConvertTo-SecureString $Pass -AsPlainText -Force
        } else {
            Write-Host "Le mot de passe généré est invalide, une nouvelle tentative est nécessaire."
            Log -FilePath $LogFile -Content "Échec de la génération du mot de passe pour l'utilisateur $Name."
            continue
        }

        $Description = "$($User.description) - $($User.fonction)"

        # Créer l'utilisateur
        $UserInfo = @{
            Name                 = $Name
            FullName             = "$Prenom $Nom"
            Password             = $Password
            AccountNeverExpires  = $true
            PasswordNeverExpires = $false
        }

        Try {
            New-LocalUser @UserInfo
            Add-LocalGroupMember -Group $groupName -Member $Name
            Write-Host "L'utilisateur $Name a été créé."
            Log -FilePath $LogFile -Content "Utilisateur $Name créé avec succès."
        }
        Catch {
            Write-Host "Erreur lors de la création de l'utilisateur $Name."
            Log -FilePath $LogFile -Content "Erreur lors de la création de l'utilisateur $Name."
        }
    }
    Else {
        Write-Host "L'utilisateur $Name existe déjà."
        Log -FilePath $LogFile -Content "L'utilisateur $Name existe déjà."
    }
}
