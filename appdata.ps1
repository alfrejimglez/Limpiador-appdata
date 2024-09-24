# Parámetros
$userAppData = "$env:USERPROFILE\AppData"
$folders = @("$userAppData\Local", "$userAppData\Roaming", "$userAppData\LocalLow")
$fileSizeLimitMB = 10 #tamnaño para q no borre cosas improtan
$excludedFolders = @("Packages") # aqui ignoradas , buscar como poner 2 omas

$programsInstalled = Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*, HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*, HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* |
                     Select-Object DisplayName

function Is-ProgramInstalled {
    param (
        [string]$folderName
    )
    $programInstalled = $programsInstalled | Where-Object { $_.DisplayName -like "*$folderName*" }
    return $programInstalled -ne $null
}

function ContainsExeOrLargeFiles {
    param (
        [string]$folderPath,
        [int]$fileSizeLimitMB
    )

    # Verificar si hay archivos .exe o archivos cuyo tamaño exceda el límite
    $containsExeOrLargeFiles = Get-ChildItem -Path $folderPath -Recurse | Where-Object {
        $_.Extension -eq ".exe" -or ($_.Length / 1MB) -gt $fileSizeLimitMB
    }

    return $containsExeOrLargeFiles.Count -gt 0
}

function Remove-UninstalledAppDataFolders {
    param (
        [string]$folderPath,
        [int]$fileSizeLimitMB,
        [string[]]$excludedFolders
    )

    # se tiene carpetas 
    Get-ChildItem -Path $folderPath -Directory | ForEach-Object {
        $folder = $_
        $folderName = $folder.Name

        if ($excludedFolders -contains $folderName) {
            Write-Host "Carpeta excluida: $folderName (No se elimina)"
            return
        }

        if (-not (Is-ProgramInstalled -folderName $folderName)) {
            if (-not (ContainsExeOrLargeFiles -folderPath $folder.FullName -fileSizeLimitMB $fileSizeLimitMB)) {
                Write-Host "Eliminando carpeta de programa desinstalado y sin archivos .exe ni grandes: $($folder.FullName)"
                Remove-Item -Recurse -Force $folder.FullName
            }
            else {
                Write-Host "Carpeta con archivos .exe o grandes: $folderName (No se elimina)"
            }
        }
        else {
            Write-Host "Carpeta de programa activo: $folderName (No se elimina)"
        }
    }
}

foreach ($folder in $folders) {
    Write-Host "Analizando: $folder"
    Remove-UninstalledAppDataFolders -folderPath $folder -fileSizeLimitMB $fileSizeLimitMB -excludedFolders $excludedFolders
}
