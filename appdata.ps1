# Parámetros
$userAppData = "$env:USERPROFILE\AppData"
$folders = @("$userAppData\Local", "$userAppData\Roaming", "$userAppData\LocalLow")
$fileSizeLimitMB = 10 # Tamaño límite para considerar la carpeta como "pequeña" (en MB)
$excludedFolders = @("Packages") # Carpetas que deben ser ignoradas

# Obtener la lista de programas instalados del registro de Windows
$programsInstalled = Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*, HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*, HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* |
                     Select-Object DisplayName

# Función para verificar si un programa está instalado
function Is-ProgramInstalled {
    param (
        [string]$folderName
    )
    # Verificar si el nombre de la carpeta está presente en la lista de programas instalados
    $programInstalled = $programsInstalled | Where-Object { $_.DisplayName -like "*$folderName*" }
    return $programInstalled -ne $null
}

# Función para verificar si la carpeta contiene archivos .exe o archivos grandes
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

# Función para eliminar carpetas de programas desinstalados y que no contengan archivos .exe o grandes
function Remove-UninstalledAppDataFolders {
    param (
        [string]$folderPath,
        [int]$fileSizeLimitMB,
        [string[]]$excludedFolders
    )

    # Obtener todas las carpetas en el directorio
    Get-ChildItem -Path $folderPath -Directory | ForEach-Object {
        $folder = $_
        $folderName = $folder.Name

        # Verificar si la carpeta está en la lista de excluidas
        if ($excludedFolders -contains $folderName) {
            Write-Host "Carpeta excluida: $folderName (No se elimina)"
            return
        }

        # Verificar si el programa ya no está instalado
        if (-not (Is-ProgramInstalled -folderName $folderName)) {
            # Verificar si la carpeta contiene archivos .exe o archivos grandes
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

# Ejecutar la función en cada directorio de AppData
foreach ($folder in $folders) {
    Write-Host "Analizando: $folder"
    Remove-UninstalledAppDataFolders -folderPath $folder -fileSizeLimitMB $fileSizeLimitMB -excludedFolders $excludedFolders
}
