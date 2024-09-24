# Parámetros
$userAppData = "C:\Users\alfre\AppData"
$folders = @("$userAppData\Local", "$userAppData\Roaming", "$userAppData\LocalLow")

# Obtener la lista de programas instalados del registro de Windows (en HKLM y HKCU)
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

# Función para eliminar carpetas de programas desinstalados
function Remove-UninstalledAppDataFolders {
    param (
        [string]$folderPath
    )

    # Obtener todas las carpetas en el directorio
    Get-ChildItem -Path $folderPath -Directory | ForEach-Object {
        $folder = $_
        $folderName = $folder.Name

        # Verificar si el programa ya no está instalado
        if (-not (Is-ProgramInstalled -folderName $folderName)) {
            Write-Host "Eliminando carpeta de programa desinstalado: $($folder.FullName)"
            Remove-Item -Recurse -Force $folder.FullName
        }
        else {
            Write-Host "Carpeta de programa activo: $folderName (No se elimina)"
        }
    }
}

# Ejecutar la función en cada directorio de AppData
foreach ($folder in $folders) {
    Write-Host "Analizando: $folder"
    Remove-UninstalledAppDataFolders -folderPath $folder
}
