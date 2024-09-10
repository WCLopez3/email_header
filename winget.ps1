# Install Microsoft PowerToys using winget
winget install --id Microsoft.PowerToys -e

# Set Microsoft Edge as the default web browser
$edgeProgId = "MSEdgeHTM"

# This will change the default browser for HTTP, HTTPS, and HTML protocols
New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\Shell\Associations\UrlAssociations\http\UserChoice" -Name "ProgId" -Value $edgeProgId -Force
New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\Shell\Associations\UrlAssociations\https\UserChoice" -Name "ProgId" -Value $edgeProgId -Force
New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\Shell\Associations\UrlAssociations\html\UserChoice" -Name "ProgId" -Value $edgeProgId -Force

# Set Microsoft Edge as the default app for .pdf files
$pdfProgId = "MSEdgePDF"
New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.pdf\UserChoice" -Name "ProgId" -Value $pdfProgId -Force
