# Get the path to the custom-layouts.json file
$jsonPath = "$env:LocalAppData\Microsoft\PowerToys\FancyZones\custom-layouts.json"

# Read the existing contents of the file
$existingContent = Get-Content $jsonPath -Raw

# Convert the JSON string to a PowerShell object
$existingData = ConvertFrom-Json $existingContent

# Create the new layout data
$newLayout = @{
    uuid = "{C502B459-A5DA-45AF-85DB-24709F61A6DE}"
    name = "Azure"
    type = "grid"
    info = @{
        rows = 2
        columns = 2
        'rows-percentage' = @(6390, 3610)
        'columns-percentage' = @(6666, 3334)
        'cell-child-map' = @(@(0, 1), @(0, 2))
        'show-spacing' = $false
        spacing = 16
        'sensitivity-radius' = 20
    }
}

# Check if 'custom-layouts' exists and is an array, then add the new layout
if ($existingData.'custom-layouts' -is [System.Collections.IList]) {
    $existingData.'custom-layouts' += $newLayout
} else {
    $existingData.'custom-layouts' = @($newLayout)
}

# Convert the updated object back to a JSON string
$newContent = ConvertTo-Json $existingData -Depth 10

# Write the new content back to the file
Set-Content -Path $jsonPath -Value $newContent -Force
