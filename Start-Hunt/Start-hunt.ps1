# search for all files that have a .ZIP or .RAR extension in the C:\Documents\exercise_8 directory
    #TODO: split total by extension
Set-Location $env:UserProfile\Desktop
$MyPath = Get-Location 
$workingPath = "$env:UserProfile\Documents\exercise_8"
$AllFiles = Get-ChildItem $workingPath\* -Recurse
$extensions = ".zip", ".rar"

$WorkingFiles = @()
$HexFiles = @()
$streamHashes = @()

foreach ($extension in $extensions) {
    $WorkingFiles += get-childitem "$workingPath\*$extension" -Recurse 
}
Write-host "Number of Zip and Rar files Found:"
$WorkingFiles.count

# identify which files within the IdentifyDataExfil_ADS directory have an ADS.

$streams = Get-Item -Path ($allfiles).FullName -Stream * | Where-Object {$_.stream -ne ':$Data'}

Write-host "These are the files with ADS:"
$streams | Select-Object @{n="FileName";e={$_.filename | Split-Path -Leaf}}, Stream | Out-Host

#  last 4 digits of the SHA1 for each file
foreach ($file in $streams){$streamHashes += Get-FileHash -Algorithm SHA1 $file.filename}

Write-host "Here are the Last 4 of the File hashes"
$streamHashes | Select-Object @{n="SHA1-Last4";e={($_.hash).substring(36)}}, @{n="Name";e={$_.path | split-path -leaf}}

# ADS File Extraction and determin the file signature

if ((Test-Path "$MyPath\Exports") -eq $false){
    New-Item -ItemType Directory -Path $MyPath -name Exports
}

foreach ($stream in $streams){
    $name = ($stream.name).tostring() | split-path -leaf
    $file = Get-Content -Path $stream.fileName -Stream $stream.Stream -encoding byte -ReadCount 0
    Set-Content "$MyPath\Exports\$name" -Encoding byte -Value $file
}

# View the first line of hex 
$knownADS = @()

foreach ($file in (Get-ChildItem "$myPath\exports")){
    $item = Format-hex $file.FullName | Select-Object -First 1
    $checker = [PSCustomObject]@{
        FileName = ($item.Path | Split-Path -Leaf)
        Signature = ($item | Select-Object -ExcludeProperty bytes | Select-Object -First 2)
        content = (Get-Content $file.FullName)
    }
    $knownADS =+ $checker
}
$knownADS | Out-Host



# Find File MisMatch
[byte[]]$rarHeader = [system.convert]::ToString(0x52,10),[system.convert]::ToString(0x61,10)
[byte[]]$ZipHeader =  [system.convert]::ToString(0x50,10), [system.convert]::ToString(0xb4,10)

$magicbytes = @()

foreach ($file in $AllFiles){$HexFiles += Format-hex $file}

foreach($item in $HexFiles){
    $checker = [PSCustomObject]@{
        FileName = ($item.path | split-path -Leaf)
        Signature = ($file | Select-Object -ExpandProperty bytes | Select-Object -First 2)
    }
    $magicbytes =+ $checker
}

$sigMisMatch = @()
Foreach ($item in $magicbytes){
    $match = "rar", "zip" -match ($item.filename).split(".")[1]
    if (($item.Signature[0] -match $rarHeader[0]) -and ($item.Signature[1] -match $rarHeader[1]) -and $match.Length -eq 0){
        write-host "File $($item.FileName) matches the RAR Signature"
    $sigMisMatch += $item}
    elseif (($item.Signature[0] -match $ZipHeader[2]) -and ($item.Signature[1] -match $ZipHeader[1])-and $match.Length -eq 0){
        write-host "File $($item.FileName) matches the Zip Signature"
    $sigMisMatch += $item}
}

$sigMisMatch.count

# [system.convert]::ToString($decimal[0],16)
# [system.convert]::ToString(0xb4,10)
