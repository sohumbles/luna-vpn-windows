[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$PackageName,
    [Parameter(Mandatory=$true)][string]$Publisher,
    [Parameter(Mandatory=$true)][string]$PublisherDisplayName,
    [string]$MakeAppxPath
)

$ErrorActionPreference='Stop'
$KitRoot=$PSScriptRoot
$PayloadRoot=Join-Path $KitRoot 'Payload'
$Template=Join-Path $KitRoot 'AppxManifest.template.xml'
$Assets=Join-Path $KitRoot 'Assets'
$BuildRoot=Join-Path $KitRoot 'Build'
$OutputRoot=Join-Path $KitRoot 'Output'

if($PackageName -match '^PASTE_' -or $Publisher -match '^PASTE_'){
    throw 'Вставьте точные Package identity name и Publisher из Partner Center.'
}

if(-not $MakeAppxPath){
    $candidates=@()
    $sdkRoot="${env:ProgramFiles(x86)}\Windows Kits\10\bin"
    if(Test-Path $sdkRoot){$candidates+=Get-ChildItem $sdkRoot -Recurse -Filter MakeAppx.exe -ErrorAction SilentlyContinue|Where-Object {$_.FullName -match '\\x64\\'}|Sort-Object FullName -Descending|Select-Object -ExpandProperty FullName}
    $localTool=Join-Path $KitRoot 'Tools\MakeAppx.exe'
    if(Test-Path $localTool){$candidates=$localTool+$candidates}
    $MakeAppxPath=$candidates|Select-Object -First 1
}
if(-not $MakeAppxPath -or -not (Test-Path $MakeAppxPath)){
    throw 'MakeAppx.exe не найден. Установите Windows SDK Build Tools или передайте -MakeAppxPath.'
}

foreach($path in @($BuildRoot,$OutputRoot)){
    if(Test-Path $path){Remove-Item -LiteralPath $path -Recurse -Force}
    New-Item -ItemType Directory -Path $path|Out-Null
}

$manifestTemplate=[IO.File]::ReadAllText($Template,[Text.Encoding]::UTF8)
$packages=@()
foreach($architecture in @('x64','x86')){
    $payload=Join-Path $PayloadRoot $architecture
    if(-not (Test-Path (Join-Path $payload 'Luna.exe'))){throw "Отсутствует Payload\$architecture\Luna.exe"}
    $staging=Join-Path $BuildRoot $architecture
    New-Item -ItemType Directory -Path $staging|Out-Null
    Copy-Item (Join-Path $payload '*') $staging -Recurse -Force
    Copy-Item $Assets (Join-Path $staging 'Assets') -Recurse -Force
    $manifest=$manifestTemplate.Replace('__PACKAGE_NAME__',$PackageName).Replace('__PUBLISHER__',$Publisher).Replace('__PUBLISHER_DISPLAY_NAME__',$PublisherDisplayName).Replace('__ARCHITECTURE__',$architecture)
    [IO.File]::WriteAllText((Join-Path $staging 'AppxManifest.xml'),$manifest,(New-Object Text.UTF8Encoding($false)))
    $package=Join-Path $OutputRoot "Luna_1.4.0.0_$architecture.msix"
    & $MakeAppxPath pack /d $staging /p $package /o
    if($LASTEXITCODE -ne 0){throw "MakeAppx pack завершился с кодом $LASTEXITCODE"}
    $packages+=$package
}

$bundleInput=Join-Path $BuildRoot 'BundleInput'
New-Item -ItemType Directory -Path $bundleInput|Out-Null
foreach($package in $packages){Copy-Item $package $bundleInput}
$bundle=Join-Path $OutputRoot 'Luna_1.4.0.0.msixbundle'
& $MakeAppxPath bundle /d $bundleInput /p $bundle /o
if($LASTEXITCODE -ne 0){throw "MakeAppx bundle завершился с кодом $LASTEXITCODE"}

$hashes=Get-FileHash ($packages+$bundle) -Algorithm SHA256
$hashLines=$hashes|ForEach-Object {"$($_.Hash)  $(Split-Path $_.Path -Leaf)"}
[IO.File]::WriteAllLines((Join-Path $OutputRoot 'SHA256SUMS.txt'),$hashLines,[Text.UTF8Encoding]::new($false))

Write-Host "Готово: $bundle"
Write-Host 'Перед отправкой убедитесь, что PackageName и Publisher полностью совпадают с Partner Center.'
