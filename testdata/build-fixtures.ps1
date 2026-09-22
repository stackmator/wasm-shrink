# Rebuilds the .NET WASM test fixtures used by wasm-trim integration tests.
# Requires: .NET 10 SDK + `dotnet workload install wasm-tools`
param(
    [switch]$AotOnly,
    [switch]$MonoOnly
)
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot

if (-not $MonoOnly) {
    Write-Host "==> Publishing NativeAOT fixture (RunAOTCompilation)..." -ForegroundColor Cyan
    dotnet publish "$root\testdata\dotnet-aot\DotnetTest.csproj" -c Release -o "$root\testdata\dotnet-aot\publish"
    if ($LASTEXITCODE -ne 0) { throw "AOT publish failed" }
}

if (-not $AotOnly) {
    Write-Host "==> Publishing Mono/Blazor fixture..." -ForegroundColor Cyan
    dotnet publish "$root\testdata\dotnet-blazor\DotnetTest.csproj" -c Release -o "$root\testdata\dotnet-blazor\publish"
    if ($LASTEXITCODE -ne 0) { throw "Mono publish failed" }
}

$fixtures = "$root\testdata\fixtures"
New-Item -ItemType Directory -Force -Path $fixtures | Out-Null

if (-not $AotOnly) {
    $mono = Get-ChildItem "$root\testdata\dotnet-blazor\publish\wwwroot\_framework\dotnet.native.*.wasm" | Select-Object -First 1
    Copy-Item $mono.FullName "$fixtures\dotnet.native.wasm" -Force
    $app = Get-ChildItem "$root\testdata\dotnet-blazor\publish\wwwroot\_framework\DotnetTest.*.wasm" | Select-Object -First 1
    Copy-Item $app.FullName "$fixtures\dotnet.app.mono.wasm" -Force
}

if (-not $MonoOnly) {
    $aot = Get-ChildItem "$root\testdata\dotnet-aot\publish\wwwroot\_framework\dotnet.native*.wasm" |
        Where-Object { $_.Name -notmatch 'symbols' } | Select-Object -First 1
    Copy-Item $aot.FullName "$fixtures\dotnet.native.aot.wasm" -Force
}

Write-Host "==> Fixtures:" -ForegroundColor Green
Get-ChildItem $fixtures\*.wasm | ForEach-Object {
    Write-Host ("    {0,-24} {1,8:N2} MB" -f $_.Name, ($_.Length / 1MB))
}
