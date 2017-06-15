$ErrorActionPreference = "Stop"

Write-Host "Starting the build script..."
Write-Host "Cleaning up the Artifacts folder..."

$solutionDir = $env:APPVEYOR_BUILD_FOLDER

if (!$solutionDir) { $solutionDir = $pwd }

$artifactsDir = "$solutionDir\artifacts"

if (Test-Path $artifactsDir) { Remove-Item $artifactsDir -Force -Recurse }

Write-Host "Restoring NuGet packages..."

MSBuild /t:restore /verbosity:minimal

Write-Host "Setting the current version number based on the " -NoNewline

$propsFile = Get-Item "version.props"
$props = [xml](Get-Content $propsFile)
$propsVersion = $props.SelectSingleNode("//PropertyGroup/Version").InnerText

if ($propsVersion.Contains("-")) { $propsVersion = $propsVersion.Substring(0, $propsVersion.IndexOf('-')) }

if ($env:APPVEYOR_REPO_TAG -eq 'true') {
    $version = $env:APPVEYOR_REPO_TAG_NAME.Replace("release", "").Replace("release/v", "")
    Write-Host "$(env:APPVEYOR_REPO_TAG_NAME)" -ForegroundColor Cyan -NoNewline
} else {
    $buildNo = $env:APPVEYOR_BUILD_NUMBER
    $version = "$propsVersion-preview$buildNo"

    Write-Host "version.props file" -NoNewline

    if ($buildNo) {
        Write-Host " and the build number " -NoNewline
        Write-Host "$buildNo" -ForegroundColor Cyan -NoNewline
    }
}

Write-Host " to " -NoNewline
Write-Host "$version" -ForegroundColor Green -NoNewline
Write-Host "..."

$props.SelectSingleNode("//PropertyGroup/Version").InnerText = $version

$props.Save($propsFile)

Write-Host "Building, packing and preparing the artifacts..."

MSBuild "/t:Build" /verbosity:minimal "/p:PackageOutputPath=$artifactsDir"

Get-ChildItem "$artifactsDir\*.symbols.nupkg" | ForEach-Object {
    $newName = $_.Name -Replace "\.symbols\.nupkg", ".nupkg"

    Write-Host "Renaming " -NoNewLine
    Write-Host "$($_.Name)" -ForegroundColor Green -NoNewline
    Write-Host " to " -NoNewLine
    Write-Host "$newName" -ForegroundColor Green -NoNewline
    Write-Host "..."

    $destination = Join-Path -Path $_.Directory.FullName -ChildPath $newName
    Move-Item -Path $_.FullName -Destination $destination -Force
}

Write-Host "Running unit tests..."

cd .\tests\Medidata.MAuth.Tests

dotnet xunit

Write-Host "Build script completed."