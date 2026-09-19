$ErrorActionPreference = "Stop"

$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$androidDir = Join-Path $root "android"
$assetsDir = Join-Path $androidDir "app\src\main\assets"

New-Item -ItemType Directory -Force -Path $assetsDir | Out-Null
Copy-Item -Force `
  (Join-Path $root "index.html"), `
  (Join-Path $root "styles.css"), `
  (Join-Path $root "client.js"), `
  (Join-Path $root "manifest.webmanifest"), `
  (Join-Path $root "sources.json"), `
  (Join-Path $root "service-worker.js"), `
  (Join-Path $root "zxkai-logo.svg"), `
  (Join-Path $root "zxkai-logo.png"), `
  (Join-Path $root "zxkai-logo-192.png"), `
  (Join-Path $root "zxkai-player-banner.svg") `
  -Destination $assetsDir

Copy-Item -Force -Recurse (Join-Path $root "js") $assetsDir
Copy-Item -Force -Recurse (Join-Path $root "player") $assetsDir

Push-Location $androidDir
try {
  if (Test-Path ".\gradlew.bat") {
    .\gradlew.bat assembleDebug
  } elseif (Get-Command gradle -ErrorAction SilentlyContinue) {
    gradle assembleDebug
  } else {
    throw "Gradle was not found. Install Android Studio, open the android folder once, then run this script again."
  }
} finally {
  Pop-Location
}

Write-Host "APK: $androidDir\app\build\outputs\apk\debug\app-debug.apk"

$downloadDir = Join-Path $root "downloads"
New-Item -ItemType Directory -Force -Path $downloadDir | Out-Null
Copy-Item -Force `
  (Join-Path $androidDir "app\build\outputs\apk\mobile\debug\app-mobile-debug.apk") `
  (Join-Path $downloadDir "zxkai-mobile.apk")
Write-Host "Download: $downloadDir\zxkai-mobile.apk"
