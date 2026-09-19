$ErrorActionPreference = "Continue"
$env:Path = "$env:SystemRoot\System32;$env:Path"

$aliasDomain = "animesenpai.in"

Write-Host "Building ZenkaiTV static bundle..." -ForegroundColor Cyan
npm run vercel-build
if ($LASTEXITCODE -ne 0) {
  throw "ZenkaiTV static build failed."
}

Write-Host "Deploying ZenkaiTV web app and API routes to Vercel..." -ForegroundColor Cyan
$deployOutput = npx --yes vercel@latest deploy --prod --yes 2>&1
$deployOutput | ForEach-Object { Write-Host $_ }
if ($LASTEXITCODE -ne 0) {
  throw "Vercel deployment failed."
}

$deploymentUrl = ($deployOutput | Select-String -Pattern "https://animetv-[^\s]+" | Select-Object -First 1).Matches.Value
if (-not $deploymentUrl) {
  $deploymentUrl = ($deployOutput | Select-String -Pattern "https://[a-z0-9-]+-juankisantiago-5844s-projects\.vercel\.app" | Select-Object -First 1).Matches.Value
}

if (-not $deploymentUrl) {
  throw "Could not find the Vercel deployment URL in the deploy output."
}

Write-Host "Pointing $aliasDomain to $deploymentUrl..." -ForegroundColor Cyan
npx --yes vercel@latest alias set $deploymentUrl $aliasDomain
if ($LASTEXITCODE -ne 0) {
  throw "Vercel alias update failed."
}

Write-Host "zxkai is live at https://$aliasDomain" -ForegroundColor Green
