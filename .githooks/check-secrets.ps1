$ErrorActionPreference = "Stop"

$repoRoot = git rev-parse --show-toplevel
if (-not $repoRoot) {
    Write-Error "This scanner must be run inside a git repository."
    exit 1
}

Set-Location $repoRoot

$stagedFiles = git diff --cached --name-only --diff-filter=ACMR
if (-not $stagedFiles) {
    Write-Host "No staged files to scan."
    exit 0
}

$patterns = @(
    @{ Name = "Password assignment"; Regex = '(?i)(?:^|[^A-Za-z0-9])(?:Password|Pwd|passwd)\s*[:=]\s*["'']?[A-Za-z0-9!@#$%^&*()_+=\-\/]{4,}(?:["'']|\b)' },
    @{ Name = "API key or token"; Regex = '(?i)(?:^|[^A-Za-z0-9])(?:api[_-]?key|apikey|token|secret)\s*[:=]\s*["'']?[A-Za-z0-9_!@#$%^&*()_+=\-\/]{8,}(?:["'']|\b)' },
    @{ Name = "GitHub PAT"; Regex = 'ghp_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}' },
    @{ Name = "AWS access key"; Regex = 'AKIA[0-9A-Z]{16}' },
    @{ Name = "Slack token"; Regex = 'xox[baprs]-[A-Za-z0-9-]+' },
    @{ Name = "Azure connection string"; Regex = '(?i)(?:DefaultEndpointsProtocol|AccountKey|SharedAccessKey|BlobEndpoint|QueueEndpoint|TableEndpoint)[^\r\n]{0,200}(?:=|:)[^;\s\r\n]+' },
    @{ Name = "JWT token"; Regex = 'eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+' },
    @{ Name = "Bearer token"; Regex = '(?i)Bearer\s+[A-Za-z0-9._~+\-/=]{20,}' },
    @{ Name = "Private key"; Regex = '-----BEGIN [A-Z ]*PRIVATE KEY-----' },
    @{ Name = "Connection string password"; Regex = '(?i)(?:Server|Data Source|User Id|ConnectionString)[^\r\n]{0,200}(?:Password|Pwd)\s*[:=]\s*[^;\s"'']+' },
    @{ Name = "Generic secret field"; Regex = '(?i)(?:client[_-]?secret|secret[_-]?key|access[_-]?key|auth[_-]?token|session[_-]?key)\s*[:=]\s*["'']?[A-Za-z0-9_!@#$%^&*()_+=\-\/]{8,}(?:["'']|\b)' },
    @{ Name = "ASP.NET ConnectionStrings"; Regex = '(?i)(?:ConnectionStrings|ConnectionStrings__)[^\r\n]{0,200}(?:\{|\s*[\w\-]+\s*[:=]\s*)["'']?[A-Za-z0-9;:=_\-\/\\.@#$%^&*()~+]{12,}["'']?' },
    @{ Name = "ASP.NET JWT settings"; Regex = '(?i)(?:JwtBearer|Jwt|TokenValidation|Authority|Audience|Issuer|SigningKey|ClientSecret|ClientId)\s*[:=]\s*["'']?[A-Za-z0-9._~+\-/=:@#$%^&*()]{8,}["'']?' },
    @{ Name = "Azure app settings"; Regex = '(?i)(?:AzureWebJobsStorage|StorageConnectionString|SqlConnectionString|CosmosConnectionString|ServiceBusConnection|EventHubConnection|BlobConnection|QueueConnection)\s*[:=]\s*["'']?[A-Za-z0-9;:=_\-\/\\.@#$%^&*()~+]{12,}["'']?' },
    @{ Name = "Key Vault / certificate"; Regex = '(?i)(?:VaultUri|KeyVault|CertificatePassword|ClientCertificate|Thumbprint|PfxPassword)\s*[:=]\s*["'']?[A-Za-z0-9._~+\-/=:@#$%^&*()]{8,}["'']?' },
    @{ Name = "C# secret constant"; Regex = '(?is)(?:const|static\s+readonly|readonly)\s+\w+\s+(?:\w+\s*=?\s*"[^"]{8,}"|\w+\s*=?\s*"[^"]{8,}"\s*;|\w+\s*=?\s*new\s+string\([^\)]*\))' },
    @{ Name = "ASP.NET JSON secret value"; Regex = '(?i)(?:"|'')?(?:ConnectionStrings|JwtBearer|ClientSecret|ApiKey|Password|Token|Secret|Key|AccessKey|PrivateKey|ClientId|SubscriptionKey)["'']?\s*:\s*["'']?[A-Za-z0-9._~+\-/=:@#$%^&*()]{8,}["'']?' },
    @{ Name = "Environment variable secret assignment"; Regex = '(?is)(?:Environment\.GetEnvironmentVariable|GetEnvironmentVariable)\s*\(\s*["''](?:TOKEN|SECRET|PASSWORD|API_KEY|CLIENT_SECRET|ACCESS_KEY|CONNECTION_STRING|KEY_VAULT|JWT_SECRET)[^"'']*["'']\s*\)\s*;?\s*(?:\|\||&&)?\s*(?:var|const|string|readonly)\s+\w+\s*=?\s*["'']?[A-Za-z0-9._~+\-/=:@#$%^&*()]{8,}["'']?' }
)

$blocked = @()

foreach ($file in $stagedFiles) {
    $normalized = [System.IO.Path]::GetFullPath($file)
    $scriptSelf = [System.IO.Path]::GetFullPath((Join-Path $repoRoot '.githooks/check-secrets.ps1'))

    if ($normalized -eq $scriptSelf) {
        continue
    }

    # Skip example and template files (they contain placeholders, not real secrets)
    if ($file -like '*.example' -or $file -like '*.sample' -or $file -like '*.template') {
        continue
    }

    if (-not (Test-Path $file)) {
        continue
    }

    $content = Get-Content -Path $file -Raw -ErrorAction SilentlyContinue
    if ($null -eq $content) {
        continue
    }

    foreach ($pattern in $patterns) {
        if ($content -match $pattern.Regex) {
            $blocked += "[$($pattern.Name)] $file"
        }
    }
}

if ($blocked.Count -gt 0) {
    Write-Host "Potential secret detected in staged files:" -ForegroundColor Red
    foreach ($item in $blocked) {
        Write-Host "  - $item" -ForegroundColor Red
    }
    Write-Host "" 
    Write-Host "Commit blocked. Remove the secret or move it to a local-only .env file that is ignored by git." -ForegroundColor Yellow
    exit 1
}

Write-Host "No suspicious secret patterns found in staged files."
exit 0
