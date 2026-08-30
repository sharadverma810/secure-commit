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
    @{ Name = "Private key"; Regex = '-----BEGIN [A-Z ]*PRIVATE KEY-----' },
    @{ Name = "Connection string password"; Regex = '(?i)(?:Server|Data Source|User Id|ConnectionString)[^\r\n]{0,200}(?:Password|Pwd)\s*[:=]\s*[^;\s"'']+' }
)

$blocked = @()

foreach ($file in $stagedFiles) {
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
