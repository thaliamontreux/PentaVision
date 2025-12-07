#!/usr/bin/env pwsh

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# If the script lives inside the repo, move to the repo root
if ($PSScriptRoot) {
    Set-Location (Join-Path $PSScriptRoot '..')
}

# Ensure we are inside a git repository
try {
    git rev-parse --is-inside-work-tree *> $null
} catch {
    Write-Host 'Not inside a Git repository.'
    exit 1
}

# Check if there is anything to commit
$status = git status --porcelain
if ([string]::IsNullOrWhiteSpace($status)) {
    Write-Host 'No changes to commit.'
    exit 0
}

Write-Host 'Staging changes...'
git add -A

# Build an automatic commit message with timestamp
$branch = (git rev-parse --abbrev-ref HEAD).Trim()
$timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
$message = "Auto commit $timestamp"

Write-Host "Committing on branch '$branch' with message: $message"
git commit -m $message

Write-Host "Pushing to origin/$branch ..."
git push origin $branch

Write-Host 'Done.'
