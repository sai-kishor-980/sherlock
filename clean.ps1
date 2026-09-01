# Cleanup Script for Hmacfr Workspace
# Deletes all temporary test vaults, logs, database files, and cache folders.

Write-Host "Cleaning up unnecessary temporary files..." -ForegroundColor Cyan

# 1. Remove generated encrypted cases and test cases in evidence vault
if (Test-Path "backend/evidence_vault/encrypted") {
    Get-ChildItem -Path "backend/evidence_vault/encrypted" -Directory | Where-Object { $_.Name -ne ".gitkeep" } | Remove-Item -Recurse -Force
}
if (Test-Path "backend/evidence_vault") {
    Get-ChildItem -Path "backend/evidence_vault" -Directory | Where-Object { $_.Name -like "test_case_*" -or $_.Name -like "04977087*" } | Remove-Item -Recurse -Force
}

# 2. Remove log files
if (Test-Path "backend/logs") {
    Get-ChildItem -Path "backend/logs" -File -Filter "*.log" | Remove-Item -Force
}

# 3. Remove local SQLite database
if (Test-Path "backend/hmacfr.db") {
    Remove-Item -Path "backend/hmacfr.db" -Force
}

# 4. Remove Pytest and Python cache folders
Get-ChildItem -Path . -Include "__pycache__",".pytest_cache" -Recurse -Directory -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue

Write-Host "Cleanup complete! All temporary test files, caches, and logs removed." -ForegroundColor Green
