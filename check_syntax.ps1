# Static check: bracket balance + string closure + cross-module import existence.
# Pure ASCII on purpose: Windows PowerShell 5.1 reads BOM-less .ps1 as ANSI,
# and non-ASCII literals corrupt quote parsing.
param([string]$Root = "src\zhigou")

$ErrorActionPreference = "Stop"
$files = Get-ChildItem -Path $Root -Filter *.py -Recurse
$problems = New-Object System.Collections.Generic.List[string]

function Test-Balance {
    param([string]$Path)

    $src = Get-Content -LiteralPath $Path -Raw -Encoding UTF8
    $stack = New-Object System.Collections.Generic.Stack[object]
    $line = 1
    $i = 0
    $len = $src.Length
    $DQ = [char]34
    $SQ = [char]39
    $BS = [char]92
    $NL = [char]10

    $pairs = @{ ")" = "("; "]" = "["; "}" = "{" }

    while ($i -lt $len) {
        $c = [string]$src[$i]

        if ($c -eq $NL) { $line++; $i++; continue }

        if ($c -eq "#") {
            while ($i -lt $len -and $src[$i] -ne $NL) { $i++ }
            continue
        }

        # triple quote
        if (($c -eq $DQ -or $c -eq $SQ) -and ($i + 2 -lt $len) -and ([string]$src[$i+1]) -eq $c -and ([string]$src[$i+2]) -eq $c) {
            $q = $c; $i += 3
            $closed = $false
            while ($i -lt $len) {
                if ([string]$src[$i] -eq $NL) { $line++ }
                if ([string]$src[$i] -eq $BS) { $i += 2; continue }
                if (([string]$src[$i]) -eq $q -and ([string]$src[$i+1]) -eq $q -and ([string]$src[$i+2]) -eq $q) { $i += 3; $closed = $true; break }
                $i++
            }
            if (-not $closed) { $problems.Add("$Path line $line : unclosed triple quote") }
            continue
        }

        # single-quoted
        if ($c -eq $SQ) {
            $i++
            $closed = $false
            while ($i -lt $len) {
                if ([string]$src[$i] -eq $NL) { break }
                if ([string]$src[$i] -eq $BS) { $i += 2; continue }
                if ([string]$src[$i] -eq $SQ) { $i++; $closed = $true; break }
                $i++
            }
            if (-not $closed) { $problems.Add("$Path line $line : unclosed single-quoted string") }
            continue
        }

        # double-quoted / f-string
        if ($c -eq $DQ) {
            $i++
            $closed = $false
            while ($i -lt $len) {
                if ([string]$src[$i] -eq $NL) { break }
                if ([string]$src[$i] -eq $BS) { $i += 2; continue }
                if ([string]$src[$i] -eq $DQ) { $i++; $closed = $true; break }
                $i++
            }
            if (-not $closed) { $problems.Add("$Path line $line : unclosed double-quoted string") }
            continue
        }

        if ($c -eq "(" -or $c -eq "[" -or $c -eq "{") {
            $stack.Push(@{ ch = $c; ln = $line })
            $i++; continue
        }

        if ($c -eq ")" -or $c -eq "]" -or $c -eq "}") {
            if ($stack.Count -eq 0) {
                $problems.Add("$Path line $line : unexpected '$c'")
            } else {
                $top = $stack.Pop()
                $expected = $pairs[$c]
                if ($top.ch -ne $expected) {
                    $problems.Add("$Path line $line : mismatch '$($top.ch)' (line $($top.ln)) vs '$c'")
                }
            }
            $i++; continue
        }

        $i++
    }

    while ($stack.Count -gt 0) {
        $t = $stack.Pop()
        $problems.Add("$Path line $($t.ln) : unclosed '$($t.ch)'")
    }
}

foreach ($f in $files) { Test-Balance -Path $f.FullName }

# ---- cross-module import check ----
$defined = @{}
foreach ($f in $files) {
    $src = Get-Content -LiteralPath $f.FullName -Raw -Encoding UTF8
    $mod = $f.BaseName
    $names = New-Object System.Collections.Generic.HashSet[string]

    foreach ($m in [regex]::Matches($src, "(?m)^(?:class|def)\s+([A-Za-z_][A-Za-z0-9_]*)")) {
        [void]$names.Add($m.Groups[1].Value)
    }
    foreach ($m in [regex]::Matches($src, "(?m)^([A-Za-z_][A-Za-z0-9_]*)\s*=\s*")) {
        [void]$names.Add($m.Groups[1].Value)
    }
    foreach ($m in [regex]::Matches($src, "(?m)^\s+([A-Za-z_][A-Za-z0-9_]*)\s*(?::[^=]+)?=\s*")) {
        [void]$names.Add($m.Groups[1].Value)
    }
    foreach ($m in [regex]::Matches($src, "(?m)^__all__\s*=\s*\[([^\]]*)\]", [System.Text.RegularExpressions.RegexOptions]::Singleline)) {
        foreach ($s in [regex]::Matches($m.Groups[1].Value, '"([^"]+)"')) {
            [void]$names.Add($s.Groups[1].Value)
        }
    }
    $defined[$mod] = $names
}

foreach ($f in $files) {
    $src = Get-Content -LiteralPath $f.FullName -Raw -Encoding UTF8
    foreach ($m in [regex]::Matches($src, "(?m)^from\s+\.([A-Za-z0-9_]+)\s+import\s+\(([^)]*)\)", [System.Text.RegularExpressions.RegexOptions]::Singleline)) {
        $target = $m.Groups[1].Value
        $body = $m.Groups[2].Value
        if (-not $defined.ContainsKey($target)) {
            $problems.Add("$($f.Name): imports missing module '.$target'")
            continue
        }
        $avail = $defined[$target]
        foreach ($part in ($body -split ",")) {
            $p = $part.Trim()
            if ($p -match "^([A-Za-z_][A-Za-z0-9_]*)(\s+as\s+\w+)?$") {
                $n = $Matches[1]
                if (-not $avail.Contains($n)) {
                    $problems.Add("$($f.Name): imports '$n' from '.$target' which does not define it")
                }
            }
        }
    }
}

Write-Output "files scanned: $($files.Count)"
if ($problems.Count -eq 0) {
    Write-Output "PASS - brackets balanced, strings closed, cross-module imports resolve"
    exit 0
} else {
    Write-Output "FOUND $($problems.Count) problem(s):"
    foreach ($p in $problems) { Write-Output "  - $p" }
    exit 1
}