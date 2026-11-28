function New-PrivateDirectory([string]$Path) {
    $acl = [Security.AccessControl.DirectorySecurity]::new()
    $acl.SetSecurityDescriptorSddlForm($privateDacl, 'Access')
    $null = [IO.FileSystemAclExtensions]::CreateDirectory($acl, $Path)
    $created = Get-Item -LiteralPath $Path -Force
    $actual = Get-Acl -LiteralPath $Path
    if (($created.Attributes -band [IO.FileAttributes]::ReparsePoint) -or
        $actual.GetOwner([Security.Principal.SecurityIdentifier]).Value -notin $trustedAccounts -or
        $actual.GetSecurityDescriptorSddlForm('Access') -cne $privateDacl) {
        throw 'Cannot establish a private installation directory.'
    }
}

function Copy-Input([string]$InputPath, [string]$OutputPath, [long]$Limit, [switch]$Secret) {
    $file = Get-Item -LiteralPath $InputPath -Force
    if ($file -isnot [IO.FileInfo] -or ($file.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw 'An installation input must be an ordinary file.'
    }
    $stream = [IO.File]::Open($file.FullName, 'Open', 'Read', 'Read')
    try {
        if ($stream.Length -lt 1 -or $stream.Length -gt $Limit) { throw 'An installation input exceeds its size limits.' }
        if ($Secret) {
            $acl = [IO.FileSystemAclExtensions]::GetAccessControl($stream)
            $descriptor = [Security.AccessControl.RawSecurityDescriptor]::new($acl.GetSecurityDescriptorBinaryForm(), 0)
            if ($descriptor.Owner.Value -notin $trustedAccounts -or $null -eq $descriptor.DiscretionaryAcl) {
                throw 'The bootstrap file must have a private owner and DACL.'
            }
            foreach ($ace in $descriptor.DiscretionaryAcl) {
                if ($ace -isnot [Security.AccessControl.CommonAce] -or $ace.SecurityIdentifier.Value -notin $trustedAccounts) {
                    throw 'Restrict the bootstrap file to SYSTEM, Administrators and the installing administrator.'
                }
            }
        }
        $outputStream = [IO.File]::Open($OutputPath, 'CreateNew', 'Write', 'None')
        try { $stream.CopyTo($outputStream) } finally { $outputStream.Dispose() }
    } finally { $stream.Dispose() }
}

function Invoke-Sc([string[]]$Arguments) {
    $result = & $sc @Arguments 2>&1
    if ($LASTEXITCODE -ne 0) { throw "SCM command $($Arguments[0]) failed ($LASTEXITCODE): $result" }
}

function Read-Distribution {
    $zip = Join-Path $stage 'device-audit-windows-amd64.zip'
    $manifestPath = Join-Path $stage 'provenance.json'
    $signaturePath = Join-Path $stage 'provenance.p7s'
    Copy-Input (Join-Path $PackageDir 'provenance.json') $manifestPath 16KB
    Copy-Input (Join-Path $PackageDir 'provenance.p7s') $signaturePath 64KB

    Add-Type -AssemblyName System.Security.Cryptography.Pkcs
    $manifest = [IO.File]::ReadAllBytes($manifestPath)
    $cms = [Security.Cryptography.Pkcs.SignedCms]::new([Security.Cryptography.Pkcs.ContentInfo]::new($manifest), $true)
    try { $cms.Decode([IO.File]::ReadAllBytes($signaturePath)) } catch { throw 'The release signature is not valid CMS.' }
    if ($cms.SignerInfos.Count -ne 1) { throw 'Expected exactly one release signer.' }
    $signer = $cms.SignerInfos[0]
    if ($null -eq $signer.Certificate -or $signer.Certificate.GetCertHashString([Security.Cryptography.HashAlgorithmName]::SHA256) -ine $SignerSHA256 -or
        $signer.DigestAlgorithm.Value -cne '2.16.840.1.101.3.4.2.1' -or
        $cms.ContentInfo.ContentType.Value -cne '1.2.840.113549.1.7.1' -or
        [DateTime]::Now -lt $signer.Certificate.NotBefore -or [DateTime]::Now -gt $signer.Certificate.NotAfter) {
        throw 'The release signer does not match the pinned certificate or signing policy.'
    }
    try { $cms.CheckSignature($true) } catch { throw 'The detached release signature is invalid.' }
    # Require the verified content to be the exact detached input, even if a
    # producer mistakenly supplied CMS with embedded content.
    if ([Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($cms.ContentInfo.Content)) -cne
        [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($manifest))) {
        throw 'The signature content differs from the detached provenance file.'
    }

    $release = [Text.Encoding]::UTF8.GetString($manifest) | ConvertFrom-Json -AsHashtable
    if ($release.schema_version -cne 'device-audit.windows-release.v1' -or
        $release.source_repository -cne 'https://github.com/i-got-this-faa/device-audit' -or
        $release.source_commit -ine $SourceCommit -or $release.target -cne 'windows/amd64' -or
        $release.runtime -cne 'native-endpoint-agent' -or $release.model_included -isnot [bool] -or
        $release.archive_sha256 -cnotmatch '\A[0-9a-f]{64}\z' -or $release.go_toolchain -cnotmatch '\Ago[0-9]+\.[0-9]+\.[0-9]+\z') {
        throw 'The signed provenance does not match the requested source, package schema and target.'
    }
    if ($release.model_included -ne [bool]$ModelPublisherSHA256) {
        throw 'A model-bearing package requires an explicit publisher key pin. A telemetry-only package requires no model pin.'
    }
    Copy-Input (Join-Path $PackageDir 'device-audit-windows-amd64.zip') $zip 96MB
    if ((Get-FileHash -LiteralPath $zip -Algorithm SHA256).Hash -ine $release.archive_sha256) {
        throw 'The archive digest differs from the signed provenance.'
    }

    $files = [Collections.Generic.Dictionary[string, long]]::new([StringComparer]::Ordinal)
    $files.Add('endpoint-agent.exe', 64MB)
    $files.Add('Install-EndpointService.ps1', 64KB)
    $files.Add('Uninstall-EndpointService.ps1', 64KB)
    if ($release.model_included) {
        $null = New-Item -ItemType Directory -Path (Join-Path $stage 'model')
        $files.Add('model/artifact.json', 16MB)
        foreach ($file in 'evaluation.json', 'manifest.json', 'publisher.pem') { $files.Add("model/$file", 128KB) }
    }
    $bundle = [IO.Compression.ZipFile]::OpenRead($zip)
    try {
        foreach ($entry in $bundle.Entries) {
            $limit = 0L
            if (-not $files.TryGetValue($entry.FullName, [ref]$limit) -or $entry.Length -lt 1 -or $entry.Length -gt $limit) {
                throw 'Unexpected, duplicate or oversized archive entry.'
            }
            $null = $files.Remove($entry.FullName)
            [IO.Compression.ZipFileExtensions]::ExtractToFile($entry, (Join-Path $stage $entry.FullName))
        }
        if ($files.Count -ne 0) { throw 'The signed archive is missing required files.' }
    } finally { $bundle.Dispose() }
    if ($release.model_included -and (Get-FileHash -LiteralPath (Join-Path $stage 'model/publisher.pem')).Hash -ine $ModelPublisherSHA256) {
        throw 'The bundled model publisher key differs from the deployment pin.'
    }
    return $release
}
