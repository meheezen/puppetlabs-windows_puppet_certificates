$cert_path = '<%= @cert_path %>'
$key_path = '<%= @key_path %>'
$cert_type = '<%= @cert_type %>'

$VerbosePreference = 'Continue'
$ErrorActionPreference = 'Stop'
 
if (-not (Test-Path -Path $cert_path)) {
    Write-Verbose "Certificate $cert_path does not exist"
    exit 1
}

$pfx = new-object System.Security.Cryptography.X509Certificates.X509Certificate2( $cert_path );
$cert_thumbprint = $pfx.Thumbprint.ToUpper()
Write-Verbose "Certificate thumbprint is $cert_thumbprint"

Write-Verbose "Opening certificate store $cert_type ..."
$storename = $null
switch ($cert_type)
{
    'trusted_root_ca' { $storename = [System.Security.Cryptography.X509Certificates.StoreName]::Root; break }
    'personal'        { $storename = [System.Security.Cryptography.X509Certificates.StoreName]::My; break }
     default          { Throw "Unknown certificate type $cert_type" }
}
$cert_store = New-Object -Type System.Security.Cryptography.X509Certificates.X509Store($storename, [System.Security.Cryptography.X509Certificates.StoreLocation]::LocalMachine)
$cert_store.Open('ReadWrite')

Write-Verbose "Checking if certificate exists..."
$found = $false
$cert_store.Certificates | % {
    $found = $found -or ($_.Thumbprint.ToUpper() -eq $cert_thumbprint)
}

if ($found) {
    Write-Verbose "Certificate already exists"
    exit 0
}

Write-Verbose "Adding certificate to the store..."
$cert_store.Add($pfx) | Out-Null
$cert_store.Close | Out-Null

Write-Verbose "Certificate added"
exit 0


