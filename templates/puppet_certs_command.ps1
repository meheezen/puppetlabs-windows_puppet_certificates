$cert_path = '<%= @cert_path %>'
$key_path = '<%= @key_path %>'
$cert_type = '<%= @cert_type %>'

$VerbosePreference = 'Continue'
$ErrorActionPreference = 'Stop'

## check given paths
if (-not (Test-Path -Path $key_path) -and ($cert_type -eq 'personal')) {
    Write-Verbose "Certificate $key_path does not exist";
    exit 1;
}
if (-not (Test-Path -Path $cert_path)) {
    Write-Verbose "Certificate $cert_path does not exist";
    exit 1;
}

## PEM KEY -> KEY
if ($cert_type -eq 'trusted_root_ca') {
} elseif (-not (Test-Path -Path "$key_path.key")) {
    Invoke-Expression openssl rsa -in $key_path -out "$key_path.key";
    if (-not $?) {
        Write-Verbose "Private key extracted from pem file and stored in $key_path.key"
    } else {
        Write-Verbose "Failed to extract private key from pem file";
        exit 1;
    }
} else {
    Write-Verbose "Private key $key_path.key already exists"
}

## PEM CERT + KEY -> PFX
if (-not (Test-Path -Path "$cert_path.pfx")) {
    if ($cert_type -eq 'personal') {
        Invoke-Expression "openssl pkcs12 -export -out ""$($cert_path).pfx"" -inkey ""$($key_path).key"" -in $cert_path -passout pass:;"
    } else {
        Invoke-Expression "openssl pkcs12 -export -out ""$($cert_path).pfx"" -nokeys -in $cert_path -passout pass:;"
    }
} else {
    Write-Verbose "Pfx file $cert_path.pfx already exists or cannot be created"
}


$pfx = new-object System.Security.Cryptography.X509Certificates.X509Certificate2;
$pfx.import( "$($cert_path).pfx" );
$cert_thumbprint = $pfx.Thumbprint.ToUpper();
Write-Verbose "Certificate thumbprint is $cert_thumbprint";

Write-Verbose "Opening certificate store $cert_type ...";
$storename = $null;
switch ($cert_type)
{
    'trusted_root_ca' { $storename = [System.Security.Cryptography.X509Certificates.StoreName]::Root; break };
    'personal'        { $storename = [System.Security.Cryptography.X509Certificates.StoreName]::My; break };
    default           { Throw "Unknown certificate type $cert_type" };
};
$cert_store = New-Object -Type System.Security.Cryptography.X509Certificates.X509Store($storename, [System.Security.Cryptography.X509Certificates.StoreLocation]::LocalMachine);
$cert_store.Open('ReadWrite');

Write-Verbose "Checking if certificate exists...";
$found = $false;
$cert_store.Certificates | % {
    $found = $found -or ($_.Thumbprint.ToUpper() -eq $cert_thumbprint);
};

if ($found) {
    Write-Verbose "Certificate already exists";
    exit 0;
};

Write-Verbose "Adding certificate to the store...";
$cert_store.Add($pfx) | Out-Null;
$cert_store.Close | Out-Null;

Write-Verbose "Certificate added";
exit 0;


