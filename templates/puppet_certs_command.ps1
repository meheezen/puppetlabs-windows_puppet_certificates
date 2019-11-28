$cert_path = '<%= @cert_path %>'
$key_path = '<%= @key_path %>'
$cert_type = '<%= @cert_type %>'

$VerbosePreference = 'Continue'
$ErrorActionPreference = 'Stop'

## check given paths
if (-not (Test-Path -Path $key_path)) {
    Write-Verbose "Certificate $key_path does not exist";
    exit 1;
} 
if (-not (Test-Path -Path $cert_path)) {
    Write-Verbose "Certificate $cert_path does not exist";
    exit 1;
} 

## PEM KEY -> KEY
if (-not (Test-Path -Path "$key_path.key")) {
    openssl rsa -in $key_path -out "$key_path.key";
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
    openssl pkcs12 -export -out "$cert_path.pfx" -inkey "$key_path.key" -in $cert_path -passout pass:;
    if (-not $?) {
        Write-Verbose "Pfx file created with private key and stored in $cert_path.pfx"
    } else {
        Write-Verbose "Failed to create pfx file";
        exit 1;
    }
} else {
    Write-Verbose "Pfx file $cert_path.pfx already exists"
}

$pfx = new-object System.Security.Cryptography.X509Certificates.X509Certificate2;
$pfx.import( "$cert_path.pfx" );
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


