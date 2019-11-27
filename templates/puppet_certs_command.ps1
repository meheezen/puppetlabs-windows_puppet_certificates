$cert_path = '<%= @cert_path %>'
$key_path = '<%= @key_path %>'
$cert_type = '<%= @cert_type %>'

$VerbosePreference = 'Continue';
$ErrorActionPreference = 'Stop';

# check if $cert_path is valid
if (-not (Test-Path -Path $cert_path)) {
    Write-Verbose "Certificate $cert_path does not exist";
    exit 1;
}

# function to convert certificate to byte array for later import
Function GetBytesFromPEM( [string] $pemString, [string] $section = 'CERTIFICATE' )
{
    $header = "-----BEGIN {0}-----" -f $section;
    $footer = "-----END {0}-----" -f $section;
    $start = $pemString.IndexOf($header, [System.StringComparison]::Ordinal);

    if( $start -lt 0 ) {return $null};

    $start += $header.Length;

    $end = $pemString.IndexOf($footer, $start, [System.StringComparison]::Ordinal) - $start;
    if( $end -lt 0 ) {return $null};

    return [System.Convert]::FromBase64String( $pemString.Substring( $start, $end ) );
}

# read cert
$pem = [System.IO.File]::ReadAllText( $cert_path );
# convert cert to byte array
$certBuffer = GetBytesFromPEM( $pem );

# create new cert from byte array
$pfx = new-object System.Security.Cryptography.X509Certificates.X509Certificate2;
$pfx.import( [System.Byte[]] $certBuffer );
$cert_thumbprint = $pfx.Thumbprint.ToUpper();
Write-Verbose "Certificate thumbprint is $cert_thumbprint";

# check current cert store
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


