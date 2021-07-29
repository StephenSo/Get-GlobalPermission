Function Get-GlobalPermission {
  param(
    [Parameter(Mandatory=$true)][string]$vc_server,
    [Parameter(Mandatory=$true)][PSCredential]$credential
  )

  # vSphere MOB URL to private enableMethods
  $mob_url = "https://$vc_server/invsvc/mob3/?moid=authorizationService&method=AuthorizationService.GetGlobalAccessControlList"

  # Ingore SSL Warnings
  add-type -TypeDefinition  @"
        using System.Net;
        using System.Security.Cryptography.X509Certificates;
        public class TrustAllCertsPolicy : ICertificatePolicy {
            public bool CheckValidationResult(
                ServicePoint srvPoint, X509Certificate certificate,
                WebRequest request, int certificateProblem) {
                return true;
            }
        }
"@
  [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy

    # Initial login to vSphere MOB using GET and store session using $vmware variable
    $results = Invoke-WebRequest -Uri $mob_url -SessionVariable vmware -Credential $Credentials -Method GET

    # Extract hidden vmware-session-nonce which must be included in future requests to prevent CSRF error
    # Credit to https://blog.netnerds.net/2013/07/use-powershell-to-keep-a-cookiejar-and-post-to-a-web-form/ for parsing vmware-session-nonce via Powershell
    if($results.StatusCode -eq 200) {
        $null = $results -match 'name="vmware-session-nonce" type="hidden" value="?([^\s^"]+)"'
        $sessionnonce = $matches[1]
    } else {
        Write-Error "Failed to login to vSphere MOB"
        exit 1
    }
    
    # The POST data payload must include the vmware-session-nonce variable + URL-encoded
  $body = @"
vmware-session-nonce=$sessionnonce
"@

    # Second request using a POST and specifying our session from initial login + body request
    $results = Invoke-WebRequest -Uri $mob_url -WebSession $vmware -Method POST -Body $body

    # Logout out of vSphere MOB
    $mob_logout_url = "https://$vc_server/invsvc/mob3/logout"
    $null = Invoke-WebRequest -Uri $mob_logout_url -WebSession $vmware -Method GET
    return (ConvertFrom-Mob3HtmlTable -Results $results)
}

function ConvertFrom-Mob3HtmlTable
{
  [CmdletBinding()]
  param
  (
    [Parameter(Mandatory=$false, Position=0)]
    [Object]
    $Results
  )
  $cleanedUpResults = ($results.ParsedHtml.body.innertext.split("`n").replace("`"","") | ? {$_.trim() -ne ""})
  $search = @()
  $search += "Field,Search"
  $search += "Group,groupboolean"
  $search += "Principal,namestring"
  $search += "Propagate,propagateboolean"
  $search += "Role,rolesArrayOfLong"
  $search += "Version,versionlong"
  $search = ConvertFrom-Csv $search
  
  $return = @()
  $MyObj = [PSCustomObject][ordered]@{}
  # Loop through results looking for valuestring which contains the data we want
  foreach ($parsedResults in ($cleanedUpResults |?{$_ -notmatch "Return value"} )) {
    if ($parsedResults -match 'groupboolean') {
    $MyObj = [PSCustomObject][ordered]@{}}
    $field = $null
    foreach ($field in $search){
      if(($parsedResults -like "$($field.Search)*")) {
        $result = $parsedResults.replace(($field.Search),"")
        $MyObj | Add-Member -MemberType NoteProperty -Name ($field.Field) -Value ($result -replace "`t|`n|`r","")
      }
      if (($MyObj | Get-Member -MemberType NoteProperty).Name -contains ($search[$search.Count-1].Field)) {
        $return += $MyObj
        $MyObj = [PSCustomObject][ordered]@{}
      }
    }
    
  }
  return $return
}
