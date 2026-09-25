@description('Existing dedicated canary app created by main.bicep.')
param canaryAppName string

@description('Name of the uploaded publicly trusted wildcard certificate resource in this resource group, covering *.canary.ninjapaws.org. Do not pass a PFX or private key.')
param certificateName string

resource canary 'Microsoft.Web/sites@2025-03-01' existing = {
  name: canaryAppName
}

resource certificate 'Microsoft.Web/certificates@2025-03-01' existing = {
  name: certificateName
}

resource binding 'Microsoft.Web/sites/hostNameBindings@2025-03-01' = {
  parent: canary
  name: '*.canary.ninjapaws.org'
  properties: {
    siteName: canary.name
    hostNameType: 'Verified'
    customHostNameDnsRecordType: 'CName'
    sslState: 'SniEnabled'
    thumbprint: certificate.properties.thumbprint
  }
}

output boundHostname string = binding.name
output boundThumbprint string = certificate.properties.thumbprint
