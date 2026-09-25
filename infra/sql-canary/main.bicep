@description('Name of the new dedicated canary app. Never use the Pawton portal app name.')
@minLength(2)
@maxLength(60)
param canaryAppName string

@description('Existing Linux Basic-or-higher App Service plan in this resource group. Its compute capacity is shared, not recreated.')
param appServicePlanName string

@description('Location of the existing App Service plan.')
param location string

resource plan 'Microsoft.Web/serverfarms@2025-03-01' existing = {
  name: appServicePlanName
}

resource canary 'Microsoft.Web/sites@2025-03-01' = {
  name: canaryAppName
  location: location
  kind: 'app,linux'
  tags: {
    purpose: 'dojo-inert-canary'
  }
  properties: {
    serverFarmId: plan.id
    httpsOnly: true
    publicNetworkAccess: 'Enabled'
    clientAffinityEnabled: false
    siteConfig: {
      linuxFxVersion: 'NODE|24-lts'
      appCommandLine: 'node scripts/serve-external-source-canary.mjs'
      alwaysOn: true
      ftpsState: 'Disabled'
      minTlsVersion: '1.2'
      scmMinTlsVersion: '1.2'
      http20Enabled: true
      remoteDebuggingEnabled: false
      appSettings: [
        { name: 'HOST', value: '0.0.0.0' }
        { name: 'PORT', value: '8080' }
        { name: 'WEBSITES_PORT', value: '8080' }
        { name: 'WEBSITE_NODE_DEFAULT_VERSION', value: '~24' }
        { name: 'SCM_DO_BUILD_DURING_DEPLOYMENT', value: 'false' }
        { name: 'ENABLE_ORYX_BUILD', value: 'false' }
      ]
    }
  }
}

resource ftpPublishing 'Microsoft.Web/sites/basicPublishingCredentialsPolicies@2025-03-01' = {
  parent: canary
  name: 'ftp'
  properties: {
    allow: false
  }
}

resource scmPublishing 'Microsoft.Web/sites/basicPublishingCredentialsPolicies@2025-03-01' = {
  parent: canary
  name: 'scm'
  properties: {
    allow: false
  }
}

output canaryAppResourceId string = canary.id
output canaryDefaultHostname string = canary.properties.defaultHostName
output cloudflareRecords array = [
  {
    type: 'CNAME'
    name: '*.canary'
    content: canary.properties.defaultHostName
    proxy: 'DNS only'
  }
  {
    type: 'TXT'
    name: 'asuid.canary'
    content: canary.properties.customDomainVerificationId
  }
]
