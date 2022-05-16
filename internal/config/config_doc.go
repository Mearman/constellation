// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// Code generated by hack/docgen tool. DO NOT EDIT.

package config

import (
	"github.com/talos-systems/talos/pkg/machinery/config/encoder"
)

var (
	ConfigDoc         encoder.Doc
	ProviderConfigDoc encoder.Doc
	AzureConfigDoc    encoder.Doc
	GCPConfigDoc      encoder.Doc
	QEMUConfigDoc     encoder.Doc
)

func init() {
	ConfigDoc.Type = "Config"
	ConfigDoc.Comments[encoder.LineComment] = "Config defines configuration used by CLI."
	ConfigDoc.Description = "Config defines configuration used by CLI."
	ConfigDoc.Fields = make([]encoder.Doc, 4)
	ConfigDoc.Fields[0].Name = "autoscalingNodeGroupsMin"
	ConfigDoc.Fields[0].Type = "int"
	ConfigDoc.Fields[0].Note = ""
	ConfigDoc.Fields[0].Description = "Minimum number of nodes in autoscaling group.\nworker nodes."
	ConfigDoc.Fields[0].Comments[encoder.LineComment] = "Minimum number of nodes in autoscaling group."
	ConfigDoc.Fields[1].Name = "autoscalingNodeGroupsMax"
	ConfigDoc.Fields[1].Type = "int"
	ConfigDoc.Fields[1].Note = ""
	ConfigDoc.Fields[1].Description = "Maximum number of nodes in autoscaling group.\nworker nodes."
	ConfigDoc.Fields[1].Comments[encoder.LineComment] = "Maximum number of nodes in autoscaling group."
	ConfigDoc.Fields[2].Name = "StateDisksizeGB"
	ConfigDoc.Fields[2].Type = "int"
	ConfigDoc.Fields[2].Note = ""
	ConfigDoc.Fields[2].Description = "Size (in GB) of root disk used for nodes."
	ConfigDoc.Fields[2].Comments[encoder.LineComment] = "Size (in GB) of root disk used for nodes."
	ConfigDoc.Fields[3].Name = "provider"
	ConfigDoc.Fields[3].Type = "ProviderConfig"
	ConfigDoc.Fields[3].Note = ""
	ConfigDoc.Fields[3].Description = "Supported cloud providers & their specific configurations."
	ConfigDoc.Fields[3].Comments[encoder.LineComment] = "Supported cloud providers & their specific configurations."

	ProviderConfigDoc.Type = "ProviderConfig"
	ProviderConfigDoc.Comments[encoder.LineComment] = "ProviderConfig are cloud-provider specific configuration values used by the CLI."
	ProviderConfigDoc.Description = "ProviderConfig are cloud-provider specific configuration values used by the CLI."
	ProviderConfigDoc.AppearsIn = []encoder.Appearance{
		{
			TypeName:  "Config",
			FieldName: "provider",
		},
	}
	ProviderConfigDoc.Fields = make([]encoder.Doc, 3)
	ProviderConfigDoc.Fields[0].Name = "azureConfig"
	ProviderConfigDoc.Fields[0].Type = "AzureConfig"
	ProviderConfigDoc.Fields[0].Note = ""
	ProviderConfigDoc.Fields[0].Description = "Configuration for Azure as provider."
	ProviderConfigDoc.Fields[0].Comments[encoder.LineComment] = "Configuration for Azure as provider."
	ProviderConfigDoc.Fields[1].Name = "gcpConfig"
	ProviderConfigDoc.Fields[1].Type = "GCPConfig"
	ProviderConfigDoc.Fields[1].Note = ""
	ProviderConfigDoc.Fields[1].Description = "Configuration for Google Cloud as provider."
	ProviderConfigDoc.Fields[1].Comments[encoder.LineComment] = "Configuration for Google Cloud as provider."
	ProviderConfigDoc.Fields[2].Name = "qemuConfig"
	ProviderConfigDoc.Fields[2].Type = "QEMUConfig"
	ProviderConfigDoc.Fields[2].Note = ""
	ProviderConfigDoc.Fields[2].Description = "Configuration for QEMU as provider."
	ProviderConfigDoc.Fields[2].Comments[encoder.LineComment] = "Configuration for QEMU as provider."

	AzureConfigDoc.Type = "AzureConfig"
	AzureConfigDoc.Comments[encoder.LineComment] = "AzureConfig are Azure specific configuration values used by the CLI."
	AzureConfigDoc.Description = "AzureConfig are Azure specific configuration values used by the CLI."
	AzureConfigDoc.AppearsIn = []encoder.Appearance{
		{
			TypeName:  "ProviderConfig",
			FieldName: "azureConfig",
		},
	}
	AzureConfigDoc.Fields = make([]encoder.Doc, 7)
	AzureConfigDoc.Fields[0].Name = "subscription"
	AzureConfigDoc.Fields[0].Type = "string"
	AzureConfigDoc.Fields[0].Note = ""
	AzureConfigDoc.Fields[0].Description = "Subscription ID of the used Azure account. See: https://docs.microsoft.com/en-us/azure/azure-portal/get-subscription-tenant-id#find-your-azure-subscription"
	AzureConfigDoc.Fields[0].Comments[encoder.LineComment] = "Subscription ID of the used Azure account. See: https://docs.microsoft.com/en-us/azure/azure-portal/get-subscription-tenant-id#find-your-azure-subscription"
	AzureConfigDoc.Fields[1].Name = "tenant"
	AzureConfigDoc.Fields[1].Type = "string"
	AzureConfigDoc.Fields[1].Note = ""
	AzureConfigDoc.Fields[1].Description = "Tenant ID of the used Azure account. See: https://docs.microsoft.com/en-us/azure/azure-portal/get-subscription-tenant-id#find-your-azure-ad-tenant"
	AzureConfigDoc.Fields[1].Comments[encoder.LineComment] = "Tenant ID of the used Azure account. See: https://docs.microsoft.com/en-us/azure/azure-portal/get-subscription-tenant-id#find-your-azure-ad-tenant"
	AzureConfigDoc.Fields[2].Name = "location"
	AzureConfigDoc.Fields[2].Type = "string"
	AzureConfigDoc.Fields[2].Note = ""
	AzureConfigDoc.Fields[2].Description = "Azure datacenter region to be used. See: https://docs.microsoft.com/en-us/azure/availability-zones/az-overview#azure-regions-with-availability-zones"
	AzureConfigDoc.Fields[2].Comments[encoder.LineComment] = "Azure datacenter region to be used. See: https://docs.microsoft.com/en-us/azure/availability-zones/az-overview#azure-regions-with-availability-zones"
	AzureConfigDoc.Fields[3].Name = "image"
	AzureConfigDoc.Fields[3].Type = "string"
	AzureConfigDoc.Fields[3].Note = ""
	AzureConfigDoc.Fields[3].Description = "Machine image used to create Constellation nodes."
	AzureConfigDoc.Fields[3].Comments[encoder.LineComment] = "Machine image used to create Constellation nodes."
	AzureConfigDoc.Fields[4].Name = "networkSecurityGroupInput"
	AzureConfigDoc.Fields[4].Type = "NetworkSecurityGroupInput"
	AzureConfigDoc.Fields[4].Note = ""
	AzureConfigDoc.Fields[4].Description = "Firewall rules."
	AzureConfigDoc.Fields[4].Comments[encoder.LineComment] = "Firewall rules."
	AzureConfigDoc.Fields[5].Name = "measurements"
	AzureConfigDoc.Fields[5].Type = "Measurements"
	AzureConfigDoc.Fields[5].Note = ""
	AzureConfigDoc.Fields[5].Description = "Measurement used to enable measured boot."
	AzureConfigDoc.Fields[5].Comments[encoder.LineComment] = "Measurement used to enable measured boot."
	AzureConfigDoc.Fields[6].Name = "userassignedIdentity"
	AzureConfigDoc.Fields[6].Type = "string"
	AzureConfigDoc.Fields[6].Note = ""
	AzureConfigDoc.Fields[6].Description = "Why is this needed? Docs only say that it is needed. (TODO) See: https://constellation-docs.edgeless.systems/6c320851-bdd2-41d5-bf10-e27427398692/#/getting-started/install?id=azure"
	AzureConfigDoc.Fields[6].Comments[encoder.LineComment] = "Why is this needed? Docs only say that it is needed. (TODO) See: https://constellation-docs.edgeless.systems/6c320851-bdd2-41d5-bf10-e27427398692/#/getting-started/install?id=azure"

	GCPConfigDoc.Type = "GCPConfig"
	GCPConfigDoc.Comments[encoder.LineComment] = "GCPConfig are GCP specific configuration values used by the CLI."
	GCPConfigDoc.Description = "GCPConfig are GCP specific configuration values used by the CLI."
	GCPConfigDoc.AppearsIn = []encoder.Appearance{
		{
			TypeName:  "ProviderConfig",
			FieldName: "gcpConfig",
		},
	}
	GCPConfigDoc.Fields = make([]encoder.Doc, 8)
	GCPConfigDoc.Fields[0].Name = "project"
	GCPConfigDoc.Fields[0].Type = "string"
	GCPConfigDoc.Fields[0].Note = ""
	GCPConfigDoc.Fields[0].Description = "GCP project. See: https://support.google.com/googleapi/answer/7014113?hl=en"
	GCPConfigDoc.Fields[0].Comments[encoder.LineComment] = "GCP project. See: https://support.google.com/googleapi/answer/7014113?hl=en"
	GCPConfigDoc.Fields[1].Name = "region"
	GCPConfigDoc.Fields[1].Type = "string"
	GCPConfigDoc.Fields[1].Note = ""
	GCPConfigDoc.Fields[1].Description = "GCP datacenter region. See: https://cloud.google.com/compute/docs/regions-zones#available"
	GCPConfigDoc.Fields[1].Comments[encoder.LineComment] = "GCP datacenter region. See: https://cloud.google.com/compute/docs/regions-zones#available"
	GCPConfigDoc.Fields[2].Name = "zone"
	GCPConfigDoc.Fields[2].Type = "string"
	GCPConfigDoc.Fields[2].Note = ""
	GCPConfigDoc.Fields[2].Description = "GCP datacenter zone. See: https://cloud.google.com/compute/docs/regions-zones#available"
	GCPConfigDoc.Fields[2].Comments[encoder.LineComment] = "GCP datacenter zone. See: https://cloud.google.com/compute/docs/regions-zones#available"
	GCPConfigDoc.Fields[3].Name = "image"
	GCPConfigDoc.Fields[3].Type = "string"
	GCPConfigDoc.Fields[3].Note = ""
	GCPConfigDoc.Fields[3].Description = "Machine image used to create Constellation nodes."
	GCPConfigDoc.Fields[3].Comments[encoder.LineComment] = "Machine image used to create Constellation nodes."
	GCPConfigDoc.Fields[4].Name = "firewallInput"
	GCPConfigDoc.Fields[4].Type = "FirewallInput"
	GCPConfigDoc.Fields[4].Note = ""
	GCPConfigDoc.Fields[4].Description = "Firewall rules."
	GCPConfigDoc.Fields[4].Comments[encoder.LineComment] = "Firewall rules."
	GCPConfigDoc.Fields[5].Name = "vpcsInput"
	GCPConfigDoc.Fields[5].Type = "VPCsInput"
	GCPConfigDoc.Fields[5].Note = ""
	GCPConfigDoc.Fields[5].Description = "Virtual Private Cloud settings."
	GCPConfigDoc.Fields[5].Comments[encoder.LineComment] = "Virtual Private Cloud settings."
	GCPConfigDoc.Fields[6].Name = "serviceAccountRoles"
	GCPConfigDoc.Fields[6].Type = "[]string"
	GCPConfigDoc.Fields[6].Note = ""
	GCPConfigDoc.Fields[6].Description = "Roles added to service account."
	GCPConfigDoc.Fields[6].Comments[encoder.LineComment] = "Roles added to service account."
	GCPConfigDoc.Fields[7].Name = "measurements"
	GCPConfigDoc.Fields[7].Type = "Measurements"
	GCPConfigDoc.Fields[7].Note = ""
	GCPConfigDoc.Fields[7].Description = "Measurement used to enable measured boot."
	GCPConfigDoc.Fields[7].Comments[encoder.LineComment] = "Measurement used to enable measured boot."

	QEMUConfigDoc.Type = "QEMUConfig"
	QEMUConfigDoc.Comments[encoder.LineComment] = ""
	QEMUConfigDoc.Description = ""
	QEMUConfigDoc.AppearsIn = []encoder.Appearance{
		{
			TypeName:  "ProviderConfig",
			FieldName: "qemuConfig",
		},
	}
	QEMUConfigDoc.Fields = make([]encoder.Doc, 1)
	QEMUConfigDoc.Fields[0].Name = "measurements"
	QEMUConfigDoc.Fields[0].Type = "Measurements"
	QEMUConfigDoc.Fields[0].Note = ""
	QEMUConfigDoc.Fields[0].Description = "Measurement used to enable measured boot."
	QEMUConfigDoc.Fields[0].Comments[encoder.LineComment] = "Measurement used to enable measured boot."
}

func (_ Config) Doc() *encoder.Doc {
	return &ConfigDoc
}

func (_ ProviderConfig) Doc() *encoder.Doc {
	return &ProviderConfigDoc
}

func (_ AzureConfig) Doc() *encoder.Doc {
	return &AzureConfigDoc
}

func (_ GCPConfig) Doc() *encoder.Doc {
	return &GCPConfigDoc
}

func (_ QEMUConfig) Doc() *encoder.Doc {
	return &QEMUConfigDoc
}

// GetConfigurationDoc returns documentation for the file ./config_doc.go.
func GetConfigurationDoc() *encoder.FileDoc {
	return &encoder.FileDoc{
		Name:        "Configuration",
		Description: "",
		Structs: []*encoder.Doc{
			&ConfigDoc,
			&ProviderConfigDoc,
			&AzureConfigDoc,
			&GCPConfigDoc,
			&QEMUConfigDoc,
		},
	}
}
