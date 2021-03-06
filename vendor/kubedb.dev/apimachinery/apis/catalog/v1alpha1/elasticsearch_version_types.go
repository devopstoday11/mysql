/*
Copyright AppsCode Inc. and Contributors

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package v1alpha1

import metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

const (
	ResourceCodeElasticsearchVersion     = "esversion"
	ResourceKindElasticsearchVersion     = "ElasticsearchVersion"
	ResourceSingularElasticsearchVersion = "elasticsearchversion"
	ResourcePluralElasticsearchVersion   = "elasticsearchversions"
)

// ElasticsearchVersion defines a Elasticsearch database version.

// +genclient
// +genclient:nonNamespaced
// +genclient:skipVerbs=updateStatus
// +k8s:openapi-gen=true
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// +kubebuilder:object:root=true
// +kubebuilder:resource:path=elasticsearchversions,singular=elasticsearchversion,scope=Cluster,shortName=esversion,categories={datastore,kubedb,appscode}
// +kubebuilder:printcolumn:name="Version",type="string",JSONPath=".spec.version"
// +kubebuilder:printcolumn:name="DB_IMAGE",type="string",JSONPath=".spec.db.image"
// +kubebuilder:printcolumn:name="AUTH_PLUGIN",type="string",JSONPath=".spec.authPlugin"
// +kubebuilder:printcolumn:name="Deprecated",type="boolean",JSONPath=".spec.deprecated"
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp"
type ElasticsearchVersion struct {
	metav1.TypeMeta   `json:",inline,omitempty"`
	metav1.ObjectMeta `json:"metadata,omitempty" protobuf:"bytes,1,opt,name=metadata"`
	Spec              ElasticsearchVersionSpec `json:"spec,omitempty" protobuf:"bytes,2,opt,name=spec"`
}

// ElasticsearchVersionSpec is the spec for elasticsearch version
type ElasticsearchVersionSpec struct {
	// Version
	Version string `json:"version" protobuf:"bytes,1,opt,name=version"`
	// Authentication plugin used by Elasticsearch cluster.
	AuthPlugin ElasticsearchAuthPlugin `json:"authPlugin" protobuf:"bytes,2,opt,name=authPlugin,casttype=ElasticsearchAuthPlugin"`
	// Database Image
	DB ElasticsearchVersionDatabase `json:"db" protobuf:"bytes,3,opt,name=db"`
	// Exporter Image
	Exporter ElasticsearchVersionExporter `json:"exporter" protobuf:"bytes,4,opt,name=exporter"`
	// Tools Image
	// +optional
	Tools ElasticsearchVersionTools `json:"tools,omitempty" protobuf:"bytes,5,opt,name=tools"`
	// Deprecated versions usable but regarded as obsolete and best avoided, typically due to having been superseded.
	// +optional
	Deprecated bool `json:"deprecated,omitempty" protobuf:"varint,6,opt,name=deprecated"`
	// Init container Image
	InitContainer ElasticsearchVersionInitContainer `json:"initContainer" protobuf:"bytes,7,opt,name=initContainer"`
	// PSP names
	PodSecurityPolicies ElasticsearchVersionPodSecurityPolicy `json:"podSecurityPolicies" protobuf:"bytes,8,opt,name=podSecurityPolicies"`
}

// ElasticsearchVersionDatabase is the Elasticsearch Database image
type ElasticsearchVersionDatabase struct {
	Image string `json:"image" protobuf:"bytes,1,opt,name=image"`
}

// ElasticsearchVersionExporter is the image for the Elasticsearch exporter
type ElasticsearchVersionExporter struct {
	Image string `json:"image" protobuf:"bytes,1,opt,name=image"`
}

// ElasticsearchVersionTools is the image for the elasticsearch tools
type ElasticsearchVersionTools struct {
	Image string `json:"image" protobuf:"bytes,1,opt,name=image"`
}

// ElasticsearchVersionInitContainer is the Elasticsearch Container initializer
type ElasticsearchVersionInitContainer struct {
	Image   string `json:"image" protobuf:"bytes,1,opt,name=image"`
	YQImage string `json:"yqImage" protobuf:"bytes,2,opt,name=yqImage"`
}

// ElasticsearchVersionPodSecurityPolicy is the Elasticsearch pod security policies
type ElasticsearchVersionPodSecurityPolicy struct {
	DatabasePolicyName string `json:"databasePolicyName" protobuf:"bytes,1,opt,name=databasePolicyName"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// ElasticsearchVersionList is a list of ElasticsearchVersions
type ElasticsearchVersionList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty" protobuf:"bytes,1,opt,name=metadata"`
	// Items is a list of ElasticsearchVersion CRD objects
	Items []ElasticsearchVersion `json:"items,omitempty" protobuf:"bytes,2,rep,name=items"`
}

// +kubebuilder:validation:Enum=SearchGuard;X-Pack;OpenDistro
type ElasticsearchAuthPlugin string

const (
	ElasticsearchAuthPluginSearchGuard ElasticsearchAuthPlugin = "SearchGuard"
	ElasticsearchAuthPluginXpack       ElasticsearchAuthPlugin = "X-Pack"
	ElasticsearchAuthPluginOpenDistro  ElasticsearchAuthPlugin = "OpenDistro"
)
