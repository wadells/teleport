/*
Copyright 2021 Gravitational, Inc.

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

package services

import (
	"context"
	"fmt"
	"strings"

	"github.com/gravitational/teleport/api/types"
	apiutils "github.com/gravitational/teleport/api/utils"
	"github.com/gravitational/teleport/lib/defaults"
	"github.com/gravitational/teleport/lib/utils"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/arn"
	"github.com/aws/aws-sdk-go/service/rds"

	"github.com/gravitational/trace"
	log "github.com/sirupsen/logrus"
)

// DatabaseGetter defines interface for fetching database resources.
type DatabaseGetter interface {
	// GetDatabases returns all database resources.
	GetDatabases(context.Context) ([]types.Database, error)
	// GetDatabase returns the specified database resource.
	GetDatabase(ctx context.Context, name string) (types.Database, error)
}

// Databases defines an interface for managing database resources.
type Databases interface {
	// DatabaseGetter provides methods for fetching database resources.
	DatabaseGetter
	// CreateDatabase creates a new database resource.
	CreateDatabase(context.Context, types.Database) error
	// UpdateDatabse updates an existing database resource.
	UpdateDatabase(context.Context, types.Database) error
	// DeleteDatabase removes the specified database resource.
	DeleteDatabase(ctx context.Context, name string) error
	// DeleteAllDatabases removes all database resources.
	DeleteAllDatabases(context.Context) error
}

// MarshalDatabase marshals the database resource to JSON.
func MarshalDatabase(database types.Database, opts ...MarshalOption) ([]byte, error) {
	if err := database.CheckAndSetDefaults(); err != nil {
		return nil, trace.Wrap(err)
	}
	cfg, err := CollectOptions(opts)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	switch database := database.(type) {
	case *types.DatabaseV3:
		if !cfg.PreserveResourceID {
			// avoid modifying the original object
			// to prevent unexpected data races
			copy := *database
			copy.SetResourceID(0)
			database = &copy
		}
		return utils.FastMarshal(database)
	default:
		return nil, trace.BadParameter("unsupported database resource %T", database)
	}
}

// UnmarshalDatabase unmarshals the database resource from JSON.
func UnmarshalDatabase(data []byte, opts ...MarshalOption) (types.Database, error) {
	if len(data) == 0 {
		return nil, trace.BadParameter("missing database resource data")
	}
	cfg, err := CollectOptions(opts)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	var h types.ResourceHeader
	if err := utils.FastUnmarshal(data, &h); err != nil {
		return nil, trace.Wrap(err)
	}
	switch h.Version {
	case types.V3:
		var database types.DatabaseV3
		if err := utils.FastUnmarshal(data, &database); err != nil {
			return nil, trace.BadParameter(err.Error())
		}
		if err := database.CheckAndSetDefaults(); err != nil {
			return nil, trace.Wrap(err)
		}
		if cfg.ID != 0 {
			database.SetResourceID(cfg.ID)
		}
		if !cfg.Expires.IsZero() {
			database.SetExpiry(cfg.Expires)
		}
		return &database, nil
	}
	return nil, trace.BadParameter("unsupported database resource version %q", h.Version)
}

// NewDatabaseFromRDSInstance creates a database resource from an RDS instance.
func NewDatabaseFromRDSInstance(instance *rds.DBInstance) (types.Database, error) {
	endpoint := instance.Endpoint
	if endpoint == nil {
		return nil, trace.BadParameter("empty endpoint")
	}
	metadata, err := MetadataFromRDSInstance(instance)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return types.NewDatabaseV3(types.Metadata{
		Name:        aws.StringValue(instance.DBInstanceIdentifier),
		Description: fmt.Sprintf("RDS instance in %v", metadata.Region),
		Labels:      labelsFromRDSInstance(instance, metadata),
	}, types.DatabaseSpecV3{
		Protocol: engineToProtocol(aws.StringValue(instance.Engine)),
		URI:      fmt.Sprintf("%v:%v", aws.StringValue(endpoint.Address), aws.Int64Value(endpoint.Port)),
		AWS:      *metadata,
	})
}

// NewDatabaseFromRDSCluster creates a database resource from an RDS cluster (Aurora).
func NewDatabaseFromRDSCluster(cluster *rds.DBCluster) (types.Database, error) {
	metadata, err := MetadataFromRDSCluster(cluster)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return types.NewDatabaseV3(types.Metadata{
		Name:        aws.StringValue(cluster.DBClusterIdentifier),
		Description: fmt.Sprintf("Aurora cluster in %v", metadata.Region),
		Labels:      labelsFromRDSCluster(cluster, metadata),
	}, types.DatabaseSpecV3{
		Protocol: engineToProtocol(aws.StringValue(cluster.Engine)),
		URI:      fmt.Sprintf("%v:%v", aws.StringValue(cluster.Endpoint), aws.Int64Value(cluster.Port)),
		AWS:      *metadata,
	})
}

// MetadataFromRDSInstance creates AWS metadata from the provided RDS instance.
func MetadataFromRDSInstance(rdsInstance *rds.DBInstance) (*types.AWS, error) {
	parsedARN, err := arn.Parse(aws.StringValue(rdsInstance.DBInstanceArn))
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return &types.AWS{
		Region:    parsedARN.Region,
		AccountID: parsedARN.AccountID,
		RDS: types.RDS{
			InstanceID: aws.StringValue(rdsInstance.DBInstanceIdentifier),
			ClusterID:  aws.StringValue(rdsInstance.DBClusterIdentifier),
			ResourceID: aws.StringValue(rdsInstance.DbiResourceId),
			IAMAuth:    aws.BoolValue(rdsInstance.IAMDatabaseAuthenticationEnabled),
		},
	}, nil
}

// MetadataFromRDSCluster creates AWS metadata from the provided RDS cluster.
func MetadataFromRDSCluster(rdsCluster *rds.DBCluster) (*types.AWS, error) {
	parsedARN, err := arn.Parse(aws.StringValue(rdsCluster.DBClusterArn))
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return &types.AWS{
		Region:    parsedARN.Region,
		AccountID: parsedARN.AccountID,
		RDS: types.RDS{
			ClusterID:  aws.StringValue(rdsCluster.DBClusterIdentifier),
			ResourceID: aws.StringValue(rdsCluster.DbClusterResourceId),
			IAMAuth:    aws.BoolValue(rdsCluster.IAMDatabaseAuthenticationEnabled),
		},
	}, nil
}

// MetadataFromRDSProxy creates AWS metadata from the provided RDS proxy.
func MetadataFromRDSProxy(rdsProxy *rds.DBProxy) (*types.AWS, error) {
	parsedARN, err := arn.Parse(aws.StringValue(rdsProxy.DBProxyArn))
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return &types.AWS{
		Region:    parsedARN.Region,
		AccountID: parsedARN.AccountID,
		RDS: types.RDS{
			ProxyID:    aws.StringValue(rdsProxy.DBProxyName),
			ResourceID: strings.TrimPrefix(parsedARN.Resource, "db-proxy:"),
			IAMAuth:    true, // always enabled
		},
	}, nil
}

// engineToProtocol converts RDS instance engine to the database protocol.
func engineToProtocol(engine string) string {
	switch engine {
	case RDSEnginePostgres, RDSEngineAuroraPostgres:
		return defaults.ProtocolPostgres
	case RDSEngineMySQL, RDSEngineAurora, RDSEngineAuroraMySQL:
		return defaults.ProtocolMySQL
	}
	return ""
}

// labelsFromRDSInstance creates database labels for the provided RDS instance.
func labelsFromRDSInstance(rdsInstance *rds.DBInstance, meta *types.AWS) map[string]string {
	labels := rdsTagsToLabels(rdsInstance.TagList)
	labels[types.OriginLabel] = types.OriginCloud
	labels[labelAccountID] = meta.AccountID
	labels[labelRegion] = meta.Region
	labels[labelEngine] = aws.StringValue(rdsInstance.Engine)
	labels[labelEngineVersion] = aws.StringValue(rdsInstance.EngineVersion)
	return labels
}

// labelsFromRDSCluster creates database labels for the provided RDS cluster.
func labelsFromRDSCluster(rdsCluster *rds.DBCluster, meta *types.AWS) map[string]string {
	labels := rdsTagsToLabels(rdsCluster.TagList)
	labels[types.OriginLabel] = types.OriginCloud
	labels[labelAccountID] = meta.AccountID
	labels[labelRegion] = meta.Region
	labels[labelEngine] = aws.StringValue(rdsCluster.Engine)
	labels[labelEngineVersion] = aws.StringValue(rdsCluster.EngineVersion)
	return labels
}

// rdsTagsToLabels converts RDS tags to a labels map.
func rdsTagsToLabels(tags []*rds.Tag) map[string]string {
	labels := make(map[string]string)
	for _, tag := range tags {
		// An AWS tag key has a pattern of "^([\p{L}\p{Z}\p{N}_.:/=+\-@]*)$",
		// which can make invalid labels (for example "aws:cloudformation:stack-id").
		// Omit those to avoid resource creation failures.
		//
		// https://docs.aws.amazon.com/directoryservice/latest/devguide/API_Tag.html
		key := aws.StringValue(tag.Key)
		if types.IsValidLabelKey(key) {
			labels[key] = aws.StringValue(tag.Value)
		} else {
			log.Debugf("Skipping RDS tag %q, not a valid label key.", key)
		}
	}
	return labels
}

// IsRDSClusterSupported checks whether the aurora cluster is supported and logs
// related info if not.
func IsRDSClusterSupported(cluster *rds.DBCluster) bool {
	switch aws.StringValue(cluster.EngineMode) {
	// Aurora Serverless (v1 and v2) does not support IAM authentication
	// https://docs.aws.amazon.com/AmazonRDS/latest/AuroraUserGuide/aurora-serverless.html#aurora-serverless.limitations
	// https://docs.aws.amazon.com/AmazonRDS/latest/AuroraUserGuide/aurora-serverless-2.limitations.html
	case RDSEngineModeServerless:
		return false

	// Aurora MySQL 1.22.2, 1.20.1, 1.19.6, and 5.6.10a only: Parallel query doesn't support AWS Identity and Access Management (IAM) database authentication.
	// https://docs.aws.amazon.com/AmazonRDS/latest/AuroraUserGuide/aurora-mysql-parallel-query.html#aurora-mysql-parallel-query-limitations
	case RDSEngineModeParallelQuery:
		if apiutils.SliceContainsStr([]string{"1.22.2", "1.20.1", "1.19.6", "5.6.10a"}, auroraMySQLVersion(cluster)) {
			return false
		}
	}

	return true
}

// auroraMySQLVersion extracts aurora mysql version from engine version
func auroraMySQLVersion(cluster *rds.DBCluster) string {
	// version guide: https://docs.aws.amazon.com/AmazonRDS/latest/AuroraUserGuide/AuroraMySQL.Updates.Versions.html
	// a list of all the available versions: https://docs.aws.amazon.com/cli/latest/reference/rds/describe-db-engine-versions.html
	//
	// some examples of possible inputs:
	// 5.6.10a
	// 5.7.12
	// 5.6.mysql_aurora.1.22.0
	// 5.6.mysql_aurora.1.22.1
	// 5.6.mysql_aurora.1.22.1.3
	//
	// general format is: <mysql-major-version>.mysql_aurora.<aurora-mysql-version>
	// 5.6.10a and 5.7.12 are "legacy" versions and they are returned as it is
	version := aws.StringValue(cluster.EngineVersion)
	parts := strings.Split(version, ".mysql_aurora.")
	if len(parts) == 2 {
		return parts[1]
	}
	return version
}

const (
	// labelAccountID is the label key containing AWS account ID.
	labelAccountID = "account-id"
	// labelRegion is the label key containing AWS region.
	labelRegion = "region"
	// labelEngine is the label key containing RDS database engine name.
	labelEngine = "engine"
	// labelEngineVersion is the label key containing RDS database engine version.
	labelEngineVersion = "engine-version"
)

const (
	// RDSEngineMySQL is RDS engine name for MySQL instances.
	RDSEngineMySQL = "mysql"
	// RDSEnginePostgres is RDS engine name for Postgres instances.
	RDSEnginePostgres = "postgres"
	// RDSEngineAurora is RDS engine name for Aurora MySQL 5.6 compatible clusters.
	RDSEngineAurora = "aurora"
	// RDSEngineAuroraMySQL is RDS engine name for Aurora MySQL 5.7 compatible clusters.
	RDSEngineAuroraMySQL = "aurora-mysql"
	// RDSEngineAuroraPostgres is RDS engine name for Aurora Postgres clusters.
	RDSEngineAuroraPostgres = "aurora-postgresql"
)

const (
	// RDSEngineModeProvisioned is the RDS engine mode for provisioned Aurora clusters
	RDSEngineModeProvisioned = "provisioned"
	// RDSEngineModeServerless is the RDS engine mode for Aurora Serverless DB clusters
	RDSEngineModeServerless = "serverless"
	// RDSEngineModeParallelQuery is the RDS engine mode for Aurora MySQL clusters with parallel query enabled
	RDSEngineModeParallelQuery = "parallelquery"
	// RDSEngineModeGlobal is the RDS engine mode for Aurora Global databases
	RDSEngineModeGlobal = "global"
	// RDSEngineModeMultiMaster is the RDS engine mode for Multi-master clusters
	RDSEngineModeMultiMaster = "multimaster"
)
