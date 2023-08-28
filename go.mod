module github.com/gravitational/teleport

go 1.20

require (
	cloud.google.com/go/compute v1.23.0
	cloud.google.com/go/compute/metadata v0.2.3
	cloud.google.com/go/container v1.25.0
	cloud.google.com/go/firestore v1.12.0
	cloud.google.com/go/iam v1.1.2
	cloud.google.com/go/kms v1.15.1
	cloud.google.com/go/storage v1.32.0
	github.com/Azure/azure-sdk-for-go/sdk/azcore v1.7.1
	github.com/Azure/azure-sdk-for-go/sdk/azidentity v1.3.1
	github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute/v3 v3.0.1
	github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/containerservice/armcontainerservice/v2 v2.4.0
	github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/mysql/armmysql v1.1.1
	github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/mysql/armmysqlflexibleservers v1.1.1
	github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/postgresql/armpostgresql v1.1.1
	github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/postgresql/armpostgresqlflexibleservers v1.1.0
	github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/redis/armredis/v2 v2.3.0
	github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/redisenterprise/armredisenterprise v1.1.1
	github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/sql/armsql v1.1.0
	github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/subscription/armsubscription v1.1.0
	github.com/Azure/azure-sdk-for-go/sdk/storage/azblob v1.1.0
	github.com/Azure/go-ansiterm v0.0.0-20210617225240-d185dfc1b5a1
	github.com/ClickHouse/ch-go v0.58.2
	github.com/ClickHouse/clickhouse-go/v2 v2.13.3
	github.com/HdrHistogram/hdrhistogram-go v1.1.2
	github.com/Microsoft/go-winio v0.6.1
	github.com/ThalesIgnite/crypto11 v1.2.5
	github.com/alecthomas/kingpin/v2 v2.3.2 // replaced
	github.com/alicebob/miniredis/v2 v2.30.5
	github.com/andybalholm/brotli v1.0.5
	github.com/aquasecurity/libbpfgo v0.4.5-libbpf-1.0.1
	github.com/armon/go-radix v1.0.0
	github.com/aws/aws-sdk-go v1.44.333
	github.com/aws/aws-sdk-go-v2 v1.21.0
	github.com/aws/aws-sdk-go-v2/config v1.18.37
	github.com/aws/aws-sdk-go-v2/credentials v1.13.35
	github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue v1.10.39
	github.com/aws/aws-sdk-go-v2/feature/ec2/imds v1.13.11
	github.com/aws/aws-sdk-go-v2/feature/s3/manager v1.11.81
	github.com/aws/aws-sdk-go-v2/service/athena v1.31.6
	github.com/aws/aws-sdk-go-v2/service/dynamodb v1.21.5
	github.com/aws/aws-sdk-go-v2/service/ec2 v1.115.0
	github.com/aws/aws-sdk-go-v2/service/ec2instanceconnect v1.16.5
	github.com/aws/aws-sdk-go-v2/service/ecs v1.29.6
	github.com/aws/aws-sdk-go-v2/service/glue v1.62.0
	github.com/aws/aws-sdk-go-v2/service/iam v1.22.5
	github.com/aws/aws-sdk-go-v2/service/rds v1.53.0
	github.com/aws/aws-sdk-go-v2/service/s3 v1.38.5
	github.com/aws/aws-sdk-go-v2/service/sns v1.21.5
	github.com/aws/aws-sdk-go-v2/service/sqs v1.24.5
	github.com/aws/aws-sdk-go-v2/service/sts v1.21.5
	github.com/aws/aws-sigv4-auth-cassandra-gocql-driver-plugin v0.0.0-20220331165046-e4d000c0d6a6
	github.com/aws/smithy-go v1.14.2
	github.com/beevik/etree v1.2.0
	github.com/bufbuild/connect-go v1.10.0
	github.com/buildkite/bintest/v3 v3.1.1
	github.com/coreos/go-oidc v2.2.1+incompatible // replaced
	github.com/coreos/go-semver v0.3.1
	github.com/creack/pty v1.1.18
	github.com/crewjam/saml v0.4.14-0.20230420111643-34930b26d33b
	github.com/datastax/go-cassandra-native-protocol v0.0.0-20220706104457-5e8aad05cf90
	github.com/digitorus/pkcs7 v0.0.0-20230818184609-3a137a874352
	github.com/dustin/go-humanize v1.0.1
	github.com/elastic/go-elasticsearch/v8 v8.9.0
	github.com/flynn/hid v0.0.0-20190502022136-f1b9b6cc019a
	github.com/flynn/u2f v0.0.0-20180613185708-15554eb68e5d
	github.com/fsouza/fake-gcs-server v1.47.4
	github.com/fxamacker/cbor/v2 v2.5.0
	github.com/ghodss/yaml v1.0.0
	github.com/gizak/termui/v3 v3.1.0
	github.com/go-ldap/ldap/v3 v3.4.5
	github.com/go-logr/logr v1.2.4
	github.com/go-mysql-org/go-mysql v1.5.0 // replaced
	github.com/go-piv/piv-go v1.11.0
	github.com/go-resty/resty/v2 v2.7.0
	github.com/go-webauthn/webauthn v0.8.6
	github.com/gocql/gocql v1.6.0
	github.com/gofrs/flock v0.8.1
	github.com/gogo/protobuf v1.3.2 // replaced
	github.com/golang-jwt/jwt/v4 v4.5.0
	github.com/google/btree v1.1.2
	github.com/google/go-attestation v0.5.0
	github.com/google/go-cmp v0.5.9
	github.com/google/go-querystring v1.1.0
	github.com/google/go-tpm-tools v0.4.0
	github.com/google/shlex v0.0.0-20191202100458-e7afc7fbc510
	github.com/google/uuid v1.3.1
	github.com/googleapis/gax-go/v2 v2.12.0
	github.com/gorilla/websocket v1.5.0
	github.com/gravitational/configure v0.0.0-20180808141939-c3428bd84c23
	github.com/gravitational/form v0.0.0-20151109031454-c4048f792f70
	github.com/gravitational/license v0.0.0-20210218173955-6d8fb49b117a
	github.com/gravitational/oxy v0.0.0-20221029012416-9fbf4c444680
	github.com/gravitational/roundtrip v1.0.2
	github.com/gravitational/teleport/api v0.0.0
	github.com/gravitational/trace v1.3.1
	github.com/gravitational/ttlmap v0.0.0-20171116003245-91fd36b9004c
	github.com/grpc-ecosystem/go-grpc-middleware/providers/openmetrics/v2 v2.0.0-rc.3
	github.com/hashicorp/go-version v1.6.0
	github.com/hashicorp/golang-lru/v2 v2.0.6
	github.com/icza/mjpeg v0.0.0-20220812133530-f79265a232f2
	github.com/jackc/pgconn v1.14.1
	github.com/jackc/pgerrcode v0.0.0-20220416144525-469b46aa5efa
	github.com/jackc/pgproto3/v2 v2.3.2
	github.com/jackc/pgtype v1.14.0
	github.com/jackc/pgx/v4 v4.18.1
	github.com/jackc/pgx/v5 v5.4.3
	github.com/jcmturner/gokrb5/v8 v8.4.4
	github.com/johannesboyne/gofakes3 v0.0.0-20210217223559-02ffa763be97
	github.com/jonboulle/clockwork v0.4.0
	github.com/joshlf/go-acl v0.0.0-20200411065538-eae00ae38531
	github.com/json-iterator/go v1.1.12
	github.com/julienschmidt/httprouter v1.3.0 // replaced
	github.com/keys-pub/go-libfido2 v1.5.3-0.20220306005615-8ab03fb1ec27 // replaced
	github.com/kyroy/kdtree v0.0.0-20200419114247-70830f883f1d
	github.com/mailgun/holster/v3 v3.16.2
	github.com/mailgun/lemma v0.0.0-20170619173223-4214099fb348
	github.com/mailgun/timetools v0.0.0-20170619190023-f3a7b8ffff47
	github.com/mailgun/ttlmap v0.0.0-20170619185759-c1c17f74874f
	github.com/mattn/go-sqlite3 v1.14.17
	github.com/mdlayher/netlink v1.7.2
	github.com/microsoft/go-mssqldb v0.0.0-00010101000000-000000000000 // replaced
	github.com/miekg/pkcs11 v1.1.1
	github.com/mitchellh/mapstructure v1.5.0
	github.com/moby/term v0.5.0
	github.com/okta/okta-sdk-golang/v2 v2.20.0
	github.com/opensearch-project/opensearch-go/v2 v2.3.0
	github.com/pavlo-v-chernykh/keystore-go/v4 v4.4.1
	github.com/pelletier/go-toml v1.9.5
	github.com/pkg/sftp v1.13.6
	github.com/pquerna/otp v1.4.0
	github.com/prometheus/client_golang v1.16.0
	github.com/prometheus/client_model v0.4.0
	github.com/prometheus/common v0.44.0
	github.com/redis/go-redis/v9 v9.0.2 // replaced
	github.com/russellhaering/gosaml2 v0.9.1
	github.com/russellhaering/goxmldsig v1.4.0
	github.com/sashabaranov/go-openai v1.14.2
	github.com/schollz/progressbar/v3 v3.13.1
	github.com/segmentio/parquet-go v0.0.0-20230622230624-510764ae9e80
	github.com/sethvargo/go-diceware v0.3.0
	github.com/sijms/go-ora/v2 v2.7.9
	github.com/sirupsen/logrus v1.9.3
	github.com/snowflakedb/gosnowflake v1.6.24
	github.com/spf13/cobra v1.7.0
	github.com/stretchr/testify v1.8.4
	github.com/tiktoken-go/tokenizer v0.1.0
	github.com/ucarion/urlpath v0.0.0-20200424170820-7ccc79b76bbb
	github.com/vulcand/predicate v1.2.0 // replaced
	go.etcd.io/etcd/api/v3 v3.5.9
	go.etcd.io/etcd/client/v3 v3.5.9
	go.mongodb.org/mongo-driver v1.13.0-prerelease.0.20230726045955-5ee10b94cc66
	go.opentelemetry.io/contrib/instrumentation/github.com/aws/aws-sdk-go-v2/otelaws v0.43.0
	go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc v0.43.0
	go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp v0.43.0
	go.opentelemetry.io/otel v1.17.0
	go.opentelemetry.io/otel/exporters/otlp/otlptrace v1.17.0
	go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc v1.17.0
	go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp v1.17.0
	go.opentelemetry.io/otel/sdk v1.17.0
	go.opentelemetry.io/otel/trace v1.17.0
	go.opentelemetry.io/proto/otlp v1.0.0
	golang.org/x/crypto v0.12.0
	golang.org/x/exp v0.0.0-20230811145659-89c5cff77bcb
	golang.org/x/mod v0.12.0
	golang.org/x/net v0.14.0
	golang.org/x/oauth2 v0.11.0
	golang.org/x/sync v0.3.0
	golang.org/x/sys v0.11.0
	golang.org/x/term v0.11.0
	golang.org/x/text v0.12.0
	golang.org/x/time v0.3.0
	google.golang.org/api v0.138.0
	google.golang.org/genproto/googleapis/rpc v0.0.0-20230807174057-1744710a1577
	google.golang.org/grpc v1.57.0
	google.golang.org/grpc/cmd/protoc-gen-go-grpc v1.3.0
	google.golang.org/protobuf v1.31.0
	gopkg.in/check.v1 v1.0.0-20201130134442-10cb98267c6c
	gopkg.in/dnaeon/go-vcr.v3 v3.1.2
	gopkg.in/ini.v1 v1.67.0
	gopkg.in/square/go-jose.v2 v2.6.0
	gopkg.in/yaml.v2 v2.4.0
	gopkg.in/yaml.v3 v3.0.1
	k8s.io/api v0.28.1
	k8s.io/apiextensions-apiserver v0.28.1
	k8s.io/apimachinery v0.28.1
	k8s.io/apiserver v0.28.1
	k8s.io/cli-runtime v0.28.1
	k8s.io/client-go v0.28.1
	k8s.io/component-base v0.28.1
	k8s.io/klog/v2 v2.100.1
	k8s.io/kubectl v0.28.1
	sigs.k8s.io/controller-runtime v0.16.0
	sigs.k8s.io/controller-tools v0.13.0
	sigs.k8s.io/yaml v1.3.0
	software.sslmate.com/src/go-pkcs12 v0.2.1
)

// Indirect mailgun dependencies.
// Updating causes breaking changes.
require (
	github.com/mailgun/metrics v0.0.0-20150124003306-2b3c4565aafd // indirect
	github.com/mailgun/minheap v0.0.0-20170619185613-3dbe6c6bf55f // indirect
)

require (
	cloud.google.com/go v0.110.6 // indirect
	cloud.google.com/go/longrunning v0.5.1 // indirect
	cloud.google.com/go/pubsub v1.33.0 // indirect
	github.com/99designs/go-keychain v0.0.0-20191008050251-8e49817e8af4 // indirect
	github.com/99designs/keyring v1.2.2 // indirect
	github.com/Azure/azure-sdk-for-go/sdk/internal v1.3.0 // indirect
	github.com/Azure/go-ntlmssp v0.0.0-20221128193559-754e69321358 // indirect
	github.com/AzureAD/microsoft-authentication-library-for-go v1.1.1 // indirect
	github.com/BurntSushi/toml v1.1.0 // indirect
	github.com/JohnCGriffin/overflow v0.0.0-20211019200055-46fa312c352c // indirect
	github.com/MakeNowJust/heredoc v1.0.0 // indirect
	github.com/Masterminds/semver/v3 v3.2.0 // indirect
	github.com/alecthomas/units v0.0.0-20211218093645-b94a6e3cc137 // indirect
	github.com/alicebob/gopher-json v0.0.0-20200520072559-a9ecdc9d1d3a // indirect
	github.com/apache/arrow/go/v12 v12.0.1 // indirect
	github.com/apache/thrift v0.16.0 // indirect
	github.com/aws/aws-sdk-go-v2/aws/protocol/eventstream v1.4.13 // indirect
	github.com/aws/aws-sdk-go-v2/internal/configsources v1.1.41 // indirect
	github.com/aws/aws-sdk-go-v2/internal/endpoints/v2 v2.4.35 // indirect
	github.com/aws/aws-sdk-go-v2/internal/ini v1.3.42 // indirect
	github.com/aws/aws-sdk-go-v2/internal/v4a v1.1.4 // indirect
	github.com/aws/aws-sdk-go-v2/service/dynamodbstreams v1.15.5 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/accept-encoding v1.9.14 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/checksum v1.1.36 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/endpoint-discovery v1.7.35 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/presigned-url v1.9.35 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/s3shared v1.15.4 // indirect
	github.com/aws/aws-sdk-go-v2/service/sso v1.13.5 // indirect
	github.com/aws/aws-sdk-go-v2/service/ssooidc v1.15.5 // indirect
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/blang/semver/v4 v4.0.0 // indirect
	github.com/boombuler/barcode v1.0.1 // indirect
	github.com/cenkalti/backoff/v4 v4.2.1 // indirect
	github.com/cespare/xxhash/v2 v2.2.0 // indirect
	github.com/chai2010/gettext-go v1.0.2 // indirect
	github.com/coreos/go-systemd/v22 v22.5.0 // indirect
	github.com/coreos/pkg v0.0.0-20220810130054-c7d1c02cb6cf // indirect
	github.com/crewjam/httperr v0.2.0 // indirect
	github.com/danieljoos/wincred v1.1.2 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/daviddengcn/go-colortext v1.0.0 // indirect
	github.com/dgryski/go-rendezvous v0.0.0-20200823014737-9f7001d12a5f // indirect
	github.com/dlclark/regexp2 v1.9.0 // indirect
	github.com/dmarkham/enumer v1.5.8 // indirect
	github.com/docker/distribution v2.8.2+incompatible // indirect
	github.com/dvsekhvalnov/jose2go v1.5.0 // indirect
	github.com/elastic/elastic-transport-go/v8 v8.3.0 // indirect
	github.com/emicklei/go-restful/v3 v3.9.0 // indirect
	github.com/evanphx/json-patch v5.6.0+incompatible // indirect
	github.com/evanphx/json-patch/v5 v5.6.0 // indirect
	github.com/exponent-io/jsonpath v0.0.0-20151013193312-d6023ce2651d // indirect
	github.com/fatih/camelcase v1.0.0 // indirect
	github.com/felixge/httpsnoop v1.0.3 // indirect
	github.com/form3tech-oss/jwt-go v3.2.5+incompatible // indirect
	github.com/fsnotify/fsnotify v1.6.0 // indirect
	github.com/fvbommel/sortorder v1.1.0 // indirect
	github.com/gabriel-vasile/mimetype v1.4.2 // indirect
	github.com/go-asn1-ber/asn1-ber v1.5.4 // indirect
	github.com/go-errors/errors v1.4.2 // indirect
	github.com/go-faster/city v1.0.1 // indirect
	github.com/go-faster/errors v0.6.1 // indirect
	github.com/go-jose/go-jose/v3 v3.0.0 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/go-logr/zapr v1.2.4 // indirect
	github.com/go-openapi/jsonpointer v0.19.6 // indirect
	github.com/go-openapi/jsonreference v0.20.2 // indirect
	github.com/go-openapi/swag v0.22.3 // indirect
	github.com/go-webauthn/x v0.1.4 // indirect
	github.com/gobuffalo/flect v1.0.2 // indirect
	github.com/goccy/go-json v0.10.0 // indirect
	github.com/godbus/dbus v0.0.0-20190726142602-4481cbc300e2 // indirect
	github.com/golang-jwt/jwt/v5 v5.0.0 // indirect
	github.com/golang-sql/civil v0.0.0-20190719163853-cb61b32ac6fe // indirect
	github.com/golang-sql/sqlexp v0.1.0 // indirect
	github.com/golang/groupcache v0.0.0-20210331224755-41bb18bfe9da // indirect
	github.com/golang/protobuf v1.5.3 // indirect
	github.com/golang/snappy v0.0.4 // indirect
	github.com/google/certificate-transparency-go v1.1.2 // indirect
	github.com/google/flatbuffers v23.1.21+incompatible // indirect
	github.com/google/gnostic-models v0.6.8 // indirect
	github.com/google/go-tpm v0.9.0 // indirect
	github.com/google/go-tspi v0.3.0 // indirect
	github.com/google/gofuzz v1.2.0 // indirect
	github.com/google/renameio/v2 v2.0.0 // indirect
	github.com/google/s2a-go v0.1.5 // indirect
	github.com/googleapis/enterprise-certificate-proxy v0.2.5 // indirect
	github.com/gorilla/handlers v1.5.1 // indirect
	github.com/gorilla/mux v1.8.0 // indirect
	github.com/gregjones/httpcache v0.0.0-20180305231024-9cad4c3443a7 // indirect
	github.com/grpc-ecosystem/go-grpc-middleware/v2 v2.0.0-rc.2.0.20220308023801-e4a6915ea237 // indirect
	github.com/grpc-ecosystem/grpc-gateway/v2 v2.16.0 // indirect
	github.com/gsterjov/go-libsecret v0.0.0-20161001094733-a6f4afe4910c // indirect
	github.com/hailocab/go-hostpool v0.0.0-20160125115350-e80d13ce29ed // indirect
	github.com/hashicorp/go-uuid v1.0.3 // indirect
	github.com/imdario/mergo v0.3.13 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/jackc/chunkreader/v2 v2.0.1 // indirect
	github.com/jackc/pgio v1.0.0 // indirect
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20221227161230-091c0ba34f0a // indirect
	github.com/jackc/puddle/v2 v2.2.1 // indirect
	github.com/jcmturner/aescts/v2 v2.0.0 // indirect
	github.com/jcmturner/dnsutils/v2 v2.0.0 // indirect
	github.com/jcmturner/gofork v1.7.6 // indirect
	github.com/jcmturner/goidentity/v6 v6.0.1 // indirect
	github.com/jcmturner/rpc/v2 v2.0.3 // indirect
	github.com/jmespath/go-jmespath v0.4.0 // indirect
	github.com/josharian/intern v1.0.0 // indirect
	github.com/josharian/native v1.1.0 // indirect
	github.com/joshlf/testutil v0.0.0-20170608050642-b5d8aa79d93d // indirect
	github.com/kelseyhightower/envconfig v1.4.0 // indirect
	github.com/klauspost/asmfmt v1.3.2 // indirect
	github.com/klauspost/compress v1.16.7 // indirect
	github.com/klauspost/cpuid/v2 v2.2.5 // indirect
	github.com/kr/fs v0.1.0 // indirect
	github.com/kr/pretty v0.3.1 // indirect
	github.com/kr/text v0.2.0 // indirect
	github.com/kylelemons/godebug v1.1.0 // indirect
	github.com/kyroy/priority-queue v0.0.0-20180327160706-6e21825e7e0c // indirect
	github.com/lib/pq v1.10.4 // indirect
	github.com/liggitt/tabwriter v0.0.0-20181228230101-89fcab3d43de // indirect
	github.com/lithammer/dedent v1.1.0 // indirect
	github.com/mailru/easyjson v0.7.7 // indirect
	github.com/mattermost/xml-roundtrip-validator v0.1.0 // indirect
	github.com/mattn/go-colorable v0.1.13 // indirect
	github.com/mattn/go-isatty v0.0.17 // indirect
	github.com/mattn/go-runewidth v0.0.14 // indirect
	github.com/matttproud/golang_protobuf_extensions v1.0.4 // indirect
	github.com/mdlayher/socket v0.4.1 // indirect
	github.com/minio/asm2plan9s v0.0.0-20200509001527-cdd76441f9d8 // indirect
	github.com/minio/c2goasm v0.0.0-20190812172519-36a3d3bbc4f3 // indirect
	github.com/mitchellh/colorstring v0.0.0-20190213212951-d06e56a500db // indirect
	github.com/mitchellh/go-wordwrap v1.0.1 // indirect
	github.com/moby/spdystream v0.2.0 // indirect
	github.com/modern-go/concurrent v0.0.0-20180306012644-bacd9c7ef1dd // indirect
	github.com/modern-go/reflect2 v1.0.2 // indirect
	github.com/monochromegane/go-gitignore v0.0.0-20200626010858-205db1a8cc00 // indirect
	github.com/montanaflynn/stats v0.7.0 // indirect
	github.com/mtibben/percent v0.2.1 // indirect
	github.com/munnerz/goautoneg v0.0.0-20191010083416-a7dc8b61c822 // indirect
	github.com/mxk/go-flowrate v0.0.0-20140419014527-cca7078d478f // indirect
	github.com/nsf/termbox-go v1.1.1 // indirect
	github.com/olekukonko/tablewriter v0.0.5 // indirect
	github.com/opencontainers/go-digest v1.0.0 // indirect
	github.com/pascaldekloe/name v1.0.1 // indirect
	github.com/patrickmn/go-cache v0.0.0-20180815053127-5633e0862627 // indirect
	github.com/paulmach/orb v0.10.0 // indirect
	github.com/peterbourgon/diskv v2.0.1+incompatible // indirect
	github.com/petermattis/goid v0.0.0-20180202154549-b0b1615b78e5 // indirect
	github.com/pierrec/lz4/v4 v4.1.18 // indirect
	github.com/pingcap/errors v0.11.5-0.20201126102027-b0a155152ca3 // indirect
	github.com/pkg/browser v0.0.0-20210911075715-681adbf594b8 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/pkg/xattr v0.4.9 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/pquerna/cachecontrol v0.1.0 // indirect
	github.com/prometheus/procfs v0.10.1 // indirect
	github.com/rivo/uniseg v0.4.3 // indirect
	github.com/rogpeppe/go-internal v1.11.0 // indirect
	github.com/rs/zerolog v1.28.0 // indirect
	github.com/russross/blackfriday/v2 v2.1.0 // indirect
	github.com/ryszard/goskiplist v0.0.0-20150312221310-2dfbae5fcf46 // indirect
	github.com/sasha-s/go-deadlock v0.0.0-20180226215254-237a9547c8a5 // indirect
	github.com/segmentio/asm v1.2.0 // indirect
	github.com/segmentio/encoding v0.3.5 // indirect
	github.com/shabbyrobe/gocovmerge v0.0.0-20190829150210-3e036491d500 // indirect
	github.com/shopspring/decimal v1.3.1 // indirect
	github.com/siddontang/go v0.0.0-20180604090527-bdc77568d726 // indirect
	github.com/siddontang/go-log v0.0.0-20180807004314-8d05993dda07 // indirect
	github.com/spf13/pflag v1.0.5 // indirect
	github.com/stretchr/objx v0.5.0 // indirect
	github.com/thales-e-security/pool v0.0.2 // indirect
	github.com/x448/float16 v0.8.4 // indirect
	github.com/xdg-go/pbkdf2 v1.0.0 // indirect
	github.com/xdg-go/scram v1.1.2 // indirect
	github.com/xdg-go/stringprep v1.0.4 // indirect
	github.com/xhit/go-str2duration/v2 v2.1.0 // indirect
	github.com/xlab/treeprint v1.2.0 // indirect
	github.com/youmark/pkcs8 v0.0.0-20181117223130-1be2e3e5546d // indirect
	github.com/yuin/gopher-lua v1.1.0 // indirect
	github.com/zeebo/xxh3 v1.0.2 // indirect
	go.etcd.io/etcd/client/pkg/v3 v3.5.9 // indirect
	go.opencensus.io v0.24.0 // indirect
	go.opentelemetry.io/otel/metric v1.17.0 // indirect
	go.starlark.net v0.0.0-20230525235612-a134d8f9ddca // indirect
	go.uber.org/atomic v1.11.0 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	go.uber.org/zap v1.25.0 // indirect
	golang.org/x/tools v0.12.0 // indirect
	golang.org/x/xerrors v0.0.0-20220907171357-04be3eba64a2 // indirect
	gomodules.xyz/jsonpatch/v2 v2.4.0 // indirect
	google.golang.org/appengine v1.6.7 // indirect
	google.golang.org/genproto v0.0.0-20230803162519-f966b187b2e5 // indirect
	google.golang.org/genproto/googleapis/api v0.0.0-20230803162519-f966b187b2e5 // indirect
	gopkg.in/inf.v0 v0.9.1 // indirect
	gopkg.in/mgo.v2 v2.0.0-20190816093944-a6b53ec6cb22 // indirect
	k8s.io/component-helpers v0.28.1 // indirect
	k8s.io/kube-openapi v0.0.0-20230717233707-2695361300d9 // indirect
	k8s.io/metrics v0.28.1 // indirect
	k8s.io/utils v0.0.0-20230406110748-d93618cff8a2 // indirect
	sigs.k8s.io/json v0.0.0-20221116044647-bc3834ca7abd // indirect
	sigs.k8s.io/kustomize/api v0.13.5-0.20230601165947-6ce0bf390ce3 // indirect
	sigs.k8s.io/kustomize/kustomize/v5 v5.0.4-0.20230601165947-6ce0bf390ce3 // indirect
	sigs.k8s.io/kustomize/kyaml v0.14.3-0.20230601165947-6ce0bf390ce3 // indirect
	sigs.k8s.io/structured-merge-diff/v4 v4.2.3 // indirect
)

// Update also `ignore` in .github/dependabot.yml.
replace (
	github.com/alecthomas/kingpin/v2 => github.com/gravitational/kingpin/v2 v2.1.11-0.20230515143221-4ec6b70ecd33
	github.com/coreos/go-oidc => github.com/gravitational/go-oidc v0.1.0
	github.com/datastax/go-cassandra-native-protocol => github.com/gravitational/go-cassandra-native-protocol v0.0.0-20221005103706-b9e66c056e90
	github.com/go-mysql-org/go-mysql => github.com/gravitational/go-mysql v1.5.0-teleport.1
	github.com/gogo/protobuf => github.com/gravitational/protobuf v1.3.2-teleport.1
	github.com/gravitational/teleport/api => ./api
	github.com/julienschmidt/httprouter => github.com/gravitational/httprouter v1.3.1-0.20220408074523-c876c5e705a5
	github.com/keys-pub/go-libfido2 => github.com/gravitational/go-libfido2 v1.5.3-0.20230728202351-0b44d4f35e28
	github.com/microsoft/go-mssqldb => github.com/gravitational/go-mssqldb v0.11.1-0.20230331180905-0f76f1751cd3
	// replace module github.com/moby/spdystream until https://github.com/moby/spdystream/pull/91 merges and deps are updated
	// otherwise tests fail with a data race detection.
	github.com/moby/spdystream => github.com/gravitational/spdystream v0.0.0-20230512133543-4e46862ca9bf
	github.com/redis/go-redis/v9 => github.com/gravitational/redis/v9 v9.0.2-teleport.1
	github.com/sijms/go-ora/v2 => github.com/gravitational/go-ora/v2 v2.0.0-20230821114616-e2a9f1131a46
	github.com/vulcand/predicate => github.com/gravitational/predicate v1.3.1
)
