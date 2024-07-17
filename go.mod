module github.com/trufflesecurity/trufflehog/v3

go 1.22.0

replace github.com/jpillora/overseer => github.com/trufflesecurity/overseer v1.2.7

replace github.com/snowflakedb/gosnowflake => github.com/trufflesecurity/gosnowflake v0.0.1

// Coinbase archived this library and it has some vulnerable dependencies so we've forked.
replace github.com/coinbase/waas-client-library-go => github.com/trufflesecurity/waas-client-library-go v1.0.9

// github.com/mholt/archiver/v4 is pinned to a specific commit hash. That commit depends on STARRY-S/zip 0.1.0
// specifically - future tags won't build. So we have to pin STARRY-S/zip@v0.1.0
replace github.com/STARRY-S/zip => github.com/STARRY-S/zip v0.1.0

require (
	cloud.google.com/go/secretmanager v1.13.4
	cloud.google.com/go/storage v1.43.0
	github.com/Azure/go-autorest/autorest/azure/auth v0.5.13
	github.com/AzureAD/microsoft-authentication-library-for-go v1.2.2
	github.com/BobuSumisu/aho-corasick v1.0.3
	github.com/TheZeroSlave/zapsentry v1.23.0
	github.com/adrg/strutil v0.3.1
	github.com/alecthomas/kingpin/v2 v2.4.0
	github.com/aws/aws-sdk-go v1.54.19
	github.com/aymanbagabas/go-osc52 v1.2.2
	github.com/bill-rich/go-syslog v0.0.0-20220413021637-49edb52a574c
	github.com/bitfinexcom/bitfinex-api-go v0.0.0-20210608095005-9e0b26f200fb
	github.com/bradleyfalzon/ghinstallation/v2 v2.11.0
	github.com/brianvoe/gofakeit/v7 v7.0.4
	github.com/charmbracelet/bubbles v0.18.0
	github.com/charmbracelet/bubbletea v0.26.6
	github.com/charmbracelet/glamour v0.7.0
	github.com/charmbracelet/lipgloss v0.10.0
	github.com/coinbase/waas-client-library-go v1.0.8
	github.com/couchbase/gocb/v2 v2.9.0
	github.com/crewjam/rfc5424 v0.1.0
	github.com/elastic/go-elasticsearch/v8 v8.14.0
	github.com/envoyproxy/protoc-gen-validate v1.0.4
	github.com/fatih/color v1.17.0
	github.com/felixge/fgprof v0.9.4
	github.com/gabriel-vasile/mimetype v1.4.4
	github.com/getsentry/sentry-go v0.28.1
	github.com/go-errors/errors v1.5.1
	github.com/go-git/go-git/v5 v5.12.0
	github.com/go-ldap/ldap/v3 v3.4.8
	github.com/go-logr/logr v1.4.2
	github.com/go-logr/zapr v1.3.0
	github.com/go-redis/redis v6.15.9+incompatible
	github.com/go-sql-driver/mysql v1.8.1
	github.com/gobwas/glob v0.2.3
	github.com/golang-jwt/jwt v3.2.2+incompatible
	github.com/golang-jwt/jwt/v4 v4.5.0
	github.com/google/go-cmp v0.6.0
	github.com/google/go-containerregistry v0.20.1
	github.com/google/go-github/v62 v62.0.0
	github.com/google/uuid v1.6.0
	github.com/googleapis/gax-go/v2 v2.12.5
	github.com/hashicorp/go-retryablehttp v0.7.7
	github.com/hashicorp/golang-lru/v2 v2.0.7
	github.com/jlaffaye/ftp v0.2.0
	github.com/joho/godotenv v1.5.1
	github.com/jpillora/overseer v1.1.6
	github.com/kylelemons/godebug v1.1.0
	github.com/lib/pq v1.10.9
	github.com/lrstanley/bubblezone v0.0.0-20240125042004-b7bafc493195
	github.com/marusama/semaphore/v2 v2.5.0
	github.com/mattn/go-isatty v0.0.20
	github.com/mholt/archiver/v4 v4.0.0-alpha.8.0.20240408183022-de08bfa4c558
	github.com/microsoft/go-mssqldb v1.7.2
	github.com/mitchellh/go-ps v1.0.0
	github.com/muesli/reflow v0.3.0
	github.com/patrickmn/go-cache v2.1.0+incompatible
	github.com/paulbellamy/ratecounter v0.2.0
	github.com/pkg/errors v0.9.1
	github.com/prometheus/client_golang v1.19.1
	github.com/rabbitmq/amqp091-go v1.10.0
	github.com/sassoftware/go-rpmutils v0.4.0
	github.com/sergi/go-diff v1.3.2-0.20230802210424-5b0b94c5c0d3
	github.com/shuheiktgw/go-travis v0.3.1
	github.com/snowflakedb/gosnowflake v1.10.1
	github.com/stretchr/testify v1.9.0
	github.com/tailscale/depaware v0.0.0-20210622194025-720c4b409502
	github.com/testcontainers/testcontainers-go v0.32.0
	github.com/testcontainers/testcontainers-go/modules/elasticsearch v0.32.0
	github.com/testcontainers/testcontainers-go/modules/mongodb v0.32.0
	github.com/testcontainers/testcontainers-go/modules/mssql v0.32.0
	github.com/testcontainers/testcontainers-go/modules/mysql v0.32.0
	github.com/testcontainers/testcontainers-go/modules/postgres v0.32.0
	github.com/trufflesecurity/disk-buffer-reader v0.2.1
	github.com/wasilibs/go-re2 v1.6.0
	github.com/xanzy/go-gitlab v0.107.0
	go.mongodb.org/mongo-driver v1.16.0
	go.uber.org/mock v0.4.0
	go.uber.org/zap v1.27.0
	golang.org/x/crypto v0.25.0
	golang.org/x/exp v0.0.0-20240716160929-1d5bc16f04a8
	golang.org/x/net v0.27.0
	golang.org/x/oauth2 v0.21.0
	golang.org/x/sync v0.7.0
	golang.org/x/text v0.16.0
	google.golang.org/api v0.188.0
	google.golang.org/protobuf v1.34.2
	gopkg.in/h2non/gock.v1 v1.1.2
	pault.ag/go/debian v0.16.0
	pgregory.net/rapid v1.1.0
	sigs.k8s.io/yaml v1.4.0
)

require (
	cloud.google.com/go v0.115.0 // indirect
	cloud.google.com/go/auth v0.7.0 // indirect
	cloud.google.com/go/auth/oauth2adapt v0.2.2 // indirect
	cloud.google.com/go/compute/metadata v0.4.0 // indirect
	cloud.google.com/go/iam v1.1.10 // indirect
	cloud.google.com/go/longrunning v0.5.9 // indirect
	dario.cat/mergo v1.0.0 // indirect
	filippo.io/edwards25519 v1.1.0 // indirect
	github.com/99designs/go-keychain v0.0.0-20191008050251-8e49817e8af4 // indirect
	github.com/99designs/keyring v1.2.2 // indirect
	github.com/Azure/go-ansiterm v0.0.0-20210617225240-d185dfc1b5a1 // indirect
	github.com/Azure/go-autorest v14.2.0+incompatible // indirect
	github.com/Azure/go-autorest/autorest v0.11.28 // indirect
	github.com/Azure/go-autorest/autorest/adal v0.9.22 // indirect
	github.com/Azure/go-autorest/autorest/azure/cli v0.4.6 // indirect
	github.com/Azure/go-autorest/autorest/date v0.3.0 // indirect
	github.com/Azure/go-autorest/logger v0.2.1 // indirect
	github.com/Azure/go-autorest/tracing v0.6.0 // indirect
	github.com/Azure/go-ntlmssp v0.0.0-20221128193559-754e69321358 // indirect
	github.com/DataDog/zstd v1.5.5 // indirect
	github.com/JohnCGriffin/overflow v0.0.0-20211019200055-46fa312c352c // indirect
	github.com/Microsoft/go-winio v0.6.2 // indirect
	github.com/Microsoft/hcsshim v0.11.5 // indirect
	github.com/ProtonMail/go-crypto v1.0.0 // indirect
	github.com/STARRY-S/zip v0.1.0 // indirect
	github.com/alecthomas/chroma/v2 v2.8.0 // indirect
	github.com/alecthomas/units v0.0.0-20211218093645-b94a6e3cc137 // indirect
	github.com/andybalholm/brotli v1.1.0 // indirect
	github.com/apache/arrow/go/v14 v14.0.2 // indirect
	github.com/atotto/clipboard v0.1.4 // indirect
	github.com/aws/smithy-go v1.20.1 // indirect
	github.com/aymanbagabas/go-osc52/v2 v2.0.1 // indirect
	github.com/aymerick/douceur v0.2.0 // indirect
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/bodgit/plumbing v1.3.0 // indirect
	github.com/bodgit/sevenzip v1.4.5 // indirect
	github.com/bodgit/windows v1.0.1 // indirect
	github.com/cenkalti/backoff/v4 v4.2.1 // indirect
	github.com/cespare/xxhash/v2 v2.2.0 // indirect
	github.com/charmbracelet/x/ansi v0.1.2 // indirect
	github.com/charmbracelet/x/input v0.1.0 // indirect
	github.com/charmbracelet/x/term v0.1.1 // indirect
	github.com/charmbracelet/x/windows v0.1.0 // indirect
	github.com/cloudflare/circl v1.3.8 // indirect
	github.com/containerd/containerd v1.7.18 // indirect
	github.com/containerd/errdefs v0.1.0 // indirect
	github.com/containerd/log v0.1.0 // indirect
	github.com/containerd/stargz-snapshotter/estargz v0.14.3 // indirect
	github.com/couchbase/gocbcore/v10 v10.5.0 // indirect
	github.com/couchbase/gocbcoreps v0.1.3 // indirect
	github.com/couchbase/goprotostellar v1.0.2 // indirect
	github.com/couchbaselabs/gocbconnstr/v2 v2.0.0-20240607131231-fb385523de28 // indirect
	github.com/cpuguy83/dockercfg v0.3.1 // indirect
	github.com/cyphar/filepath-securejoin v0.2.4 // indirect
	github.com/danieljoos/wincred v1.1.2 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/dimchansky/utfbom v1.1.1 // indirect
	github.com/distribution/reference v0.6.0 // indirect
	github.com/dlclark/regexp2 v1.4.0 // indirect
	github.com/docker/cli v24.0.0+incompatible // indirect
	github.com/docker/distribution v2.8.2+incompatible // indirect
	github.com/docker/docker v27.0.3+incompatible // indirect
	github.com/docker/docker-credential-helpers v0.7.0 // indirect
	github.com/docker/go-connections v0.5.0 // indirect
	github.com/docker/go-units v0.5.0 // indirect
	github.com/dsnet/compress v0.0.1 // indirect
	github.com/dvsekhvalnov/jose2go v1.6.0 // indirect
	github.com/elastic/elastic-transport-go/v8 v8.6.0 // indirect
	github.com/emirpasic/gods v1.18.1 // indirect
	github.com/erikgeiser/coninput v0.0.0-20211004153227-1c3628e74d0f // indirect
	github.com/felixge/httpsnoop v1.0.4 // indirect
	github.com/form3tech-oss/jwt-go v3.2.5+incompatible // indirect
	github.com/go-asn1-ber/asn1-ber v1.5.5 // indirect
	github.com/go-git/gcfg v1.5.1-0.20230307220236-3a3c6141e376 // indirect
	github.com/go-git/go-billy/v5 v5.5.0 // indirect
	github.com/go-jose/go-jose/v4 v4.0.2 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/go-ole/go-ole v1.2.6 // indirect
	github.com/goccy/go-json v0.10.2 // indirect
	github.com/godbus/dbus v0.0.0-20190726142602-4481cbc300e2 // indirect
	github.com/gogo/protobuf v1.3.2 // indirect
	github.com/golang-jwt/jwt/v5 v5.2.1 // indirect
	github.com/golang-sql/civil v0.0.0-20220223132316-b832511892a9 // indirect
	github.com/golang-sql/sqlexp v0.1.0 // indirect
	github.com/golang/groupcache v0.0.0-20210331224755-41bb18bfe9da // indirect
	github.com/golang/protobuf v1.5.4 // indirect
	github.com/golang/snappy v0.0.4 // indirect
	github.com/google/flatbuffers v23.5.26+incompatible // indirect
	github.com/google/go-querystring v1.1.0 // indirect
	github.com/google/pprof v0.0.0-20240227163752-401108e1b7e7 // indirect
	github.com/google/s2a-go v0.1.7 // indirect
	github.com/googleapis/enterprise-certificate-proxy v0.3.2 // indirect
	github.com/gorilla/css v1.0.0 // indirect
	github.com/grpc-ecosystem/go-grpc-middleware v1.4.0 // indirect
	github.com/grpc-ecosystem/grpc-gateway/v2 v2.16.0 // indirect
	github.com/gsterjov/go-libsecret v0.0.0-20161001094733-a6f4afe4910c // indirect
	github.com/h2non/parth v0.0.0-20190131123155-b4df798d6542 // indirect
	github.com/hashicorp/errwrap v1.1.0 // indirect
	github.com/hashicorp/go-cleanhttp v0.5.2 // indirect
	github.com/hashicorp/go-multierror v1.1.1 // indirect
	github.com/jbenet/go-context v0.0.0-20150711004518-d14ea06fba99 // indirect
	github.com/jmespath/go-jmespath v0.4.0 // indirect
	github.com/jpillora/s3 v1.1.4 // indirect
	github.com/kevinburke/ssh_config v1.2.0 // indirect
	github.com/kjk/lzma v0.0.0-20161016003348-3fd93898850d // indirect
	github.com/klauspost/compress v1.17.8 // indirect
	github.com/klauspost/cpuid/v2 v2.2.5 // indirect
	github.com/klauspost/pgzip v1.2.6 // indirect
	github.com/lucasb-eyer/go-colorful v1.2.0 // indirect
	github.com/lufia/plan9stats v0.0.0-20211012122336-39d0f177ccd0 // indirect
	github.com/magiconair/properties v1.8.7 // indirect
	github.com/mattn/go-colorable v0.1.13 // indirect
	github.com/mattn/go-localereader v0.0.1 // indirect
	github.com/mattn/go-runewidth v0.0.15 // indirect
	github.com/microcosm-cc/bluemonday v1.0.25 // indirect
	github.com/mitchellh/go-homedir v1.1.0 // indirect
	github.com/moby/docker-image-spec v1.3.1 // indirect
	github.com/moby/patternmatcher v0.6.0 // indirect
	github.com/moby/sys/sequential v0.5.0 // indirect
	github.com/moby/sys/user v0.1.0 // indirect
	github.com/moby/term v0.5.0 // indirect
	github.com/montanaflynn/stats v0.7.1 // indirect
	github.com/morikuni/aec v1.0.0 // indirect
	github.com/mtibben/percent v0.2.1 // indirect
	github.com/muesli/ansi v0.0.0-20230316100256-276c6243b2f6 // indirect
	github.com/muesli/cancelreader v0.2.2 // indirect
	github.com/muesli/termenv v0.15.2 // indirect
	github.com/nwaples/rardecode/v2 v2.0.0-beta.2 // indirect
	github.com/olekukonko/tablewriter v0.0.5 // indirect
	github.com/onsi/ginkgo v1.16.5 // indirect
	github.com/opencontainers/go-digest v1.0.0 // indirect
	github.com/opencontainers/image-spec v1.1.0 // indirect
	github.com/pierrec/lz4/v4 v4.1.19 // indirect
	github.com/pjbgf/sha1cd v0.3.0 // indirect
	github.com/pkg/diff v0.0.0-20200914180035-5b29258ca4f7 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/power-devops/perfstat v0.0.0-20210106213030-5aafc221ea8c // indirect
	github.com/prometheus/client_model v0.5.0 // indirect
	github.com/prometheus/common v0.48.0 // indirect
	github.com/prometheus/procfs v0.12.0 // indirect
	github.com/rivo/uniseg v0.4.7 // indirect
	github.com/sahilm/fuzzy v0.1.1-0.20230530133925-c48e322e2a8f // indirect
	github.com/shirou/gopsutil/v3 v3.23.12 // indirect
	github.com/shoenig/go-m1cpu v0.1.6 // indirect
	github.com/sirupsen/logrus v1.9.3 // indirect
	github.com/skeema/knownhosts v1.2.2 // indirect
	github.com/sorairolake/lzip-go v0.3.1 // indirect
	github.com/stretchr/objx v0.5.2 // indirect
	github.com/tetratelabs/wazero v1.7.2 // indirect
	github.com/therootcompany/xz v1.0.1 // indirect
	github.com/tklauser/go-sysconf v0.3.12 // indirect
	github.com/tklauser/numcpus v0.6.1 // indirect
	github.com/ulikunitz/xz v0.5.12 // indirect
	github.com/vbatts/tar-split v0.11.3 // indirect
	github.com/xanzy/ssh-agent v0.3.3 // indirect
	github.com/xdg-go/pbkdf2 v1.0.0 // indirect
	github.com/xdg-go/scram v1.1.2 // indirect
	github.com/xdg-go/stringprep v1.0.4 // indirect
	github.com/xhit/go-str2duration/v2 v2.1.0 // indirect
	github.com/xi2/xz v0.0.0-20171230120015-48954b6210f8 // indirect
	github.com/xo/terminfo v0.0.0-20220910002029-abceb7e1c41e // indirect
	github.com/youmark/pkcs8 v0.0.0-20181117223130-1be2e3e5546d // indirect
	github.com/yuin/goldmark v1.5.4 // indirect
	github.com/yuin/goldmark-emoji v1.0.2 // indirect
	github.com/yusufpapurcu/wmi v1.2.3 // indirect
	github.com/zeebo/xxh3 v1.0.2 // indirect
	go.einride.tech/aip v0.60.0 // indirect
	go.opencensus.io v0.24.0 // indirect
	go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc v0.49.0 // indirect
	go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp v0.49.0 // indirect
	go.opentelemetry.io/otel v1.24.0 // indirect
	go.opentelemetry.io/otel/metric v1.24.0 // indirect
	go.opentelemetry.io/otel/trace v1.24.0 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	go4.org v0.0.0-20230225012048-214862532bf5 // indirect
	golang.org/x/mod v0.19.0 // indirect
	golang.org/x/sys v0.22.0 // indirect
	golang.org/x/term v0.22.0 // indirect
	golang.org/x/time v0.5.0 // indirect
	golang.org/x/tools v0.23.0 // indirect
	golang.org/x/xerrors v0.0.0-20231012003039-104605ab7028 // indirect
	google.golang.org/genproto v0.0.0-20240708141625-4ad9e859172b // indirect
	google.golang.org/genproto/googleapis/api v0.0.0-20240701130421-f6361c86f094 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20240708141625-4ad9e859172b // indirect
	google.golang.org/grpc v1.64.1 // indirect
	gopkg.in/warnings.v0 v0.1.2 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
	pault.ag/go/topsort v0.1.1 // indirect
)
