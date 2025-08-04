package azure_storage

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

func TestAzureStorage_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		// True Positive
		// CONNECTION STRINGS
		{
			name:  `connection_string_1`,
			input: `DefaultEndpointsProtocol=https;AccountName=storagetest123;AccountKey=YutGV0Vlauqsobd5tPWz2AKwHhBXMEWsAH+rSbz0UZUfaMVj1CFrcNQK47ygmrC4vHmc7eOp1LdM+AStk5mMyA==;EndpointSuffix=core.windows.net`,
			want:  []string{`{"accountName":"storagetest123","accountKey":"YutGV0Vlauqsobd5tPWz2AKwHhBXMEWsAH+rSbz0UZUfaMVj1CFrcNQK47ygmrC4vHmc7eOp1LdM+AStk5mMyA=="}`},
		},
		{
			name:  `connection_string_2`,
			input: `EndpointSuffix=core.windows.net;AccountKey=ldlKgoKPJhRjPJTkaC5c/QNqtu4sVQRc/teGJ0MZHbDYEHdvBV5z8JEfJK+evE87D7U8TzMZ0G2C+ASt2B4ifg==;AccountName=storagetest123;DefaultEndpointsProtocol=http`,
			want:  []string{`{"accountName":"storagetest123","accountKey":"ldlKgoKPJhRjPJTkaC5c/QNqtu4sVQRc/teGJ0MZHbDYEHdvBV5z8JEfJK+evE87D7U8TzMZ0G2C+ASt2B4ifg=="}`},
		},
		{
			name:  `connection_string_3`,
			input: `			public const string SharedStorageKey = "DefaultEndpointsProtocol=https;AccountName=huntappstorage;AccountKey=rrttFty/b52ET/e8VqpMSN+ZqAUP7hcXVkdekrPX58gsMZyOCrE+igN07t3lyi7tAV0+OrJFBaDtMe06YJ2tFw==;EndpointSuffix=core.windows.net";`,
			want:  []string{`{"accountName":"huntappstorage","accountKey":"rrttFty/b52ET/e8VqpMSN+ZqAUP7hcXVkdekrPX58gsMZyOCrE+igN07t3lyi7tAV0+OrJFBaDtMe06YJ2tFw=="}`},
		},
		{
			name: `connection_string_multiline`,
			input: `
export const DevelopmentConnectionString = 'DefaultEndpointsProtocol=http;AccountName=macdemostorage;
			AccountKey=Jby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz4I6tq/K1SZFPTOtr/KBHBeksoGMGw==;
			QueueEndpoint=http://127.0.0.1:10001/devstoreaccount1;';`,
			want: []string{`{"accountName":"macdemostorage","accountKey":"Jby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz4I6tq/K1SZFPTOtr/KBHBeksoGMGw=="}`},
		},

		// LANGUAGES
		// TODO:
		// - https://github.com/Satyamk21/az204/blob/75f340c5bbfb34c1477a6885e216d5ae0972a380/Lab%203.txt#L22

		// https://github.com/facebookincubator/velox/blob/98e958c0df498efd7cf44a2078cc71caeb7aed23/velox/connectors/hive/storage_adapters/abfs/tests/AzuriteServer.h#L32-L36
		{
			name: `cpp`,
			input: `static const std::string AzuriteAccountName{"storagetest123"};
static const std::string AzuriteContainerName{"test"};
// the default key of Azurite Server used for connection
static const std::string AzuriteAccountKey{
    "qYaZm3m8+Z2aYAiSDzzvStkTUgZXl29U76lDJ0qiob7bbV4g7kjtwO+FI2QoptGdZgEdtsAYzG8T0hl5TeftWA=="};`,
			want: []string{`{"accountName":"storagetest123","accountKey":"qYaZm3m8+Z2aYAiSDzzvStkTUgZXl29U76lDJ0qiob7bbV4g7kjtwO+FI2QoptGdZgEdtsAYzG8T0hl5TeftWA=="}`},
		},
		// https://github.com/MicrosoftDX/Dash/blob/03c4bb55f9e84fd03ee943559c128c4d5c2a31c2/DashServer.Tests/RequestAuthTests.cs#L29
		{
			name: `dotnet1`,
			input: `           _ctx = InitializeConfigAndCreateTestBlobs(ctx, "datax1", new Dictionary<string, string>
                {
                    { "AccountName", "dashstorage1" },
                    { "AccountKey", "8jqRVtXUWiEthgIhR+dFwrB8gh3lFuquvJQ1v4eabObIj7okI1cZIuzY8zZHmEdpcC0f+XlUkbFwAhjTfyrLIg==" },
                    { "SecondaryAccountKey", "Klari9ZbVdFQ35aULCfqqehCsd136amhusMHWynTpz2Pg+GyQMJw3GH177hvEQbaZ2oeRYk3jw0mIaV3ehNIRg==" },
                },`,
			want: []string{
				`{"accountName":"dashstorage1","accountKey":"8jqRVtXUWiEthgIhR+dFwrB8gh3lFuquvJQ1v4eabObIj7okI1cZIuzY8zZHmEdpcC0f+XlUkbFwAhjTfyrLIg=="}`,
				`{"accountName":"dashstorage1","accountKey":"Klari9ZbVdFQ35aULCfqqehCsd136amhusMHWynTpz2Pg+GyQMJw3GH177hvEQbaZ2oeRYk3jw0mIaV3ehNIRg=="}`,
			},
		},
		// https://github.com/Satyamk21/az204/blob/75f340c5bbfb34c1477a6885e216d5ae0972a380/Lab%203.txt#L11
		{
			name: `dotnet2`,
			input: `public class Program
{
    private const string blobServiceEndpoint = "https://k21storagemedia.blob.core.windows.net/";

    private const string storageAccountName = "k21storagemedia";

    private const string storageAccountKey = "DFdukxfl0SwO4NB91bi/FTPh9BMEKr6Z5wWf+tGDfXMakXvGVp/NDzAUjWc/9171OqoDvXSj1o8N+AStUk1GXg==";    


    //The following code to create a new asynchronous Main method
    public static async Task Main(string[] args)`,
			want: []string{`{"accountName":"k21storagemedia","accountKey":"DFdukxfl0SwO4NB91bi/FTPh9BMEKr6Z5wWf+tGDfXMakXvGVp/NDzAUjWc/9171OqoDvXSj1o8N+AStUk1GXg=="}`},
		},
		// https://github.com/apache/camel/blob/main/test-infra/camel-test-infra-azure-common/src/test/java/org/apache/camel/test/infra/azure/common/services/AzuriteContainer.java#L25-L27
		{
			name: `java`,
			input: `public class AzuriteContainer extends GenericContainer<AzuriteContainer> {
    public static final String DEFAULT_ACCOUNT_NAME = "storagetest123";
    public static final String DEFAULT_ACCOUNT_KEY
            = "qYaZm3m8+Z2aYAiSDzzvStkTUgZXl29U76lDJ0qiob7bbV4g7kjtwO+FI2QoptGdZgEdtsAYzG8T0hl5TeftWA==";

    public static final String IMAGE_NAME = "mcr.microsoft.com/azure-storage/azurite:3.27.0";`,
			want: []string{`{"accountName":"storagetest123","accountKey":"qYaZm3m8+Z2aYAiSDzzvStkTUgZXl29U76lDJ0qiob7bbV4g7kjtwO+FI2QoptGdZgEdtsAYzG8T0hl5TeftWA=="}`},
		},
		// https://github.com/Azure/azure-storage-node/blob/6873387fc65bad6d577babe278be2ee2e6071493/test/common/connectionstringparsertests.js
		{
			name: `javascript`,
			input: `   var parsedConnectionString = ServiceSettings.parseAndValidateKeys(defaultConnectionString + endpointsConnectionString, validKeys);
    assert.equal(parsedConnectionString['DefaultEndpointsProtocol'], 'https');
    assert.equal(parsedConnectionString['AccountName'], 'storagetest123');
    assert.equal(parsedConnectionString['AccountKey'], 'KWPLd0rpW2T0U7K2pVpF8rYr1BgYtR7wYQk33AYiXeUoquiaY6o0TWqduxmPHlqeCNZ3LU0DHptbeIHy5l/Yhg==');
    assert.equal(parsedConnectionString['BlobEndpoint'], 'myBlobEndpoint');
    assert.equal(parsedConnectionString['QueueEndpoint'], 'myQueueEndpoint');
    assert.equal(parsedConnectionString['TableEndpoint'], 'myTableEndpoint');`,
			want: []string{`{"accountName":"storagetest123","accountKey":"KWPLd0rpW2T0U7K2pVpF8rYr1BgYtR7wYQk33AYiXeUoquiaY6o0TWqduxmPHlqeCNZ3LU0DHptbeIHy5l/Yhg=="}`},
		},
		// https://github.com/nextcloud/server/blob/81a9e19ace190ea0a64d52d95d341e25c7ad618b/tests/preseed-config.php#L89
		{
			name: `php`,
			input: `	'arguments' => [
			'container' => 'test',
			'account_name' => 'storagetest123',
			'account_key' => 'qYaZm3m8+Z2aYAiSDzzvStkTUgZXl29U76lDJ0qiob7bbV4g7kjtwO+FI2QoptGdZgEdtsAYzG8T0hl5TeftWA==',
			'endpoint' => 'http://' . (getenv('DRONE') === 'true' ? 'azurite' : 'localhost') . ':10000/devstoreaccount1',
			'autocreate' => true
		]`,
			want: []string{`{"accountName":"storagetest123","accountKey":"qYaZm3m8+Z2aYAiSDzzvStkTUgZXl29U76lDJ0qiob7bbV4g7kjtwO+FI2QoptGdZgEdtsAYzG8T0hl5TeftWA=="}`},
		},
		// https://github.com/Azure/azure-sdk-for-js/blob/2719dcfbe835a2da3003876dcb5d77efba95f912/sdk/cosmosdb/cosmos/test/public/common/_fakeTestSecrets.ts
		{
			name: `typescript`,
			input: `export const name =
  process.env.ACCOUNT_NAME || "storagename123";
export const key =
  process.env.ACCOUNT_KEY ||
  "C2y6yDjf5/R+ob0N8A7Cgv30VRDJIWEHLM+4QDU5DE2nQ9nDuVTqobD4b8mGGyPMbIZnqyMsEcaGQy67XIw/Jw==";`,
			want: []string{`{"accountName":"storagename123","accountKey":"C2y6yDjf5/R+ob0N8A7Cgv30VRDJIWEHLM+4QDU5DE2nQ9nDuVTqobD4b8mGGyPMbIZnqyMsEcaGQy67XIw/Jw=="}`},
		},

		// FORMATS
		// TODO: Doesn't work.
		// https://github.com/Azure/azure-quickstart-templates/blob/03e792429fbc65c9353335611933746364590b22/quickstarts/microsoft.datafactory/data-factory-hive-transformation/azuredeploy.parameters.json#L9C38-L9C38
		//	{
		//		name: `json`,
		//		input: `    "storageAccountName": {
		//  "value": "changemeazurestorage"
		//},
		//"storageAccountKey": {
		//  "value": "YA1gKAMY34PeVgEWPF8FdbQO+U0nFkd3SaFE4d32K16AYL/DowrTYun8anOdAiCnMkCiRYm+PxUh5mw7a7lVcA=="
		//},`,
		//		want: []string{`{"accountName":"storagetest123","accountKey":"qYaZm3m8+Z2aYAiSDzzvStkTUgZXl29U76lDJ0qiob7bbV4g7kjtwO+FI2QoptGdZgEdtsAYzG8T0hl5TeftWA=="}`},
		//	},
		// https://github.com/ClickHouse/ClickHouse/blob/eba52b318d67d85330c9c1781499b7ff27fb7c0e/tests/integration/test_storage_azure_blob_storage/configs/named_collections.xml
		{
			name: `xml`,
			input: `        <azure_conf2>
            <account_name>storagetest123</account_name>
            <account_key>qYaZm3m8+Z2aYAiSDzzvStkTUgZXl29U76lDJ0qiob7bbV4g7kjtwO+FI2QoptGdZgEdtsAYzG8T0hl5TeftWA==</account_key>
        </azure_conf2>`,
			want: []string{`{"accountName":"storagetest123","accountKey":"qYaZm3m8+Z2aYAiSDzzvStkTUgZXl29U76lDJ0qiob7bbV4g7kjtwO+FI2QoptGdZgEdtsAYzG8T0hl5TeftWA=="}`},
		},
		// https://github.com/hubblestack/hubble/blob/f9b7bf38752bd16b27d050a3b8787652a1c6319b/hubblestack/fileserver/azurefs.py
		{
			name: `yaml1`,
			input: `    azurefs:
      - account_name: mystorage
        account_key: 'fNH9cRp0+qVIVYZ+5rnZAhHc9ycOUcJnHtzpfOr0W0sxrtL2KVLuMe1xDfLwmfed+JJInZaEdWVCPHD4d/oqeA=='
        container_name: my_container
        proxy: 10.10.10.10:8080`,
			want: []string{`{"accountName":"mystorage","accountKey":"fNH9cRp0+qVIVYZ+5rnZAhHc9ycOUcJnHtzpfOr0W0sxrtL2KVLuMe1xDfLwmfed+JJInZaEdWVCPHD4d/oqeA=="}`},
		},
		{
			name: `yaml2`,
			input: `  - name: filesharevolume
    azureFile:
      sharename: containershare
      storageAccountName: newstore100033323
      storageAccountKey: Ar4/2iY8L0rEMeQaijINnfaMJr7vqjfbPgmJayw6Pu5l9ZI+GrFDm1uIWOqXk5RQLrTiXfBwWY6hAbPEIQqy1g==`,
			want: []string{`{"accountName":"newstore100033323","accountKey":"Ar4/2iY8L0rEMeQaijINnfaMJr7vqjfbPgmJayw6Pu5l9ZI+GrFDm1uIWOqXk5RQLrTiXfBwWY6hAbPEIQqy1g=="}`},
		},
		// This was manually base64-decoded since that doesn't work in unit tests.
		// https://github.com/fabric8io/configmapcontroller/blob/master/vendor/k8s.io/kubernetes/examples/azure_file/secret/azure-secret.yaml
		{
			name: `yaml_3`,
			input: `apiVersion: v1
		kind: Secret
		metadata:
		 name: azure-secret
		type: Opaque
		data:
		 azurestorageaccountname: k8stest
		 azurestorageaccountkey: xIF1zJbnnojFLMSkBp50mx02rHsMK2sjU7mFt4L13hoB7drAaJ8jD6+A443jJogV7y2FUOhQCWPmM6YaNHy7qg==
`,
			want: []string{`{"accountName":"k8stest","accountKey":"xIF1zJbnnojFLMSkBp50mx02rHsMK2sjU7mFt4L13hoB7drAaJ8jD6+A443jJogV7y2FUOhQCWPmM6YaNHy7qg=="}`},
		},

		// MISC
		// https://github.com/Azure-Samples/nested-virtualization-image-builder/blob/cf0373a421343b00ce3d261be99ddced80deb55b/README.md?plain=1#L54
		{
			name:  `blob_url`,
			input: `"name": "storagetest123.blob.core.windows.net", "accountKey":"hGeB3WqDyx0mGsQMsQDl+gmnXa51ZODiBtcXJpMoRhPjkDm79f9ErNfaYizXm7nkElix8n2uBwNk6KY8Rc866w=="`,
			want:  []string{`{"accountName":"storagetest123","accountKey":"hGeB3WqDyx0mGsQMsQDl+gmnXa51ZODiBtcXJpMoRhPjkDm79f9ErNfaYizXm7nkElix8n2uBwNk6KY8Rc866w=="}`},
		},
		{
			name:  `random_cli_1`,
			input: `go run .\main.go -debug -dest="https://kenfau.blob.core.windows.net/ss3/" -AzureDefaultAccountName="kenfoo" -AzureDefaultAccountKey="hGeB3WqDyx0mGsQMsQDl+gmnXa51ZODiBtcXJpMoRhPjkDm79f9ErNfaYizXm7nkElix8n2uBwNk6KY8Rc866w=="`,
			want: []string{
				`{"accountName":"kenfau","accountKey":"hGeB3WqDyx0mGsQMsQDl+gmnXa51ZODiBtcXJpMoRhPjkDm79f9ErNfaYizXm7nkElix8n2uBwNk6KY8Rc866w=="}`,
				`{"accountName":"kenfoo","accountKey":"hGeB3WqDyx0mGsQMsQDl+gmnXa51ZODiBtcXJpMoRhPjkDm79f9ErNfaYizXm7nkElix8n2uBwNk6KY8Rc866w=="}`,
			},
		},
		// - https://github.com/nwoolls/AzureStorageCleanup/blob/980e5cb163c78e9446e70d2513ba5a7ed9051a7a/README.md?plain=1#L24
		{
			name: `random_cli_2`,
			input: `AzureStorageCleanup.exe 
    -storagename storageaccount
    -storagekey hGeB3WqDyx0mGsQMsQDl+gmnXa51ZODiBtcXJpMoRhPjkDm79f9ErNfaYizXm7nkElix8n2uBwNk6KY8Rc866w==
    -container sqlbackup
    -mindaysold 60
    -searchpattern .*
    -recursive
    -whatif`,
			want: []string{`{"accountName":"storageaccount","accountKey":"hGeB3WqDyx0mGsQMsQDl+gmnXa51ZODiBtcXJpMoRhPjkDm79f9ErNfaYizXm7nkElix8n2uBwNk6KY8Rc866w=="}`},
		},
		// https://github.com/dahlej/rpi-spark-titantic/blob/d00b8f5b4696aeb2113e9452c24bb31b7f9a0242/tmp.txt#L9
		{
			name: `random_cli_3`,
			input: `$ bin/spark-submit --master \
    k8s://test-cluster.eastus2.cloudapp.azure.com:443 \
    --deploy-mode cluster \
    --name copyLocations \
    --class io.timpark.CopyData \
    --conf spark.copydata.containerpath=wasb://containers@storagetest123.blob.core.windows.net \
    --conf spark.copydata.storageaccount=storagetest123 \
    --conf spark.copydata.storageaccountkey=hGeB3WqDyx0mGsQMsQDl+gmnXa51ZODiBtcXJpMoRhPjkDm79f9ErNfaYizXm7nkElix8n2uBwNk6KY8Rc866w== \`,
			want: []string{`{"accountName":"storagetest123","accountKey":"hGeB3WqDyx0mGsQMsQDl+gmnXa51ZODiBtcXJpMoRhPjkDm79f9ErNfaYizXm7nkElix8n2uBwNk6KY8Rc866w=="}`},
		},
		{
			name: `custom_config_1`,
			input: `driver := ArtifactDriver{
		AccountName: "storagetest123",
		AccountKey: "qYaZm3m8+Z2aYAiSDzzvStkTUgZXl29U76lDJ0qiob7bbV4g7kjtwO+FI2QoptGdZgEdtsAYzG8T0hl5TeftWA==",
		Container:  "test",
	}`,
			want: []string{`{"accountName":"storagetest123","accountKey":"qYaZm3m8+Z2aYAiSDzzvStkTUgZXl29U76lDJ0qiob7bbV4g7kjtwO+FI2QoptGdZgEdtsAYzG8T0hl5TeftWA=="}`},
		},
		// https://github.com/MicrosoftDX/Dash/blob/master/LoadTestDotNet/GetBlobCoded.cs
		{
			name: `storage_account_1`,
			input: `                this.Context.Add("StorageEndPoint", "http://dashstorage3.blob.core.windows.net");
                this.Context.Add("StorageAccount", "dashstorage3");
                this.Context.Add("AccountKey", "TP+G/9FTZRP1he1EpKilMercxSbMyqtaI9xTbc/3HqT2/FkxyIk1wVlBdemDFuYKStmlkFqHc7049l8McTd8NQ==");
                this.Context.Add("SendChunked", false);`,
			want: []string{`{"accountName":"dashstorage3","accountKey":"TP+G/9FTZRP1he1EpKilMercxSbMyqtaI9xTbc/3HqT2/FkxyIk1wVlBdemDFuYKStmlkFqHc7049l8McTd8NQ=="}`},
		},
		// https://github.com/kubecost/poc-common-configurations/blob/d626a48824a104e3089fc66ef57029f1e2212f6a/keys.txt#L18
		{
			name: `storage_account_2`,
			input: `AZ_cloud_integration_subscriptionId:0bd50fdf-c923-4e1e-850c-196ddSAMPLE
AZ_cloud_integration_azureStorageAccount:kubecostexport
AZ_cloud_integration_azureStorageAccessKey:TP+G/9FTZRP1he1EpKilMercxSbMyqtaI9xTbc/3HqT2/FkxyIk1wVlBdemDFuYKStmlkFqHc7049l8McTd8NQ==
AZ_cloud_integration_azureStorageContainer:costexports`,
			want: []string{`{"accountName":"kubecostexport","accountKey":"TP+G/9FTZRP1he1EpKilMercxSbMyqtaI9xTbc/3HqT2/FkxyIk1wVlBdemDFuYKStmlkFqHc7049l8McTd8NQ=="}`},
		},

		// False positives
		{
			name:  `test_key`,
			input: `    azureblockblob: TEST_BACKEND=azureblockblob://DefaultEndpointsProtocol=http;AccountName=devstoreaccount1;AccountKey=Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz4I6tq/K1SZFPTOtr/KBHBeksoGMGw==;BlobEndpoint=http://127.0.0.1:10000/devstoreaccount1;`,
		},
		{
			name: `test_key_multiline`,
			input: `
export const DevelopmentConnectionString = 'DefaultEndpointsProtocol=http;AccountName=devstoreaccount1;
			AccountKey=Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz4I6tq/K1SZFPTOtr/KBHBeksoGMGw==;
			QueueEndpoint=http://127.0.0.1:10001/devstoreaccount1;';`,
		},
		{
			name:  `invalid_key_1`,
			input: `        docs::examples = "DefaultEndpointsProtocol=https;AccountName=mylogstorage;AccountKey=storageaccountkeybase64encoded;EndpointSuffix=core.windows.net"`,
		},
		{
			name:  `invalid_key_2`,
			input: `PS C:\> Add-AzIotHubRoutingEndpoint -ResourceGroupName "myresourcegroup" -Name "myiothub" -EndpointName S1 -EndpointType AzureStorageContainer -EndpointResourceGroup resourcegroup1 -EndpointSubscriptionId 91d12343-a3de-345d-b2ea-135792468abc -ConnectionString 'DefaultEndpointsProtocol=https;AccountName=mystorage1;AccountKey=*****;EndpointSuffix=core.windows.net' -ContainerName container -Encoding json`,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			matchedDetectors := ahoCorasickCore.FindDetectorMatches([]byte(test.input))
			if len(matchedDetectors) == 0 {
				t.Errorf("test %q failed: expected keywords %v to be found in the input", test.name, d.Keywords())
				return
			}

			results, err := d.FromData(context.Background(), false, []byte(test.input))
			require.NoError(t, err)

			if len(results) != len(test.want) {
				t.Errorf("mismatch in result count: expected %d, got %d", len(test.want), len(results))
				return
			}

			actual := make(map[string]struct{}, len(results))
			for _, r := range results {
				if len(r.RawV2) > 0 {
					actual[string(r.RawV2)] = struct{}{}
				} else {
					actual[string(r.Raw)] = struct{}{}
				}
			}

			expected := make(map[string]struct{}, len(test.want))
			for _, v := range test.want {
				expected[v] = struct{}{}
			}

			if diff := cmp.Diff(expected, actual); diff != "" {
				t.Errorf("%s diff: (-want +got)\n%s", test.name, diff)
			}
		})
	}
}
