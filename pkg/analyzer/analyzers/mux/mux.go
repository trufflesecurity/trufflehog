//go:generate generate_permissions permissions.yaml permissions.go mux
package mux

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/fatih/color"
	"github.com/jedib0t/go-pretty/v6/table"

	_ "embed"

	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/analyzers"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/config"
	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
)

var _ analyzers.Analyzer = (*Analyzer)(nil)

type Analyzer struct {
	Cfg *config.Config
}

//go:embed tests.json
var testsConfig []byte

func readTestsConfig() (*permissionTestConfig, error) {
	var config permissionTestConfig
	if err := json.Unmarshal(testsConfig, &config); err != nil {
		return nil, fmt.Errorf("failed to unmarshal tests config: %w", err)
	}
	return &config, nil
}

func (a Analyzer) Type() analyzers.AnalyzerType {
	return analyzers.AnalyzerTypeMux
}

func (a Analyzer) Analyze(_ context.Context, credInfo map[string]string) (*analyzers.AnalyzerResult, error) {
	key, exist := credInfo["key"]
	if !exist {
		return nil, errors.New("key not found in credentials info")
	}
	secret, exist := credInfo["secret"]
	if !exist {
		return nil, errors.New("secret not found in credentials info")
	}

	info, err := AnalyzePermissions(a.Cfg, key, secret)
	if err != nil {
		return nil, err
	}

	return secretInfoToAnalyzerResult(info), nil
}

func AnalyzeAndPrintPermissions(cfg *config.Config, key string, secret string) {
	info, err := AnalyzePermissions(cfg, key, secret)
	if err != nil {
		color.Red("[x] Invalid Mux Key or Secret\n")
		color.Red("[x] Error : %s", err.Error())
		return
	}

	if info == nil {
		color.Red("[x] Error : %s", "No information found")
		return
	}

	color.Green("[i] Valid Mux API Key and Secret\n")
	printResourcesAndPermissions(info)
}

func AnalyzePermissions(cfg *config.Config, key string, secret string) (*secretInfo, error) {
	client := analyzers.NewAnalyzeClientUnrestricted(cfg)
	secretInfo := &secretInfo{}
	if err := testAllPermissions(client, secretInfo, key, secret); err != nil {
		return nil, err
	}
	if err := populateAllResources(client, secretInfo, key, secret); err != nil {
		return nil, err
	}

	return secretInfo, nil
}

func secretInfoToAnalyzerResult(info *secretInfo) *analyzers.AnalyzerResult {
	if info == nil {
		return nil
	}

	bindings := []analyzers.Binding{}
	readAccessPermission := analyzers.Permission{
		Value: PermissionStrings[Read],
	}
	fullAccessPermission := analyzers.Permission{
		Value: PermissionStrings[FullAccess],
	}

	videoResourcePermission := readAccessPermission
	if info.hasPermission(ResourceTypeVideo, FullAccess) {
		videoResourcePermission = fullAccessPermission
	}

	dataResourcePermission := readAccessPermission
	if info.hasPermission(ResourceTypeData, FullAccess) {
		dataResourcePermission = fullAccessPermission
	}

	systemResourcePermission := readAccessPermission
	if info.hasPermission(ResourceTypeSystem, FullAccess) {
		systemResourcePermission = fullAccessPermission
	}

	// Binding all Mux Video Assets
	for _, asset := range info.Assets {
		assetResource := createAssetResource(asset)
		trackResources := createAssetTrackResources(asset, &assetResource)
		playbackIDResources := createAssetPlaybackIDResources(asset, &assetResource)

		for _, resource := range trackResources {
			bindings = append(bindings, createBinding(&resource, videoResourcePermission))
		}
		for _, resource := range playbackIDResources {
			bindings = append(bindings, createBinding(&resource, videoResourcePermission))
		}

		bindings = append(bindings, createBinding(&assetResource, videoResourcePermission))
	}

	// Binding all Mux Data Annotations
	for _, annotation := range info.Annotations {
		annotationResource := createAnnotationResource(annotation)
		bindings = append(bindings, createBinding(&annotationResource, dataResourcePermission))
	}

	// Binding all Mux System Signing Keys
	for _, signingKey := range info.SigningKeys {
		signingKeyResource := createSigningKeyResource(signingKey)
		bindings = append(bindings, createBinding(&signingKeyResource, systemResourcePermission))
	}

	result := analyzers.AnalyzerResult{
		AnalyzerType: analyzers.AnalyzerTypeMux,
		Metadata:     nil,
		Bindings:     bindings,
	}
	return &result
}

func createBinding(resource *analyzers.Resource, permission analyzers.Permission) analyzers.Binding {
	return analyzers.Binding{
		Resource:   *resource,
		Permission: permission,
	}
}

func printResourcesAndPermissions(info *secretInfo) {
	color.Yellow("\n[i] Permissions:")
	t1 := table.NewWriter()
	t1.AppendHeader(table.Row{"Resource Category", "Access Level", "Resource List"})

	for idx, resource := range muxResourcesMap[ResourceTypeVideo] {
		category, access := "", ""
		if idx == 0 {
			category = "Mux Video"
			access = getAccessLevelStringFromPermission(info.Permissions[ResourceTypeVideo])
		}
		t1.AppendRow(table.Row{
			color.GreenString(category),
			color.GreenString(access),
			color.GreenString(resource),
		})
	}
	t1.AppendSeparator()

	for idx, resource := range muxResourcesMap[ResourceTypeData] {
		category, access := "", ""
		if idx == 0 {
			category = "Mux Data"
			access = getAccessLevelStringFromPermission(info.Permissions[ResourceTypeData])
		}
		t1.AppendRow(table.Row{
			color.GreenString(category),
			color.GreenString(access),
			color.GreenString(resource),
		})
	}
	t1.AppendSeparator()

	for idx, resource := range muxResourcesMap[ResourceTypeSystem] {
		category, access := "", ""
		if idx == 0 {
			category = "Mux System"
			access = getAccessLevelStringFromPermission(info.Permissions[ResourceTypeSystem])
		}
		t1.AppendRow(table.Row{
			color.GreenString(category),
			color.GreenString(access),
			color.GreenString(resource),
		})
	}
	t1.SetOutputMirror(os.Stdout)
	t1.Render()

	color.Yellow("\n[i] Resources:")

	if info.hasPermission(ResourceTypeVideo, Read) {
		printMuxVideoResources(info)
	}

	if info.hasPermission(ResourceTypeData, Read) {
		printMuxDataResources(info)
	}

	if info.hasPermission(ResourceTypeSystem, Read) {
		printMuxSystemResources(info)
	}

	fmt.Printf("%s: https://www.mux.com/docs/api-reference\n\n", color.GreenString("Ref"))
}

func printMuxVideoResources(info *secretInfo) {
	t1 := table.NewWriter()
	t1.SetTitle("Assets")
	t1.AppendHeader(table.Row{"ID", "Title", "Duration", "Status", "Creator ID", "External ID", "Created At"})

	t2 := table.NewWriter()
	t2.SetTitle("Asset Tracks")
	t2.AppendHeader(table.Row{"Asset ID", "ID", "Name", "Type", "Duration", "Status", "Primary"})

	t3 := table.NewWriter()
	t3.SetTitle("Asset Playback IDs")
	t3.AppendHeader(table.Row{"Asset ID", "ID", "Policy"})

	for _, asset := range info.Assets {
		t1.AppendRow(table.Row{
			color.GreenString(asset.ID),
			color.GreenString(asset.Meta.Title),
			color.GreenString(fmt.Sprintf("%.2fs", asset.Duration)),
			color.GreenString(asset.Status),
			color.GreenString(asset.Meta.CreatorID),
			color.GreenString(asset.Meta.ExternalID),
			color.GreenString(asset.CreatedAt),
		})
		t1.AppendSeparator()
		for _, track := range asset.Tracks {
			t2.AppendRow(table.Row{
				color.GreenString(asset.ID),
				color.GreenString(track.ID),
				color.GreenString(track.Name),
				color.GreenString(track.Type),
				color.GreenString(fmt.Sprintf("%.2fs", track.Duration)),
				color.GreenString(track.Status),
				color.GreenString(fmt.Sprintf("%t", track.Primary)),
			})
			t2.AppendSeparator()
		}
		for _, playbackID := range asset.PlaybackIDs {
			t3.AppendRow(table.Row{
				color.GreenString(asset.ID),
				color.GreenString(playbackID.ID),
				color.GreenString(playbackID.Policy),
			})
			t3.AppendSeparator()
		}
	}
	t1.SetOutputMirror(os.Stdout)
	t1.Render()

	t2.SetOutputMirror(os.Stdout)
	t2.Render()

	t3.SetOutputMirror(os.Stdout)
	t3.Render()
}

func printMuxDataResources(info *secretInfo) {
	t1 := table.NewWriter()
	t1.SetTitle("Annotations")
	t1.AppendHeader(table.Row{"ID", "Note", "Date", "Sub Property ID"})
	for _, annotation := range info.Annotations {
		t1.AppendRow(table.Row{
			color.GreenString(annotation.ID),
			color.GreenString(annotation.Note),
			color.GreenString(annotation.Date),
			color.GreenString(annotation.SubPropertyID),
		})
	}
	t1.SetOutputMirror(os.Stdout)
	t1.Render()
}

func printMuxSystemResources(info *secretInfo) {
	t1 := table.NewWriter()
	t1.SetTitle("Signing Keys")
	t1.AppendHeader(table.Row{"ID", "Created At"})
	for _, signingKey := range info.SigningKeys {
		t1.AppendRow(table.Row{
			color.GreenString(signingKey.ID),
			color.GreenString(signingKey.CreatedAt),
		})
	}
	t1.SetOutputMirror(os.Stdout)
	t1.Render()
}

func getAccessLevelStringFromPermission(permission Permission) string {
	switch permission {
	case Read:
		return "Read"
	case FullAccess:
		return "Read & Write"
	default:
		return "None"
	}
}
