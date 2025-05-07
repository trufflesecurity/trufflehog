package mux

import "github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/analyzers"

var muxResourcesMap map[ResourceType][]string

func init() {
	muxResourcesMap = map[ResourceType][]string{
		ResourceTypeVideo: {
			"Transcription Vocabularies",
			"Web Inputs",
			"Assets",
			"Live Streams",
			"Uploads",
			"Playback Restrictions",
			"DRM Configurations",
		},
		ResourceTypeData: {
			"Video Views",
			"Filters",
			"Dimensions",
			"Export",
			"Metrics",
			"Monitoring",
			"Realtime",
			"Incidents",
			"Annotations",
		},
		ResourceTypeSystem: {
			"Signing Keys",
		},
	}
}

func createAssetResource(asset asset) analyzers.Resource {
	return analyzers.Resource{
		Name:               asset.ID,
		FullyQualifiedName: "asset/" + asset.ID,
		Type:               "asset",
		Metadata: map[string]any{
			"duration":     asset.Duration,
			"status":       asset.Status,
			"videoQuality": asset.VideoQuality,
			"mp4Support":   asset.MP4Support,
			"aspectRatio":  asset.AspectRatio,
			"createdAt":    asset.CreatedAt,
		},
	}
}

func createAssetTrackResources(asset asset, parent *analyzers.Resource) []analyzers.Resource {
	trackResources := []analyzers.Resource{}
	for _, track := range asset.Tracks {
		trackResources = append(trackResources, analyzers.Resource{
			Name:               track.ID,
			FullyQualifiedName: "asset/" + asset.ID + "/track/" + track.ID,
			Type:               "track",
			Metadata: map[string]any{
				"name":         track.Name,
				"type":         track.Type,
				"duration":     track.Duration,
				"status":       track.Status,
				"primary":      track.Primary,
				"textType":     track.TextType,
				"textSource":   track.TextSource,
				"languageCode": track.LanguageCode,
				"maxWidth":     track.MaxWidth,
				"maxHeight":    track.MaxHeight,
				"maxFrameRate": track.MaxFrameRate,
				"maxChannels":  track.MaxChannels,
			},
			Parent: parent,
		})
	}
	return trackResources
}

func createAssetPlaybackIDResources(asset asset, parent *analyzers.Resource) []analyzers.Resource {
	playbackIDResources := []analyzers.Resource{}
	for _, playbackID := range asset.PlaybackIDs {
		playbackIDResources = append(playbackIDResources, analyzers.Resource{
			Name:               playbackID.ID,
			FullyQualifiedName: "asset/" + asset.ID + "/playback_id/" + playbackID.ID,
			Type:               "playback_id",
			Metadata: map[string]any{
				"policy": playbackID.Policy,
			},
			Parent: parent,
		})
	}
	return playbackIDResources
}

func createAnnotationResource(annotation annotation) analyzers.Resource {
	return analyzers.Resource{
		Name:               annotation.ID,
		FullyQualifiedName: "annotation/" + annotation.ID,
		Type:               "annotation",
		Metadata: map[string]any{
			"subPropertyID": annotation.SubPropertyID,
			"note":          annotation.Note,
			"date":          annotation.Date,
		},
	}
}
func createSigningKeyResource(signingKey signingKey) analyzers.Resource {
	return analyzers.Resource{
		Name:               signingKey.ID,
		FullyQualifiedName: "signing_key/" + signingKey.ID,
		Type:               "signing_key",
		Metadata: map[string]any{
			"createdAt": signingKey.CreatedAt,
		},
	}
}
