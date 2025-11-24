package handlers

import (
	"reflect"
	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/trufflesecurity/trufflehog/v3/pkg/api/models"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/defaults"
)

type DetectorHandler struct{}

func NewDetectorHandler() *DetectorHandler {
	return &DetectorHandler{}
}

// ListDetectors godoc
// @Summary      List all available detectors
// @Description  Get a list of all available secret detectors including custom ones
// @Tags         detectors
// @Produce      json
// @Success      200 {object} models.DetectorsResponse
// @Router       /api/v1/detectors [get]
func (h *DetectorHandler) ListDetectors(c *fiber.Ctx) error {
	allDetectors := defaults.DefaultDetectors()
	detectorInfos := make([]models.DetectorInfo, 0, len(allDetectors))

	for _, detector := range allDetectors {
		info := models.DetectorInfo{
			Type:     getDetectorType(detector),
			Name:     getDetectorName(detector),
			Keywords: getDetectorKeywords(detector),
			Version:  getDetectorVersion(detector),
		}
		detectorInfos = append(detectorInfos, info)
	}

	return c.JSON(models.DetectorsResponse{
		Detectors: detectorInfos,
		Total:     len(detectorInfos),
	})
}

func getDetectorType(detector detectors.Detector) string {
	t := reflect.TypeOf(detector)
	if t.Kind() == reflect.Ptr {
		t = t.Elem()
	}
	return t.PkgPath()
}

func getDetectorName(detector detectors.Detector) string {
	t := reflect.TypeOf(detector)
	if t.Kind() == reflect.Ptr {
		t = t.Elem()
	}
	name := t.Name()
	
	// Remove common suffixes
	name = strings.TrimSuffix(name, "Scanner")
	name = strings.TrimSuffix(name, "Detector")
	
	return name
}

func getDetectorKeywords(detector detectors.Detector) []string {
	keywords := detector.Keywords()
	if len(keywords) == 0 {
		return []string{}
	}
	return keywords
}

func getDetectorVersion(detector detectors.Detector) int {
	if versioned, ok := detector.(interface{ Version() int }); ok {
		return versioned.Version()
	}
	return 1
}

