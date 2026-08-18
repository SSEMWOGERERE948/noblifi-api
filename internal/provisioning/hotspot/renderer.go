package hotspot

import (
	"bytes"
	"embed"
	"fmt"
	"html/template"
)

//go:embed templates/*.html
var templateFS embed.FS

var portalTemplates = template.Must(
	template.ParseFS(
		templateFS,
		"templates/*.html",
	),
)

func RenderLogin(data PortalData) (string, error) {
	var buf bytes.Buffer

	err := portalTemplates.ExecuteTemplate(
		&buf,
		"login.html",
		data,
	)

	if err != nil {
		return "", fmt.Errorf(
			"render hotspot login template: %w",
			err,
		)
	}

	return buf.String(), nil
}

func RenderStatus(data PortalData) (string, error) {
	var buf bytes.Buffer

	err := portalTemplates.ExecuteTemplate(
		&buf,
		"status.html",
		data,
	)

	if err != nil {
		return "", fmt.Errorf(
			"render hotspot status template: %w",
			err,
		)
	}

	return buf.String(), nil
}

func RenderLogout(data PortalData) (string, error) {
	var buf bytes.Buffer

	err := portalTemplates.ExecuteTemplate(
		&buf,
		"logout.html",
		data,
	)

	if err != nil {
		return "", fmt.Errorf(
			"render hotspot logout template: %w",
			err,
		)
	}

	return buf.String(), nil
}