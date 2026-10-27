// Package webconsole owns the server-rendered console and its embedded assets.
// Callers must authorize protected pages before rendering them.
package webconsole

import (
	"bytes"
	"embed"
	"html/template"
	"net/http"
)

//go:embed templates/*.html static/*
var files embed.FS

var pageTemplate = template.Must(template.ParseFS(files, "templates/page.html"))

type Binding struct {
	Subject string
	Role    string
}

type Page struct {
	Title     string
	Section   string
	Subject   string
	Role      string
	CSRFToken string
	ExpiresAt string
	Message   string
	Bindings  []Binding
}

func RegisterAssets(mux *http.ServeMux) {
	for _, asset := range []struct{ name, contentType string }{{"console.css", "text/css; charset=utf-8"}, {"console.js", "text/javascript; charset=utf-8"}} {
		data, err := files.ReadFile("static/" + asset.name)
		if err != nil {
			panic(err)
		}
		mux.HandleFunc("GET /console/assets/"+asset.name, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", asset.contentType)
			w.Header().Set("X-Content-Type-Options", "nosniff")
			w.Header().Set("Cache-Control", "no-cache")
			_, _ = w.Write(data)
		})
	}
}

func Render(w http.ResponseWriter, status int, page Page) error {
	var buffer bytes.Buffer
	if err := pageTemplate.Execute(&buffer, page); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	// no-referrer makes browser form navigations send Origin: null, rejecting
	// the CSRF-protected logout. strict-origin still omits paths and queries.
	w.Header().Set("Referrer-Policy", "strict-origin")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'self'; script-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
	w.WriteHeader(status)
	_, err := buffer.WriteTo(w)
	return err
}
