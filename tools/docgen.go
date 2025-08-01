package main

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

type Request struct {
	URL    string `yaml:"url"`
	Name   string `yaml:"name"`
	Method string `yaml:"method"`
	Body   struct {
		MimeType string `yaml:"mimeType"`
		Text     string `yaml:"text"`
	} `yaml:"body"`
}

type Group struct {
	Name     string    `yaml:"name"`
	Children []Request `yaml:"children"`
}

type Collection struct {
	Collection []Group `yaml:"collection"`
}

func main() {
	data, err := os.ReadFile("go-jwt-api.yaml")
	if err != nil {
		panic(err)
	}

	var parsed Collection
	err = yaml.Unmarshal(data, &parsed)
	if err != nil {
		panic(err)
	}

	html := `
<!DOCTYPE html>
<html lang="pt-BR">
<head>
  <meta charset="UTF-8">
  <title>go-jwt-api Documentation</title>
  <style>
	body {
		font-family: 'Segoe UI', sans-serif;
		background-color: #f8f9fa;
		margin: 0;
		padding: 2rem;
		color: #212529;
	}

	h1 {
		font-size: 2.8rem;
		text-align: center;
		margin-bottom: 2.5rem;
		color: #007bff;
		border-bottom: 2px solid #dee2e6;
		padding-bottom: 0.5rem;
	}

	.group {
		border: 1px solid #dee2e6;
		border-radius: 6px;
		margin-bottom: 1rem;
		background: white;
		box-shadow: 0 2px 4px rgba(0,0,0,0.05);
	}

	.group-header {
		padding: 1rem;
		font-size: 1.2rem;
		font-weight: bold;
		background-color: #e9ecef;
		cursor: pointer;
		user-select: none;
		transition: background-color 0.2s;
	}

	.group-header:hover {
		background-color: #d6d8db;
	}

	.group-content {
		display: none;
		padding: 1rem;
	}

	.endpoint {
		margin-bottom: 1.5rem;
		padding: 1rem;
		background: #fefefe;
		border: 1px solid #ccc;
		border-radius: 6px;
	}

	.method {
		font-weight: bold;
		display: inline-block;
		padding: 0.25rem 0.5rem;
		border-radius: 4px;
		margin-right: 0.5rem;
		text-transform: uppercase;
	}

	.GET { background-color: #e2f0d9; color: #2e7d32; }
	.POST { background-color: #d1ecf1; color: #0c5460; }
	.PUT { background-color: #fff3cd; color: #856404; }
	.DELETE { background-color: #f8d7da; color: #721c24; }

	pre {
		background-color: #f1f3f5;
		padding: 1rem;
		border-radius: 6px;
		overflow-x: auto;
		white-space: pre-wrap;
	}
	</style>
</head>
<body>
<h1>go-jwt-api Documentation</h1>
`
	html += `<script>
function toggleGroup(el) {
  const content = el.nextElementSibling;
  if (content.style.display === 'block') {
    content.style.display = 'none';
  } else {
    content.style.display = 'block';
  }
}
</script>`

	for _, group := range parsed.Collection {
		html += `<div class="group">`
		html += fmt.Sprintf(`<div class="group-header" onclick="toggleGroup(this)">%s</div>`, group.Name)
		html += `<div class="group-content">`
		for _, req := range group.Children {
			methodClass := strings.ToUpper(req.Method)
			html += `<div class="endpoint">`
			html += fmt.Sprintf(`<h3><span class="method %s">%s</span> %s</h3>`, methodClass, req.Method, req.URL)
			html += fmt.Sprintf("<p><strong>Nome:</strong> %s</p>", req.Name)
			if req.Body.Text != "" {
				html += "<p><strong>Body:</strong></p><pre>" + req.Body.Text + "</pre>"
			}
			html += "</div>"
		}
		html += `</div></div>`
	}

	html += "</body></html>"

	err = os.WriteFile("docs.html", []byte(html), 0644)
	if err != nil {
		panic(err)
	}

	fmt.Println("📄 Documentação interativa gerada: docs.html")
}
