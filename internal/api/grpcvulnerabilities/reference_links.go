package grpcvulnerabilities

import (
	"net/url"

	"github.com/yuin/goldmark"
	"github.com/yuin/goldmark/ast"
	"github.com/yuin/goldmark/extension"
	"github.com/yuin/goldmark/text"
	"github.com/yuin/goldmark/util"
)

var refLinksMarkdown = goldmark.New(goldmark.WithExtensions(extension.Linkify))

func parseRefLinks(referenceText string) []string {
	if referenceText == "" {
		return nil
	}

	source := []byte(referenceText)
	document := refLinksMarkdown.Parser().Parse(text.NewReader(source))
	var links []string
	seen := make(map[string]struct{})
	_ = ast.Walk(document, func(node ast.Node, entering bool) (ast.WalkStatus, error) {
		if !entering {
			return ast.WalkContinue, nil
		}

		var destination []byte
		switch node := node.(type) {
		case *ast.Link:
			destination = util.URLEscape(node.Destination, true)
		case *ast.AutoLink:
			destination = util.URLEscape(node.URL(source), false)
		default:
			return ast.WalkContinue, nil
		}

		link := string(destination)
		parsed, err := url.Parse(link)
		if _, duplicate := seen[link]; !duplicate && err == nil && (parsed.Scheme == "http" || parsed.Scheme == "https") && parsed.Hostname() != "" && parsed.User == nil {
			seen[link] = struct{}{}
			links = append(links, link)
		}
		return ast.WalkSkipChildren, nil
	})
	return links
}
