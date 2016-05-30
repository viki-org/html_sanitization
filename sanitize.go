package sanitize

func Sanitize(htmlIn string) string {
	// Sanitize the HTML document
	return sanitizeCSS(sanitizeHTML(htmlIn))
}

func sanitizeHTML(htmlIn string) string {
	// Sanitize HTML elements, attributes and protocols
	return htmlPolicy.Sanitize(htmlIn)
}

func sanitizeCSS(htmlIn string) string {
	// Sanitize CSS styles
	return cssPolicy.Sanitize(htmlIn)
}
