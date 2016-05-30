package sanitize

func Sanitize(htmlIn string) string {
	return sanitizeCSS(sanitizeHTML(htmlIn))
}

func sanitizeHTML(htmlIn string) string {
	return htmlPolicy.Sanitize(htmlIn)
}

func sanitizeCSS(htmlIn string) string {
	return cssPolicy.Sanitize(htmlIn)
}
