package sanitize

<<<<<<< HEAD
<<<<<<< HEAD
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
=======
import (
	"github.com/microcosm-cc/bluemonday"
)

//custom policy
type CustomPolicy struct{
	htmlPolicy *bluemonday.Policy
	cssPolicy *CssPolicy
=======
func Sanitize(htmlIn string) string {
	return sanitizeCSS(sanitizeHTML(htmlIn))
>>>>>>> cb78ce6... make policy static, format code by gofmt; fix test
}

func sanitizeHTML(htmlIn string) string {
	return htmlPolicy.Sanitize(htmlIn)
}

func sanitizeCSS(htmlIn string) string {
	return cssPolicy.Sanitize(htmlIn)
}
<<<<<<< HEAD

func (p *CustomPolicy) sanitizeHTML(htmlIn string) string{
  return p.htmlPolicy.Sanitize(htmlIn)
}

func (p *CustomPolicy) sanitizeCSS(htmlIn string) string{
  return p.cssPolicy.Sanitize(htmlIn)
}

>>>>>>> 86f530f... refactoring code
=======
>>>>>>> cb78ce6... make policy static, format code by gofmt; fix test
