package sanitize

import (
	"github.com/microcosm-cc/bluemonday"
)

//custom policy
type CustomPolicy struct{
	htmlPolicy *bluemonday.Policy
	cssPolicy *CssPolicy
}




//Get Our Custom Policy
func GetPolicy() *CustomPolicy{
  cp := &CustomPolicy{
    htmlPolicy : GetHTMLPolicy(),
    cssPolicy : GetCSSPolicy()}
  return cp
}

func (cp *CustomPolicy) Sanitize(htmlIn string) string{
  return cp.sanitizeCSS(cp.sanitizeHTML(htmlIn))
}

func (p *CustomPolicy) sanitizeHTML(htmlIn string) string{
  return p.htmlPolicy.Sanitize(htmlIn)
}

func (p *CustomPolicy) sanitizeCSS(htmlIn string) string{
  return p.cssPolicy.Sanitize(htmlIn)
}

