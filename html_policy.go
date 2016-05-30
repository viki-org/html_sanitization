package sanitize

import (
	"github.com/microcosm-cc/bluemonday"
	"regexp"
)

var htmlPolicy *bluemonday.Policy

//Get the HMTL Policy
func GetHTMLPolicy() *bluemonday.Policy {
	return htmlPolicy
}

func init() {
	htmlPolicy = bluemonday.NewPolicy()
	//allow elements
	htmlPolicy.AllowElements(elements...)
	//allow global attributes
	htmlPolicy.AllowAttrs(globalAttributes...).Globally()

	for _, attrs := range attributesWithElement {
		htmlPolicy.AllowAttrs(attrs.Attributes...).OnElements(attrs.Element)
	}

	//allow relative URL
	htmlPolicy.AllowRelativeURLs(true)
	//add rel="nofollow" on links in href
	htmlPolicy.RequireNoFollowOnLinks(true)

	//allow <!DOCTYPE HTML>
	htmlPolicy.AllowDocType(true)

	//special case to set protocols allowed for tag p
	htmlPolicy.AllowAttrs("cite").Matching(regexp.MustCompile(protocol_regexp)).OnElements(tagNameWithTwoProtocols...)
	htmlPolicy.AllowAttrs("src").Matching(regexp.MustCompile(protocol_regexp)).OnElements("img")
	//allow more protocols in URL schemes
	htmlPolicy.AllowURLSchemes(protocol_schemes...)

}
