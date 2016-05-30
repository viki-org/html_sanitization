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
		for _, attr := range attrs.Attributes {
			htmlPolicy.AllowAttrs(attr).OnElements(attrs.Element)
			// log.Println("allows attr",attributes[j].Attributes[k], " on element ", attributes[j].Element) //for debug
		}
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
	for _, protocol := range protocol_schemes {
		htmlPolicy.AllowURLSchemes(protocol)
		// log.Println("allows protocol ",protocols[0].Protocols[i]) //for debug
	}

}
