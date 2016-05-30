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
	for i := 0; i < len(elements); i++ {
		// log.Println("allows element", elements[i])  //for debug
		htmlPolicy.AllowElements(elements[i])
	}

	//allow global attributes
	for i := 0; i < len(globalAttributes); i++ {
		htmlPolicy.AllowAttrs(globalAttributes[i]).Globally()
	}

	for j := 0; j < len(attributes); j++ {
		for k := 0; k < len(attributes[j].Attributes); k++ {
			htmlPolicy.AllowAttrs(attributes[j].Attributes[k]).OnElements(attributes[j].Element)
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
	htmlPolicy.AllowAttrs("cite").Matching(regexp.MustCompile(protocol_regexp)).OnElements("q", "blockquote", "del", "ins")
	htmlPolicy.AllowAttrs("src").Matching(regexp.MustCompile(protocol_regexp)).OnElements("img")
	//allow more protocols in URL schemes
	for i := 0; i < len(protocol_schemes); i++ {
		htmlPolicy.AllowURLSchemes(protocol_schemes[i])
		// log.Println("allows protocol ",protocols[0].Protocols[i]) //for debug
	}

}
