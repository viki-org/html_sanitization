package sanitize

import (
	"fmt"
	"github.com/microcosm-cc/bluemonday"
	html "golang.org/x/net/html"
	"log"
	"regexp"
	//"sort"
	"strings"
)

//custom policy
type CustomPolicy struct{
	HTMLPolicy *bluemonday.Policy
	CSSPolicy CssPolicy
}

type CssPolicy struct{
	PrefixAllowed []string
	PropertiesWithPrefix map[string]([]string)
	NormalProperties []string
}
//pair element with attribute allowed
type AllowedAttributesWithElement struct{
	Element string
	Attributes []string
}


//tagName regonization for tag that have protocol policy
type tagNameReg struct{
	Open string
	Close string
}

//Get Our Custom Policy
func GetPolicy() CustomPolicy{
  var cp CustomPolicy
  cp.HTMLPolicy = GetHTMLPolicy()
  cp.CSSPolicy = GetCSSPolicy()
  return cp
}

func (cp CustomPolicy) Sanitize(htmlIn string) string{
  htmlPolicy := cp.HTMLPolicy
  htmlSanitized := htmlPolicy.Sanitize(htmlIn)
  fullSanitized := cp.CSSPolicy.Sanitize(htmlSanitized)
  return fullSanitized
}

//Get the HMTL Policy
func GetHTMLPolicy() *bluemonday.Policy{
	var p *bluemonday.Policy = bluemonday.NewPolicy()
        //allow elements
	for i := 0; i < len(elements) ; i++ {
		// log.Println("allows element", elements[i])  //for debug
		p.AllowElements(elements[i])
	}
	//allow attributes
	p.AllowAttrs("class","dir","hidden","id","lang","style","yabeindex","title","translate").Globally()
	for j:= 0; j < len(attributes); j++{
		for k:=0; k < len(attributes[j].Attributes); k++{
			p.AllowAttrs(attributes[j].Attributes[k]).OnElements(attributes[j].Element)
			// log.Println("allows attr",attributes[j].Attributes[k], " on element ", attributes[j].Element) //for debug
		}
	}

	//allow relative URL
	p.AllowRelativeURLs(true)
	//add rel="nofollow" on links in href
	p.RequireNoFollowOnLinks(true)

	//allow <!DOCTYPE HTML>
	p.AllowDocType(true)


	//special case to set protocols allowed for tag p
	p.AllowAttrs("cite").Matching(regexp.MustCompile(protocol_regexp)).OnElements("q","blockquote","del","ins")
	p.AllowAttrs("src").Matching(regexp.MustCompile(protocol_regexp)).OnElements("img")
	//allow more protocols in URL schemes
	for i:=0; i < len(protocols_schemes); i++{
		p.AllowURLSchemes(protocols_schemes[i])
		// log.Println("allows protocol ",protocols[0].Protocols[i]) //for debug
	}
       //return the policy
       return p
}

//Get CSS Policy
func GetCSSPolicy() CssPolicy{
	var p CssPolicy
	copy(p.PrefixAllowed,CssPropertyPrefix)
	copy(p.PropertiesWithPrefix["-moz-"], MozPrefixProperties)
	copy(p.PropertiesWithPrefix["-ms-"], MsPrefixProperties)
  copy(p.PropertiesWithPrefix["-webkit-"], WebkitPrefixProperties)
	copy(p.NormalProperties, NormalCssProperties)
	return p
}

func (p CssPolicy) Sanitize(htmlIn string) string{
  doc, err := html.Parse(strings.NewReader(htmlIn))
	if err != nil {
	  log.Fatal(err)
	}
	var f func(*html.Node)
	f = func(n *html.Node) {
	  if n.Type == html.ElementNode {
	      for _, a := range n.Attr {
	          if a.Key == "style" {
	              fmt.Println(a.Val)
	              break
	          }
	      }
	  }
	  for c := n.FirstChild; c != nil; c = c.NextSibling {
	      f(c)
	  }
	}
	f(doc)
	return htmlIn
}



