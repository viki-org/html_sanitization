package sanitize

import (
  "github.com/microcosm-cc/bluemonday"
  "regexp"
)

//Get the HMTL Policy
func GetHTMLPolicy() *bluemonday.Policy{
  var p *bluemonday.Policy = bluemonday.NewPolicy()
        //allow elements
  for i := 0; i < len(elements) ; i++ {
    // log.Println("allows element", elements[i])  //for debug
    p.AllowElements(elements[i])
  }

  //allow global attributes
  for i:= 0; i < len(globalAttributes); i++ {
    p.AllowAttrs(globalAttributes[i]).Globally()  
  }
  
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
  for i:=0; i < len(protocol_schemes); i++{
    p.AllowURLSchemes(protocol_schemes[i])
    // log.Println("allows protocol ",protocols[0].Protocols[i]) //for debug
  }
       //return the policy
  return p
}
