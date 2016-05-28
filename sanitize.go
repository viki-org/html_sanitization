package sanitize

import (
	"bytes"
	//"fmt"
	"github.com/microcosm-cc/bluemonday"
	html "golang.org/x/net/html"
	"log"
	"regexp"
	//"strconv"
	"sort"
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
  htmlSanitized := cp.HTMLPolicy.Sanitize(htmlIn)
  fullSanitized := sanitizeCSS(cp.CSSPolicy, htmlSanitized)
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

//Get CSS Policy
func GetCSSPolicy() CssPolicy{
	var p CssPolicy
	p.PrefixAllowed = make([]string, len(CssPropertyPrefix))
	p.PropertiesWithPrefix = make(map[string]([]string))
	p.PropertiesWithPrefix["-moz-"] = make([]string, len(MozPrefixProperties))
	p.PropertiesWithPrefix["-ms-"] = make([]string, len(MsPrefixProperties))
	p.PropertiesWithPrefix["-webkit-"] =make([]string, len(WebkitPrefixProperties))
	p.NormalProperties = make([]string, len(NormalCssProperties))
	copy(p.PrefixAllowed,CssPropertyPrefix)
	copy(p.PropertiesWithPrefix["-moz-"], MozPrefixProperties)
	copy(p.PropertiesWithPrefix["-ms-"], MsPrefixProperties)
  copy(p.PropertiesWithPrefix["-webkit-"], WebkitPrefixProperties)
	copy(p.NormalProperties, NormalCssProperties)
	return p
}

func sanitizeCSS(p CssPolicy, htmlIn string) string{
  doc, err := html.Parse(strings.NewReader(htmlIn))
	if err != nil {
		log.Fatal(err)
	}

  doc = sanitizeHTMLNode(p, doc)

  var buffer bytes.Buffer 
  if err := html.Render(&buffer, doc) ; err != nil {
  	log.Println("Render error: %s \n", err)
  }
  return buffer.String()
}

func sanitizeHTMLNode(p CssPolicy, node *html.Node) *html.Node{
  if node.Type == html.ElementNode {
  	  var Attrs []html.Attribute
	      for _, attr := range node.Attr {
          if attr.Key == "style" {
              attr.Val = sanitizeStyle(p, attr.Val)
          }
          if attr.Val != ""{  
          Attrs = append(Attrs, attr)
	        }
	      }
	      node.Attr = Attrs

	  }
	
	for child := node.FirstChild; child != nil; child = child.NextSibling {
	      child = sanitizeHTMLNode(p, child)
	}

	
  return node
}

func sanitizeStyle(p CssPolicy, style string) string{
	styleArray := strings.Split(style,";")
	var styleSanitized string = ""

	for i := 0; i < len(styleArray); i++{
		var buffer bytes.Buffer
		//trim space and begin and end
		var styleEach string= strings.TrimSpace(styleArray[i])

		//no declaration found this string
		if !strings.Contains(styleEach,":") {

			continue 
		}
    


    //take comment out
	  for {
			commentStart := strings.Index(styleEach, "/*")
			if commentStart == -1 {
				break;
			}
			commentEnd := strings.Index(styleEach[commentStart:], "*/") + 2
			buffer.WriteString(" " + styleEach[commentStart:commentEnd] + " ")
			styleEach = styleEach[commentEnd+1:]
		} 



		styleEach = strings.TrimSpace(styleEach)
		
		//seperate property and value
		arr := strings.Split(styleEach, ":")
		//check for valid declaration
		if len(arr) > 2 {
			continue
		}
		v := strings.Split(arr[1]," ")
    val := v[0]

	  //valid property
		key := strings.Split(arr[0]," ")
		property := key[len(key)-1]
 

    if string(property[0]) == "-" {
    	for i := 0; i < len(p.PrefixAllowed) ; i++ {
	    	if property[:len(p.PrefixAllowed[i])] == p.PrefixAllowed[i] {

	    		arrSearch := p.PropertiesWithPrefix[p.PrefixAllowed[i]]
	    		postfixProperty := property[len(p.PrefixAllowed[i]):]
	        index:= sort.SearchStrings( arrSearch, postfixProperty)
	        if index < len(arrSearch) && arrSearch[index] == postfixProperty {
	        	buffer.WriteString(" " + property + ":" + val + ";")
	          styleSanitized += buffer.String()

	          break;
	        }
	      }
	    }

    } else{
    	arrSearch := p.NormalProperties
    	index:= sort.SearchStrings( arrSearch, property)

	    if index < len(arrSearch) && arrSearch[index] == property{
      	buffer.WriteString(" " + property + ":" + val + ";")
        styleSanitized += buffer.String()
 
        break;
	    }
    }

	}

  return styleSanitized
}

