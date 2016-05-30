package sanitize

import (
	"bytes"
	html "golang.org/x/net/html"
	"log"
	"sort"
	"strings"
)

type CssPolicy struct {
	PrefixAllowed        []string
	PropertiesWithPrefix map[string]([]string)
	NormalProperties     []string
}

var cssPolicy CssPolicy

func init() {
	cssPolicy.PrefixAllowed = make([]string, len(CssPropertyPrefix))
	cssPolicy.PropertiesWithPrefix = make(map[string]([]string))
	cssPolicy.NormalProperties = make([]string, len(NormalCssProperties))
	cssPolicy.PropertiesWithPrefix["-moz-"] = make([]string, len(MozPrefixProperties))
	cssPolicy.PropertiesWithPrefix["-ms-"] = make([]string, len(MsPrefixProperties))
	cssPolicy.PropertiesWithPrefix["-webkit-"] = make([]string, len(WebkitPrefixProperties))
	copy(cssPolicy.PrefixAllowed, CssPropertyPrefix)
	copy(cssPolicy.PropertiesWithPrefix["-moz-"], MozPrefixProperties)
	copy(cssPolicy.PropertiesWithPrefix["-ms-"], MsPrefixProperties)
	copy(cssPolicy.PropertiesWithPrefix["-webkit-"], WebkitPrefixProperties)
	copy(cssPolicy.NormalProperties, NormalCssProperties)
}

//Get CSS Policy
func GetCSSPolicy() *CssPolicy {
	return &cssPolicy
}

func (p *CssPolicy) Sanitize(htmlIn string) string {
	doc, err := html.Parse(strings.NewReader(htmlIn))
	if err != nil {
		log.Fatal(err)
	}

	doc = p.sanitizeCSSOfHTMLNode(doc).FirstChild.FirstChild.NextSibling

	var htmlOut string
	for child := doc.FirstChild; child != nil; child = child.NextSibling {
		var buffer bytes.Buffer
		if err := html.Render(&buffer, child); err != nil {
			log.Println("Render error: %s \n", err)
		}
		htmlOut += buffer.String()

	}
	return strings.TrimSpace(htmlOut)
}

func (p *CssPolicy) sanitizeCSSOfHTMLNode(node *html.Node) *html.Node {
	if node.Type == html.ElementNode {
		var Attrs []html.Attribute
		for _, attr := range node.Attr {
			if attr.Key == "style" {
				attr.Val = p.validateStyle(attr.Val)
			}
			if attr.Val != "" {
				Attrs = append(Attrs, attr)
			}
		}
		node.Attr = Attrs

	}

	for child := node.FirstChild; child != nil; child = child.NextSibling {
		child = p.sanitizeCSSOfHTMLNode(child)
	}

	return node
}

func (p *CssPolicy) validateStyle(style string) string {
	styleArray := strings.Split(style, ";")

	var styleSanitized string = ""

	for i := 0; i < len(styleArray); i++ {
		var buffer bytes.Buffer
		//trim space and begin and end

		var styleEach string = strings.TrimSpace(styleArray[i])

		//no declaration found this string
		if !strings.Contains(styleEach, ":") {

			continue
		}

		//take comment out
		for {
			commentStart := strings.Index(styleEach, "/*")
			if commentStart == -1 {
				break
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
		v := strings.Split(arr[1], " ")
		val := v[0]

		//valid property
		k := strings.Split(arr[0], " ")
		property := k[len(k)-1]

		if string(property[0]) == "-" {
			for i := 0; i < len((*p).PrefixAllowed); i++ {
				prefix := (*p).PrefixAllowed[i]
				if property[:len(prefix)] == prefix {

					arrSearch := (*p).PropertiesWithPrefix[prefix]
					postfixProperty := property[len(prefix):]
					index := sort.SearchStrings(arrSearch, postfixProperty)
					if index < len(arrSearch) && arrSearch[index] == postfixProperty {
						buffer.WriteString(property + ":" + val + ";")
						styleSanitized += buffer.String()
					}
				}
			}

		} else {
			arrSearch := (*p).NormalProperties
			index := sort.SearchStrings(arrSearch, property)

			if index < len(arrSearch) && arrSearch[index] == property {
				buffer.WriteString(property + ":" + val + ";")
				styleSanitized += buffer.String()
			}
		}

	}

	return styleSanitized
}
