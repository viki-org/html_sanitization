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

func array_copy(arr []string) []string {
	newArr := make([]string, len(arr))
	copy(newArr, arr)

	return newArr
}

func init() {
	cssPolicy.PrefixAllowed = array_copy(CssPropertyPrefix)
	cssPolicy.PropertiesWithPrefix = make(map[string]([]string))
	cssPolicy.PropertiesWithPrefix["-moz-"] = array_copy(MozPrefixProperties)
	cssPolicy.PropertiesWithPrefix["-ms-"] = array_copy(MsPrefixProperties)
	cssPolicy.PropertiesWithPrefix["-webkit-"] = array_copy(WebkitPrefixProperties)
	cssPolicy.NormalProperties = array_copy(NormalCssProperties)
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
	//checking style of each node and each child recursively
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
	//split style to declaration blocks
	styleArray := strings.Split(style, ";")

	var styleSanitized string = ""

	for _, styleEach := range styleArray {
		var buffer bytes.Buffer

		//trim trailing space
		styleEach = strings.TrimSpace(styleEach)

		//take comment out
		p.takeCommentOut(styleEach, buffer)

		//no declaration found this string
		if !strings.Contains(styleEach, ":") {
			continue
		}
		//separate property and value
		arr := strings.Split(styleEach, ":")
		//check for valid declaration, arr should contain only 2 element, property and value
		if len(arr) > 2 {
			continue
		}
		//get valid value
		v := strings.Split(arr[1], " ")
		value := v[0]

		//get valid property
		k := strings.Split(arr[0], " ")
		property := k[len(k)-1]

		//check if property in the list and add to sanitized style if match
		if found, styleString := p.searchProperty(property, value, buffer); found {
			styleSanitized += styleString
		}

	}

	return styleSanitized
}

/*style declaration example:
style="width:91px;-moz-font-style:italic"
propety "width" will be seach in list of NormalProperties
property "-moz-" will be search in list of MozPrefixProperties
*/
func (p *CssPolicy) searchProperty(property string, value string, buffer bytes.Buffer) (bool, string) {
	//check whether style with prefix -moz-, -ms-, -webkit- or normal to get the
	//relevant list for search
	if string(property[0]) == "-" {
		for _, prefix := range (*p).PrefixAllowed {
			if property[:len(prefix)] == prefix {
				arrSearch := (*p).PropertiesWithPrefix[prefix]
				postfixProperty := property[len(prefix):]

				// search among list of postfix to find the match, if match stores this style declaration
				index := sort.SearchStrings(arrSearch, postfixProperty)
				if index < len(arrSearch) && arrSearch[index] == postfixProperty {
					buffer.WriteString(property + ":" + value + ";")
					return true, buffer.String()
				}
			}
		}

	} else {
		// search among list of properties to find the match, if match stores this style declaration
		arrSearch := (*p).NormalProperties
		index := sort.SearchStrings(arrSearch, property)

		if index < len(arrSearch) && arrSearch[index] == property {
			buffer.WriteString(property + ":" + value + ";")
			return true, buffer.String()
		}
	}

	return false, ""
}

// "/*font-size:13pt*/font-style:italic;" will become "font-style:italic" and comment stored in buffer

func (p *CssPolicy) takeCommentOut(style string, buffer bytes.Buffer) string {
	//take comment out from style string to buffer
	for {
		commentStart := strings.Index(style, "/*")
		if commentStart == -1 {
			break
		}

		commentEnd := strings.Index(style[commentStart:], "*/")
		if commentEnd == -1 {
			break
		}
		commentEnd += 2
		buffer.WriteString(style[commentStart:commentEnd])
		style = style[commentEnd+1:]
	}

	style = strings.TrimSpace(style)
	return style
}
