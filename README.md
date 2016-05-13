#HTML Sanitization

## What is it?
This Golang project does the same work as the ruby gem used in oceanus to sanitize the HTML in cover pages and community walls. From `microcosm-cc\bluemonday` basic policy and functions, we build our own policy for specific used.
We allow these elements:
```sh
"b","em","i","strong","u","a","abbr","blockquote","br",
	"cite","code","dd","dfn","dl","dt","kbd","li","mark","ol","p","pre","q","s",
	"samp","small","strike","sub","sup","time","ul","var","address","article","aside",
	"bdi","bdo","body","caption","col","colgroup","data","del","div","figcaption","figure",
	"footer","h1","h2","h3","h4","h5","h6","head","header","hgroup","hr","html","img",
	"ins","main","nav","rp","rt","ruby","section","span","style","summary","sup","table",
	"tbody","td","tfoot","th","thead","title","tr","wbrr"
```
We allow the attributes
 * global attributes

```sh
 "class","dir","hidden","id","lang","style","yabeindex","title","translate"
```
 * attributes on specific elements
```sh
	{ Element:"a" ,Attributes:[]string{"href","rel","hreflang","name"} },
		{ Element:"abbr", Attributes:[]string{"title"} },
		{ Element:"blockquote", Attributes:[]string{"cite"} },
		{ Element:"col", Attributes:[]string{"span","width"} },
		{ Element:"colgroup", Attributes:[]string{"span","width"} },
		{ Element:"data", Attributes:[]string{"value"} },
		{ Element:"del", Attributes:[]string{"cite","datetime"} },
		{ Element:"dfn", Attributes:[]string{"title"} },
		{ Element:"img", Attributes:[]string{"align","alt","border","height","src","width"} },
		{ Element:"ins", Attributes:[]string{"cite","datetime"} },
		{ Element:"li", Attributes:[]string{"value"} },
		{ Element:"ol", Attributes:[]string{"reversed","start","type"} },
		{ Element:"q", Attributes:[]string{"cite"} },
		{ Element:"style", Attributes:[]string{"media","scoped","type"} },
		{ Element:"table", Attributes:[]string{"align","bgcolor","border","cellpadding","cellspacing","frame","rules","sortable","summary","width"} },
		{ Element:"td", Attributes:[]string{"abbr","align","axis","colspan","headers","rowspan","valign","width"} },
		{ Element:"th", Attributes:[]string{"abbr","align","axis","colspan","headers","rowspan","scope","sorted","valign","width"} },
		{ Element:"time", Attributes:[]string{"time"} },
		{ Element:"ul", Attributes:[]string{"type"} } }

```

* protocols 
```sh
'a'          => {'href' => ['ftp', 'http', 'https', 'mailto', :relative]},
'blockquote' => {'cite' => ['http', 'https', :relative]},
'q'          => {'cite' => ['http', 'https', :relative]}

'del' => {'cite' => ['http', 'https', :relative]},
'img' => {'src'  => ['http', 'https', :relative]},
'ins' => {'cite' => ['http', 'https', :relative]}
```

## Differents with old ruby gems:
Since the restriction in `bluemonday` rule, we don't check `CSS` rules. It will not affect perfomance since all CSS rules are generated by editor.

## How to use it
```sh
  go get github.com/viki-org/html_sanitization
```
* Import to your project
```sh
	import "github.com/viki-org/html_sanitization"
```
* To do sanitization with string input
```sh
	sanitize.Sanitize(htmlIn)
```

## Testing
See sanitize_test.go for some built tests using gspec