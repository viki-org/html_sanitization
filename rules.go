package sanitize
//store elements that will be allowed in policy
var elements []string = []string{"b","em","i","strong","u","a","abbr","blockquote","br",
  "cite","code","dd","dfn","dl","dt","kbd","li","mark","ol","p","pre","q","s",
  "samp","small","strike","sub","sup","time","ul","var","address","article","aside",
  "bdi","bdo","body","caption","col","colgroup","data","del","div","figcaption","figure",
  "footer","h1","h2","h3","h4","h5","h6","head","header","hgroup","hr","html","img",
  "ins","main","nav","rp","rt","ruby","section","span","style","summary","sup","table",
  "tbody","td","tfoot","th","thead","title","tr","wbrr"}

//store attributes will be allowed on relevant element in policy
var attributes []AllowedAttributesWithElement = []AllowedAttributesWithElement{
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


//the string regexp that match protocols http or https (only for elements in tagNames)
var protocol_regexp string = `(http|https):\/\/([\w\-_]+(?:(?:\.[\w\-_]+)+))([\w\-\.,@?^=%&amp;:/~\+#]*[\w\-\@?^=%&amp;/~\+#])?`
var protocols_schemes []string = []string{"ftp","http","https","mailto"}
//store protocols will be allowed in attributes on relevant element in policy

//store tagName recognization for element with allowed only 2 protocol http and https
var tagNames []tagNameReg = []tagNameReg{
  {"<q ","</q>"},
  {"<blockquote","</blockquote>"},
  {"<del","</del>"},
  {"<img","/>"},
  {"<ins","</ins>"} }

