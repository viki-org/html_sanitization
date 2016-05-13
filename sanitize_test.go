package sanitize

import (
	"github.com/viki-org/gspec"
	"testing"
)

func TestEliminateUnallowedElement(t *testing.T) {
	spec := gspec.New(t)
	input := `<h2 style="font-style:italic;">review<sub>snsd</sub></h2>
<p><script>function funct() {}</script></p>`
	output := `<h2 style="font-style:italic;">review<sub>snsd</sub></h2>
<p></p>`
	unexpected_output := `<h2 style="font-style:italic;">review<sub>snsd</sub></h2>
<script>function funct() {}</script>`
	spec.Expect(Sanitize(input)).ToEqual(output)
	spec.Expect(Sanitize(input)).ToNotEqual(unexpected_output)
}

func TestEliminateUnallowedAttribute(t *testing.T) {
	spec := gspec.New(t)
	input := `<table border="1" cellpadding="1" cellspacing="1" style="width:500px;">
    <tbody>
        <tr>
            <td>a</td>
            <td>b</td>  
        </tr>
        <tr>
            <td>a</td>
            <td>b</td>  
        </tr>
        <tr>
            <td>a</td>
            <td onclick="onFunc()">b</td>  
        </tr>  
    </tbody>  
</table>`

	output := `<table border="1" cellpadding="1" cellspacing="1" style="width:500px;">
    <tbody>
        <tr>
            <td>a</td>
            <td>b</td>  
        </tr>
        <tr>
            <td>a</td>
            <td>b</td>  
        </tr>
        <tr>
            <td>a</td>
            <td>b</td>  
        </tr>  
    </tbody>  
</table>`
	unexpected_output := `<table border="1" cellpadding="1" cellspacing="1" style="width:500px;">
    <tbody>
        <tr>
            <td>a</td>
            <td>b</td>  
        </tr>
        <tr>
            <td>a</td>
            <td>b</td>  
        </tr>
        <tr>
            <td>a</td>
            <td onclick="onFunc()">b</td>  
        </tr>  
    </tbody>  
</table>`
	spec.Expect(Sanitize(input)).ToEqual(output)
	spec.Expect(Sanitize(input)).ToNotEqual(unexpected_output)

}
func TestEliminateUnallowedProtocol(t *testing.T) {
	spec := gspec.New(t)
	input := `<table border="1" cellpadding="1" cellspacing="1" style="width:500px;">
    <tbody>
        <tr>
            <td>a</td>
            <td>b</td>  
        </tr>
        <tr>
            <td>a</td>
            <td>b</td>  
        </tr>
        <tr>
            <td>a</td>
            <td>b</td>  
        </tr>  
    </tbody>  
</table>
<p> </p>
<h2>review
    <sub>snsd</sub>
</h2>
<p>
    <img alt="no img" src="otp://0.viki.io/a/bg/viki-r-02adc744596524946c427e998e706ec2.png" style="height:32px; width:91px;"/>
</p>`
	output := `<table border="1" cellpadding="1" cellspacing="1" style="width:500px;">
    <tbody>
        <tr>
            <td>a</td>
            <td>b</td>  
        </tr>
        <tr>
            <td>a</td>
            <td>b</td>  
        </tr>
        <tr>
            <td>a</td>
            <td>b</td>  
        </tr>  
    </tbody>  
</table>
<p> </p>
<h2>review
    <sub>snsd</sub>
</h2>
<p>
    <img alt="no img" style="height:32px;width:91px;"/>
</p>`
	unexpected_output_1 := `<table border="1" cellpadding="1" cellspacing="1" style="width:500px">
    <tbody>
        <tr>
            <td>a</td>
            <td>b</td>  
        </tr>
        <tr>
            <td>a</td>
            <td>b</td>  
        </tr>
        <tr>
            <td>a</td>
            <td>b</td>  
        </tr>  
    </tbody>  
</table>
<p> </p>
<h2>review
    <sub>snsd</sub>
</h2>
<p>
</p>`
	unexpected_output_2 := `<table border="1" cellpadding="1" cellspacing="1" style="width:500px">
    <tbody>
        <tr>
            <td>a</td>
            <td>b</td>  
        </tr>
        <tr>
            <td>a</td>
            <td>b</td>  
        </tr>
        <tr>
            <td>a</td>
            <td>b</td>  
        </tr>  
    </tbody>  
</table>
<p> </p>
<h2>review
    <sub>snsd</sub>
</h2>
<p>
</p>`
	spec.Expect(Sanitize(input)).ToEqual(output)
	spec.Expect(Sanitize(input)).ToNotEqual(unexpected_output_1)
	spec.Expect(Sanitize(input)).ToNotEqual(unexpected_output_2)

}
