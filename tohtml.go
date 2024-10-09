package main

import (
	//"crypto/tls"
	"encoding/hex"
	"fmt"
	"time"
	//"log"
	//"net/http"
	"strconv"
	"strings"

	//"time"

	//"github.com/gin-contrib/cors"
	//"github.com/gin-contrib/static"
	//"github.com/gin-gonic/gin"
	"github.com/miekg/dns"
)

const (
	il string = "info" // style selector to use with [class^="info-"] in css for styling info links
	//hxget string = "https://ardeth.tolvmannen.se:5555/dig/info/"
	hxget string = "dig/info/"
)

func (r *DigOut) ToHTML() string {

	var out, header, question, answer, authority, opt, additional, footer string

	header = headerToHTML(r.Response)
	incl := map[string]string{
		"OP": "set",
		"QU": "set",
		"AN": "set",
		"AU": "set",
		"AD": "set",
	}
	if len(r.Response.Question) < 1 {
		incl["QU"] = "unset"
	}
	if len(r.Response.Answer) < 1 {
		incl["AN"] = "unset"
	}
	if len(r.Response.Ns) < 1 {
		incl["AU"] = "unset"
	}
	if len(r.Response.Extra) < 2 {
		incl["AD"] = "unset"
	}
	if len(r.Response.Extra) < 1 {
		incl["OP"] = "unset"
	}

	question = questonToHTML(r.Response, incl["QU"])
	answer = answerToHTML(r.Response, incl["AN"])
	authority = authorityToHTML(r.Response, incl["AU"])
	opt = optToHTML(r.Response, incl["OP"])
	additional = additionalToHTML(r.Response, incl["AD"])

	footer += "<tr>\n"
	footer += "<td colspan='5'>\n"
	// divide the Nanoseconds by 1e6 to get the Milliseconds as a int64
	footer += ";; " + htmxwrap("Query time: "+strconv.Itoa(int(r.RTT)/1e6)+" ms", "span", "Qtime", []string{il})
	footer += "</td>\n"
	footer += "</tr>\n"
	footer += "<tr>\n"
	footer += "<td colspan='5'>\n"
	footer += ";; " + htmxwrap("SERVER: "+r.Nameserver+"("+r.QNSname+") ("+r.Transport[:3]+")", "span", "Qserver", []string{il})
	footer += "</td>\n"
	footer += "</tr>\n"
	footer += "<tr>\n"
	footer += "<td colspan='5'>\n"
	footer += ";; WHEN: " + time.Now().Format(time.UnixDate)
	footer += "</td>\n"
	footer += "</tr>\n"
	footer += "<tr>\n"
	footer += "<td colspan='5'>\n"
	footer += ";; " + htmxwrap("MSG SIZE: "+strconv.Itoa(r.Response.Len()), "span", "MSGsize", []string{il})
	footer += "</td>\n"
	footer += "</tr>\n"

	out += "<table>\n"
	out += header
	out += opt
	out += question
	out += answer
	out += authority
	out += additional
	out += footer
	out += "</table>\n"

	fmt.Printf("\n%s\n", out)

	return out
}

func headerToHTML(msg *dns.Msg) string {

	opcode := dns.OpcodeToString[msg.Opcode]
	rcode := dns.RcodeToString[msg.Rcode]
	id := strconv.Itoa(int(msg.Id))

	setflag := map[string]string{
		"QR": "unset",
		"RD": "unset",
		"RA": "unset",
		"AA": "unset",
		"AD": "unset",
		"CD": "unset",
		"TC": "unset",
	}

	if msg.Response {
		setflag["QR"] = "set"
	}

	if msg.RecursionDesired {
		setflag["RD"] = "set"
	}

	if msg.RecursionAvailable {
		setflag["RA"] = "set"
	}

	if msg.Authoritative {
		setflag["AA"] = "set"
	}

	if msg.AuthenticatedData {
		setflag["AD"] = "set"
	}

	if msg.CheckingDisabled {
		setflag["CD"] = "set"
	}

	if msg.Truncated {
		setflag["TC"] = "set"
	}

	flags := []string{"QR", "RD", "RA", "AA", "AD", "CD", "TC"}
	//fmt.Printf("%#v", dns.OpcodeToString[hdr])

	//fmt.Printf("%#v", msg)

	var header string

	header += "<tr>\n"
	header += "<td colspan='5'>; <<>> NerDiG 0.10 <<>></td>\n"
	header += "</tr>\n"
	header += "<tr>\n"
	header += "<td colspan='5'>;; Got answer:</td>\n"
	header += "</tr>\n"
	header += "<tr>\n"
	header += "<td colspan='5'>\n"
	header += ";; ->>HEADER<<-" + htmxwrap(";; opcode: "+opcode+",", "span", opcode, []string{opcode, il})
	header += htmxwrap("status: "+rcode+",", "span", rcode, []string{rcode, il})
	header += htmxwrap("id: "+id, "span", "qid", []string{il})
	header += "</td>\n"
	header += "</tr>\n"
	header += "<tr>\n"
	header += "<td colspan='5'>\n"
	header += htmxwrap(";; flags: ", "span", "flags", []string{"flags", il})
	for _, flag := range flags {
		//header += htmxwrap(flag, "span class='"+setflag[flag]+"'", flag)
		header += htmxwrap(flag, "span", flag, []string{flag, il, setflag[flag]})
	}
	header += "<span class='sepcolon'>;</span>"
	header += htmxwrap("QUERY: "+strconv.Itoa(len(msg.Question))+",", "span", "QUERYcount", []string{il})
	header += htmxwrap("ANSWER: "+strconv.Itoa(len(msg.Answer))+",", "span", "ANSWERcount", []string{il})
	header += htmxwrap("AUTHORITY: "+strconv.Itoa(len(msg.Ns))+",", "span", "AUTHORITYcount", []string{il})
	header += htmxwrap("ADDITIONAL: "+strconv.Itoa(len(msg.Extra)), "span", "ADDITIONALcount", []string{il})
	header += "</td>\n"
	header += "</tr>\n"
	header += "<tr>\n<td colspan='5' class='spacer'></td></tr>\n"

	return header
}

func questonToHTML(msg *dns.Msg, status string) string {
	var question string

	question += "<tr class='" + status + "'>\n"
	question += "<td colspan='5'>\n"
	question += htmxwrap(";; QUESTION SECTION:", "span", "QUsection", []string{il})
	question += "</td>\n"
	question += "</tr>\n"
	question += "<td colspan='5'>\n"
	for _, q := range msg.Question {
		question += htmxwrap(strings.TrimSpace(q.String()), "span", "placeholder", []string{il})
	}
	question += "</td>\n"
	question += "</tr>\n"
	question += "<tr>\n<td colspan='5' class='spacer'></td></tr>\n"

	return question
}

func answerToHTML(msg *dns.Msg, status string) string {
	var answer string
	answer += "<tr class='" + status + "'>\n"
	answer += "<td colspan='5'>\n"
	answer += htmxwrap(";; ANSWER SECTION:", "span", "ANsection", []string{il})
	answer += "</td>\n"
	answer += "</tr>\n"

	for _, a := range msg.Answer {

		//fmt.Printf("%s\n", a.String())

		head := *a.Header()

		//fmt.Printf("%#v\n", head.Rrtype)

		//out += head.String()
		answer += "<tr>\n"
		answer += htmxwrap(head.Name, "td", "oname", []string{il})
		answer += htmxwrap(strconv.FormatUint(uint64(head.Ttl), 10), "td", "ttl", []string{il})
		answer += htmxwrap(dns.ClassToString[head.Class], "td", "rclass", []string{il})
		answer += htmxwrap(dns.Type(head.Rrtype).String(), "td", "rtype", []string{il})

		rdata := ""
		for i := 1; i <= dns.NumField(a); i++ {
			rdata += dns.Field(a, i) + " "
			//out += dns.Field(a, i) + " "
			//out += "<div class=\"" + rfields[i-1] + "\">" + dns.Field(a, i) + "</div>\n"
			//fmt.Printf("field %v - %#v ", i, dns.Field(a, i))
		}
		answer += htmxwrap(rdata, "td", "rdata", []string{il, "rdata"})
		answer += "</tr>\n"
	}
	answer += "<tr>\n<td colspan='5' class='spacer'></td></tr>\n"

	return answer
}

func authorityToHTML(msg *dns.Msg, status string) string {

	var authority string

	authority += "<tr class='" + status + "'>\n"
	authority += "<td colspan='5'>\n"
	authority += htmxwrap(";; AUTHORITY SECTION:", "span", "AUsection", []string{il})
	authority += "</td>\n"
	authority += "</tr>\n"
	for _, a := range msg.Ns {

		head := *a.Header()

		authority += "<tr>\n"
		authority += htmxwrap(head.Name, "td", "oname", []string{il})
		authority += htmxwrap(strconv.FormatUint(uint64(head.Ttl), 10), "td", "ttl", []string{il})
		authority += htmxwrap(dns.ClassToString[head.Class], "td", "rclass", []string{il})
		authority += htmxwrap(dns.Type(head.Rrtype).String(), "td", "rtype", []string{il})

		authority += rdatawrap(a, dns.Type(head.Rrtype).String())
		authority += "</tr>\n"
		/*
			rdata := ""
			for i := 1; i <= dns.NumField(a); i++ {
				rdata += dns.Field(a, i) + " "
			}
			authority += htmxwrap(rdata, "div", "rdata", []string{il})
		*/
	}
	authority += "<tr>\n<td colspan='5' class='spacer'></td></tr>\n"

	return authority
}

func additionalToHTML(msg *dns.Msg, status string) string {
	var additional string

	additional += "<tr class='" + status + "'>\n"
	additional += "<td colspan='5'>\n"
	//additional += htmxwrap(";; ADDITIONAL SECTION:", "span", "ADsection", []string{il, status})
	additional += htmxwrap(";; ADDITIONAL SECTION:", "span", "ADsection", []string{il})
	additional += "</td>\n"
	additional += "</tr>\n"

	for _, e := range msg.Extra {
		head := *e.Header()

		if dns.Type(head.Rrtype).String() != "OPT" {

			additional += "<tr>\n"
			additional += htmxwrap(head.Name, "td", "oname", []string{il})
			additional += htmxwrap(strconv.FormatUint(uint64(head.Ttl), 10), "td", "ttl", []string{il})
			additional += htmxwrap(dns.ClassToString[head.Class], "td", "rclass", []string{il})
			additional += htmxwrap(dns.Type(head.Rrtype).String(), "td", "rtype", []string{il})

			rdata := ""
			for i := 1; i <= dns.NumField(e); i++ {
				rdata += dns.Field(e, i) + " "
			}
			additional += htmxwrap(rdata, "td", "rdata", []string{il, "rdata"})
			additional += "</tr>\n"
		}
	}
	additional += "<tr>\n<td colspan='5' class='spacer'></td></tr>\n"

	return additional
}

func optToHTML(msg *dns.Msg, status string) string {
	var opt string

	opt += "<tr class='" + status + "'>\n"
	opt += "<td colspan='5'>\n"
	opt += htmxwrap(";; OPT PSEUDOSECTION:", "span", "OPTsection", []string{il})
	opt += "</td>"
	opt += "</tr>\n"

	for _, e := range msg.Extra {
		head := *e.Header()

		if dns.Type(head.Rrtype).String() == "OPT" {

			f := e.(*dns.OPT)

			//
			// Pretty format the OPT section like
			//
			opt += "<tr>\n"
			opt += "<td colspan='5'>\n"
			opt += htmxwrap("; EDNS: version "+strconv.Itoa(int(f.Version()))+"; ", "span", "EDNSversion", []string{il})

			var fs string
			if f.Do() {
				fs = "flags: do; "
			} else {
				fs = "flags:; "
			}
			opt += htmxwrap(fs, "span", "OPTdoflag", []string{il})

			if f.Hdr.Ttl&0x7FFF != 0 {
				ms := fmt.Sprintf("MBZ: 0x%04x, ", f.Hdr.Ttl&0x7FFF)
				opt += htmxwrap(ms, "span", "MBZ", []string{il})
			}

			opt += htmxwrap("udp: "+strconv.Itoa(int(f.UDPSize())), "span", "OPTudp", []string{il})
			opt += "</td>\n"
			opt += "</tr>\n"

			for _, o := range f.Option {
				var s string
				opt += "<tr>\n"
				opt += "<td colspan='5'>\n"
				switch o.(type) {
				case *dns.EDNS0_NSID:
					to := o.(*dns.EDNS0_NSID)
					s += "\n; NSID: " + to.String()
					h, e := PackNSID(to)
					var r string
					if e == nil {
						for _, c := range h {
							r += "(" + string(c) + ")"
						}
						s += "  " + r
					}
				case *dns.EDNS0_SUBNET:
					s += "; SUBNET: " + o.String()
				case *dns.EDNS0_COOKIE:
					s += "; COOKIE: " + o.String()
				case *dns.EDNS0_EXPIRE:
					s += "; EXPIRE: " + o.String()
				case *dns.EDNS0_TCP_KEEPALIVE:
					s += "; KEEPALIVE: " + o.String()
				case *dns.EDNS0_UL:
					s += "; UPDATE LEASE: " + o.String()
				case *dns.EDNS0_LLQ:
					s += "; LONG LIVED QUERIES: " + o.String()
				case *dns.EDNS0_DAU:
					s += "; DNSSEC ALGORITHM UNDERSTOOD: " + o.String()
				case *dns.EDNS0_DHU:
					s += "; DS HASH UNDERSTOOD: " + o.String()
				case *dns.EDNS0_N3U:
					s += "; NSEC3 HASH UNDERSTOOD: " + o.String()
				case *dns.EDNS0_LOCAL:
					s += "; LOCAL OPT: " + o.String()
				case *dns.EDNS0_PADDING:
					s += "; PADDING: " + o.String()
				case *dns.EDNS0_EDE:
					s += "; EDE: " + o.String()
				case *dns.EDNS0_ESU:
					s += "; ESU: " + o.String()
				}
				opt += htmxwrap(s, "span", "EDNSplaceholder", []string{il})
				opt += "</td>\n"
				opt += "</tr>\n"
			}

		}
	}
	opt += "<tr>\n<td colspan='5' class='spacer'></td></tr>\n"

	return opt
}

func htmxwrap(txt, tag, rfield string, cs []string) string {
	// Add classes to rr parts for styling and htmx links for info retrieval
	class := strings.Join(cs, " ")
	ws := "<" + tag + " class='" + class + "' "
	ws += "hx-get='" + hxget + rfield + "' "
	ws += "hx-target='#infobox' "
	ws += "hx-swap='innerHTML' "
	ws += ">\n" + txt + "\n</" + tag + ">\n"

	return ws

}

func rdatawrap(rr dns.RR, rtype string) string {

	rdata := ""
	wrr := ""

	// Add info for rdata
	switch rtype {
	default:
		for i := 1; i <= dns.NumField(rr); i++ {
			rdata += dns.Field(rr, i) + " "
		}
		wrr += htmxwrap(rdata, "td", "rdata", []string{il, "rdata"})
	}
	return wrr
}

func PackNSID(e *dns.EDNS0_NSID) ([]byte, error) {
	h, err := hex.DecodeString(e.Nsid)
	if err != nil {
		return nil, err
	}
	return h, nil
}
