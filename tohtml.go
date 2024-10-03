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
	//respstring := fmt.Sprintf("%#v", r.Response)
	//fmt.Printf("Extra \n%#v\n", r.Response.Extra)
	//ans := r.Response.Answer
	//fmt.Printf("%#v", ans)
	//fmt.Printf("Is AA? %#v", r.Response.Authoritative)

	//nocryptoMsg(r.Response)

	// strconv.FormatUint(uint64(n), 10)
	opcode := dns.OpcodeToString[r.Response.Opcode]
	rcode := dns.RcodeToString[r.Response.Rcode]
	id := strconv.Itoa(int(r.Response.Id))

	setflag := map[string]string{
		"QR": "unset",
		"RD": "unset",
		"RA": "unset",
		"AA": "unset",
		"AD": "unset",
		"CD": "unset",
		"TC": "unset",
	}

	if r.Response.Response {
		setflag["QR"] = "set"
	}

	if r.Response.RecursionDesired {
		setflag["RD"] = "set"
	}

	if r.Response.RecursionAvailable {
		setflag["RA"] = "set"
	}

	if r.Response.Authoritative {
		setflag["AA"] = "set"
	}

	if r.Response.AuthenticatedData {
		setflag["AD"] = "set"
	}

	if r.Response.CheckingDisabled {
		setflag["CD"] = "set"
	}

	if r.Response.Truncated {
		setflag["TC"] = "set"
	}

	flags := []string{"QR", "RD", "RA", "AA", "AD", "CD", "TC"}
	//fmt.Printf("%#v", dns.OpcodeToString[hdr])

	//fmt.Printf("%#v", r.Response)

	var out, header, question, answer, authority, opt, additional, footer string

	header += "<div class='digheader'>\n"
	header += "<span>"
	header += "<span>; <<>> NerDiG 0.10 <<>></span><br/>"
	header += "<span>;; Got answer: </span><br/>"
	header += "</span><br/>"
	header += "<span>"
	header += ";; ->>HEADER<<-" + htmxwrap(";; opcode: "+opcode+",", "span", opcode, []string{opcode, il})
	header += htmxwrap("status: "+rcode+",", "span", rcode, []string{rcode, il})
	header += htmxwrap("id: "+id, "span", "qid", []string{il})
	header += "<br/>"
	header += "</span>"
	header += "<span>"
	header += htmxwrap(";; flags: ", "span", "flags", []string{"flags", il})
	for _, flag := range flags {
		//header += htmxwrap(flag, "span class='"+setflag[flag]+"'", flag)
		header += htmxwrap(flag, "span", flag, []string{flag, il, setflag[flag]})
	}
	header += "<span class='sepcolon'>;</span>"
	header += htmxwrap("QUERY: "+strconv.Itoa(len(r.Response.Question))+",", "span", "QUERYcount", []string{il})
	header += htmxwrap("ANSWER: "+strconv.Itoa(len(r.Response.Answer))+",", "span", "ANSWERcount", []string{il})
	header += htmxwrap("AUTHORITY: "+strconv.Itoa(len(r.Response.Ns))+",", "span", "AUTHORITYcount", []string{il})
	header += htmxwrap("ADDITIONAL: "+strconv.Itoa(len(r.Response.Extra)), "span", "ADDITIONALcount", []string{il})
	header += "</span>"
	header += "</div>\n"

	/*
		for _, a := range r.Response.Answer {
			//out += strconv.Quote(a.String()) + "\n"
			//out += "<tr>\n\t<td>" + strings.Replace(a.String(), "\t", "</td>\n\t<td>", -1) + "</td>\n</tr>\n"
			out += "<div>" + strings.Replace(a.String(), "\t", "</div>\n<div>", -1) + "</div>\n"
		}
	*/

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
	/*
		header += htmxwrap("ANSWER: "+strconv.Itoa(len(r.Response.Answer))+",", "span", "ANSWERcount")
		header += htmxwrap("AUTHORITY: "+strconv.Itoa(len(r.Response.Ns))+",", "span", "AUTHORITYcount")
		header += htmxwrap("ADDITIONAL: "+strconv.Itoa(len(r.Response.Extra)), "span", "ADDITIONALcount")
	*/
	question += "<div class='digheader'>\n"
	//question += "<span class=" + incl["QU"] + ">;; QUESTION SECTION:</span><br/>"
	question += htmxwrap(";; QUESTION SECTION:", "span", "QUsection", []string{il, incl["QU"]})
	for _, q := range r.Response.Question {
		question += htmxwrap(strings.TrimSpace(q.String()), "span", "placeholder", []string{il})
	}
	question += "</div>\n"

	answer += "<div class='digheader'>\n"
	//answer += "<span class=" + incl["AN"] + ">;; ANSWER SECTION:</span><br/>"
	answer += htmxwrap(";; ANSWER SECTION:", "span", "ANsection", []string{il, incl["AN"]})
	answer += "</div>\n"
	for _, a := range r.Response.Answer {

		//fmt.Printf("%s\n", a.String())

		head := *a.Header()

		//fmt.Printf("%#v\n", head.Rrtype)

		//out += head.String()
		answer += htmxwrap(head.Name, "div", "oname", []string{il})
		answer += htmxwrap(strconv.FormatUint(uint64(head.Ttl), 10), "div", "ttl", []string{il})
		answer += htmxwrap(dns.ClassToString[head.Class], "div", "rclass", []string{il})
		answer += htmxwrap(dns.Type(head.Rrtype).String(), "div", "rtype", []string{il})

		rdata := ""
		for i := 1; i <= dns.NumField(a); i++ {
			rdata += dns.Field(a, i) + " "
			//out += dns.Field(a, i) + " "
			//out += "<div class=\"" + rfields[i-1] + "\">" + dns.Field(a, i) + "</div>\n"
			//fmt.Printf("field %v - %#v ", i, dns.Field(a, i))
		}
		answer += htmxwrap(rdata, "div", "rdata", []string{il})

	}

	authority += "<div class='digheader'>\n"
	//authority += "<span class=" + incl["AU"] + ">;; AUTHORITY SECTION:</span><br/>"
	authority += htmxwrap(";; AUTHORITY SECTION:", "span", "AUsection", []string{il, incl["AU"]})
	authority += "</div>\n"
	for _, a := range r.Response.Ns {

		head := *a.Header()

		authority += htmxwrap(head.Name, "div", "oname", []string{il})
		authority += htmxwrap(strconv.FormatUint(uint64(head.Ttl), 10), "div", "ttl", []string{il})
		authority += htmxwrap(dns.ClassToString[head.Class], "div", "rclass", []string{il})
		authority += htmxwrap(dns.Type(head.Rrtype).String(), "div", "rtype", []string{il})

		authority += rdatawrap(a, dns.Type(head.Rrtype).String())
		/*
			rdata := ""
			for i := 1; i <= dns.NumField(a); i++ {
				rdata += dns.Field(a, i) + " "
			}
			authority += htmxwrap(rdata, "div", "rdata", []string{il})
		*/
	}

	opt += "<div class='digheader'>\n"
	//opt += "<span class=" + incl["OP"] + ">;; OPT PSEUDOSECTION:</span><br/>"
	opt += htmxwrap(";; OPT PSEUDOSECTION:", "span", "OPTsection", []string{il, incl["OP"]})

	additional += "<div class='digheader'>\n"
	//additional += "<span class=" + incl["AD"] + ">;; ADDITIONAL SECTION:</span><br/>"
	additional += htmxwrap(";; ADDITIONAL SECTION:", "span", "ADsection", []string{il, incl["AD"]})
	additional += "</div>\n"

	for _, e := range r.Response.Extra {
		head := *e.Header()

		// There has GOT to be a better and simpler way to do this

		if dns.Type(head.Rrtype).String() == "OPT" {

			f := e.(*dns.OPT)

			//
			// Pretty format the OPT section like
			//
			opt += "<span>"
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
			opt += "</span><br/>\n"

			for _, o := range f.Option {
				var s string
				opt += "<span>"
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
				opt += "</span><br/>\n"
			}

			/*
				rdata := ""
				for i := 1; i <= dns.NumField(e); i++ {
					f := dns.Field(e, i)
					fmt.Printf("%#v", f)
					//rdata += dns.Field(e, i) + " "
				}
				fmt.Printf("optdata:%v\n", rdata)
			*/
			//		fmt.Printf("REC:\n %#v\n", e)

		} else {

			additional += htmxwrap(head.Name, "div", "oname", []string{il})
			additional += htmxwrap(strconv.FormatUint(uint64(head.Ttl), 10), "div", "ttl", []string{il})
			additional += htmxwrap(dns.ClassToString[head.Class], "div", "rclass", []string{il})
			additional += htmxwrap(dns.Type(head.Rrtype).String(), "div", "rtype", []string{il})

			rdata := ""
			for i := 1; i <= dns.NumField(e); i++ {
				rdata += dns.Field(e, i) + " "
			}
			additional += htmxwrap(rdata, "div", "rdata", []string{il})
		}
	}

	opt += "</div>\n"

	footer += "<div class='digheader'>\n"
	footer += "<span>"
	// divide the Nanoseconds by 1e6 to get the Milliseconds as a int64
	footer += ";; " + htmxwrap("Query time: "+strconv.Itoa(int(r.RTT)/1e6)+" ms", "span", "Qtime", []string{il})
	footer += "</span><br/>"
	footer += "<span>"
	footer += ";; " + htmxwrap("SERVER: "+r.Nameserver+"("+r.QNSname+") ("+r.Transport[:3]+")", "span", "Qserver", []string{il})
	footer += "</span><br/>"
	footer += "<span>"
	footer += ";; WHEN: " + time.Now().Format(time.UnixDate)
	footer += "</span><br/>"
	footer += "<span>"
	footer += ";; " + htmxwrap("MSG SIZE: "+strconv.Itoa(r.Response.Len()), "span", "MSGsize", []string{il})
	footer += "</span><br/>"
	footer += "</div>"

	out += header
	out += opt
	out += question
	out += answer
	out += authority
	out += additional
	out += footer

	return out
}

func htmxwrap(txt, tag, rfield string, cs []string) string {
	// Add classes to rr parts for styling and htmx links for info retrieval
	class := strings.Join(cs, " ")
	ws := "<" + tag + " class='" + class + "' "
	ws += "hx-get='" + hxget + rfield + "' "
	ws += "hx-target='#infobox' "
	ws += "hx-swap='innerHTML' "
	ws += ">\n" + txt + "\n</" + tag + ">"

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
		wrr += htmxwrap(rdata, "div", "rdata", []string{il})
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
