package main

import (
	//"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"
)

func dig(query Query) DigOut {

	// Just to be safe, we sanitize data close to usage
	query.Sanitize()
	//fmt.Printf("\n%+v\n", query)
	message := &dns.Msg{
		MsgHdr: dns.MsgHdr{
			Authoritative:     query.AA,
			AuthenticatedData: query.AD,
			CheckingDisabled:  query.CD,
			RecursionDesired:  query.RD,
			Opcode:            dns.OpcodeQuery,
		},
		Question: make([]dns.Question, 1),
	}

	message.Id = dns.Id()

	message.Question = make([]dns.Question, 1)
	message.Question[0] = dns.Question{
		Name:   dns.Fqdn(query.Qname),
		Qtype:  TypeToInt(query.Qtype),
		Qclass: dns.ClassINET,
	}

	/*
		// If DNSSEC records wanted, add DO bit in OPT
		message.SetEdns0(1232, query.DO)
	*/

	o := &dns.OPT{
		Hdr: dns.RR_Header{
			Name:   ".",
			Rrtype: dns.TypeOPT,
		},
	}

	o.SetUDPSize(query.UDPsize) // other options may override. Change later?

	if query.DO {
		o.SetDo()
		o.SetUDPSize(dns.DefaultMsgSize)
	}
	if query.Nsid {
		e := &dns.EDNS0_NSID{
			Code: dns.EDNS0NSID,
		}
		o.Option = append(o.Option, e)
		// NSD will not return nsid when the udp message size is too small
		o.SetUDPSize(dns.DefaultMsgSize)
	}
	message.Extra = append(message.Extra, o)

	QNS := query.Nameserver // Preserve name server name to use in output
	nameserver := query.GetLookupNS()

	// Set correct transport protocol (udp, udp4, udp6, tcp, tcp4, tcp6)
	query.Transport += query.IpVersion

	client := new(dns.Client)
	client.Net = query.Transport

	client.DialTimeout = 2 * time.Second
	client.ReadTimeout = 2 * time.Second
	client.WriteTimeout = 2 * time.Second

	response, rtt, err := client.Exchange(message, nameserver)

	if err != nil {
		panic(err)
	}

	msgSize := response.Len()

	digOut := DigOut{
		Qname:      query.Qname,
		Response:   response,
		RTT:        rtt, // Note to self: rtt is in nanoseconds (1M ns = 1 millisecond)
		Nameserver: nameserver,
		QNSname:    QNS,
		MsgSize:    msgSize,
		Transport:  query.Transport,
	}

	if query.NoCrypto {
		nocryptoMsg(digOut.Response)
	}

	return digOut
}

// emulate the dig option +nocrypto

func nocryptoMsg(in *dns.Msg) {
	for i, answer := range in.Answer {
		in.Answer[i] = nocryptoRR(answer)
	}
	for i, ns := range in.Ns {
		in.Ns[i] = nocryptoRR(ns)
	}
	for i, extra := range in.Extra {
		in.Extra[i] = nocryptoRR(extra)
	}
}

func nocryptoRR(r dns.RR) dns.RR {
	switch t := r.(type) {
	case *dns.DS:
		t.Digest = "[omitted]"
	case *dns.DNSKEY:
		t.PublicKey = "[omitted]"
	case *dns.RRSIG:
		t.Signature = "[omitted]"
	case *dns.NSEC3:
		t.Salt = "." // Nobody cares
		if len(t.TypeBitMap) > 5 {
			t.TypeBitMap = t.TypeBitMap[1:5]
		}
	}
	return r
}

// miekg/dns has a TYPE converter. This function is just to handle 'untyped' (TYPEXYZ) type values.
func TypeToInt(t string) uint16 {
	var ti uint16
	if strings.HasPrefix(t, "TYPE") {
		i, err := strconv.Atoi(t[4:])
		if err == nil {
			ti = uint16(i)
		}
	} else {
		if i, ok := dns.StringToType[strings.ToUpper(t)]; ok {
			ti = i
		}
	}
	return ti
}