package main

import (
	"bytes"
	"flag"
	"fmt"
	"io/ioutil"
	"net"
	"net/netip"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/IrineSistiana/mosdns/v3/dispatcher/pkg/matcher/v2data"
	"github.com/nadoo/ipset"
)

var Params struct {
	GeoFile     string // g
	GeoCategory string // c
	Mode        string // m
	NotV4       bool   // n4
	NotV6       bool   // n6
	IPSetV4     string // i4
	IPSetV6     string // i6
	FileSaveV4  string // s4
	FileSaveV6  string // s6
}

func main() {
	flag.StringVar(&Params.GeoFile, "g", "./geoip.dat", "Set GeoFile")
	flag.StringVar(&Params.GeoCategory, "c", "", "Set GeoCategory")
	flag.StringVar(&Params.Mode, "m", "show", "Set Mode")
	flag.StringVar(&Params.IPSetV4, "i4", "", "Set IPSet V4 Name")
	flag.StringVar(&Params.IPSetV6, "i6", "", "Set IPSet V6 Name")
	flag.StringVar(&Params.FileSaveV4, "s4", "", "Set Safe Filename V4")
	flag.StringVar(&Params.FileSaveV6, "s6", "", "Set Safe Filename V6")
	flag.BoolVar(&Params.NotV4, "n4", false, "Not IPv4")
	flag.BoolVar(&Params.NotV6, "n6", false, "Not IPv6")
	flag.Parse()
	if Params.GeoFile == "" || Params.GeoCategory == "" || Params.Mode == "" {
		flag.Usage()
		return
	}
	switch Params.Mode {
	case "show":
	case "save":
		if Params.FileSaveV4 == "" || Params.FileSaveV6 == "" {
			_, _ = fmt.Fprintln(os.Stdout, "Safe Filename Invalid")
			return
		}
	case "ipset":
		if runtime.GOOS != "linux" {
			_, _ = fmt.Fprintln(os.Stdout, "IPSet Not Support On Your OS")
			return
		} else {
			if err := ipset.Init(); err != nil {
				_, _ = fmt.Fprintln(os.Stdout, "IPSet Init Fail:", err)
				return
			}
		}
		if Params.IPSetV4 == "" && Params.IPSetV6 == "" {
			_, _ = fmt.Fprintln(os.Stdout, "IPSet Name Invalid")
			return
		}
		if Params.IPSetV4 == Params.IPSetV6 {
			_, _ = fmt.Fprintln(os.Stdout, "IPSet Name Invalid")
			return
		}
	default:
		_, _ = fmt.Fprintln(os.Stdout, "Mode Only Support `show` `save` `ipset`")
		return
	}
	data, err := ConvertIPDat(Params.GeoFile, Params.GeoCategory)
	if err != nil {
		_, _ = fmt.Fprintln(os.Stdout, err)
		return
	}
	data = data[:len(data)-1]
	switch Params.Mode {
	case "show":
		if Params.NotV4 || Params.NotV6 {
			CIDRv4, CIDRv6 := Translate46(data)
			if !Params.NotV4 {
				for _, v := range CIDRv4 {
					_, _ = fmt.Fprintln(os.Stdout, v.String())
				}
			}
			if !Params.NotV6 {
				for _, v := range CIDRv6 {
					_, _ = fmt.Fprintln(os.Stdout, v.String())
				}
			}
		} else {
			_, _ = fmt.Fprintln(os.Stdout, string(data))
		}
	case "save":
		if Params.FileSaveV4 != "" && Params.FileSaveV6 != "" && Params.FileSaveV4 == Params.FileSaveV6 {
			File, err := os.Create(Params.FileSaveV4)
			if err != nil {
				_, _ = fmt.Fprintf(os.Stdout, "Fail To Create File: %s\n", Params.FileSaveV4)
				return
			}
			defer File.Close()
			if !Params.NotV4 && !Params.NotV6 {
				File.Write(data)
			} else {
				CIDRv4, CIDRv6 := Translate46(data)
				if !Params.NotV4 {
					data4 := make([]byte, 0)
					for _, v := range CIDRv4 {
						data4 = append(data4, []byte(v.String()+"\n")...)
					}
					if Params.NotV6 {
						data4 = data4[:len(data4)-1]
					}
					File.Write(data4)
				}
				if !Params.NotV6 {
					data6 := make([]byte, 0)
					for _, v := range CIDRv6 {
						data6 = append(data6, []byte(v.String()+"\n")...)
					}
					data6 = data6[:len(data6)-1]
					File.Write(data6)
				}
			}
		} else {
			CIDRv4, CIDRv6 := Translate46(data)
			if Params.FileSaveV4 != "" && !Params.NotV4 {
				File4, err := os.Create(Params.FileSaveV4)
				if err != nil {
					_, _ = fmt.Fprintf(os.Stdout, "Fail To Create File: %s\n", Params.FileSaveV4)
					return
				}
				defer File4.Close()
				data4 := make([]byte, 0)
				for _, v := range CIDRv4 {
					data4 = append(data4, []byte(v.String()+"\n")...)
				}
				if Params.FileSaveV6 == "" || Params.NotV6 {
					data4 = data4[:len(data4)-1]
				}
				File4.Write(data4)
			}
			if Params.FileSaveV6 != "" && !Params.NotV6 {
				File6, err := os.Create(Params.FileSaveV6)
				if err != nil {
					_, _ = fmt.Fprintf(os.Stdout, "Fail To Create File: %s\n", Params.FileSaveV6)
					return
				}
				defer File6.Close()
				data6 := make([]byte, 0)
				for _, v := range CIDRv6 {
					data6 = append(data6, []byte(v.String()+"\n")...)
				}
				data6 = data6[:len(data6)-1]
				File6.Write(data6)
			}
		}
		_, _ = fmt.Fprintln(os.Stdout, "OK")
	case "ipset":
		CIDRv4, CIDRv6 := Translate46(data)
		if Params.IPSetV4 != "" && !Params.NotV4 {
			if err := ipset.Create(Params.IPSetV4); err != nil {
				_, _ = fmt.Fprintln(os.Stdout, "Create IPSet ["+Params.IPSetV4+"] Fail:", err)
				return
			}
			for _, v := range CIDRv4 {
				if err := ipset.AddPrefix(Params.IPSetV4, v); err != nil {
					_, _ = fmt.Fprintln(os.Stdout, "Add IPSet ["+Params.IPSetV4+"] "+v.String()+" Fail:", err)
					return
				}
			}
		}
		if Params.IPSetV6 != "" && !Params.NotV6 {
			if err := ipset.Create(Params.IPSetV6, ipset.OptIPv6()); err != nil {
				_, _ = fmt.Fprintln(os.Stdout, "Create IPSet ["+Params.IPSetV6+"] Fail:", err)
				return
			}
			for _, v := range CIDRv6 {
				if err := ipset.AddPrefix(Params.IPSetV6, v); err != nil {
					_, _ = fmt.Fprintln(os.Stdout, "Add IPSet ["+Params.IPSetV6+"] "+v.String()+" Fail:", err)
					return
				}
			}
		}
		_, _ = fmt.Fprintln(os.Stdout, "OK")
	}
}

func ConvertIPDat(GeoFile, GeoCategory string) ([]byte, error) {
	wantTag := strings.ToLower(GeoCategory)
	geoIPList, err := v2data.LoadGeoIPListFromDAT(GeoFile)
	if err != nil {
		return nil, err
	}
	o := &bytes.Buffer{}
	for _, ipList := range geoIPList.GetEntry() {
		tag := strings.ToLower(ipList.GetCountryCode())
		if len(wantTag) != 0 && wantTag != tag {
			continue
		}
		for _, record := range ipList.GetCidr() {
			n := net.IPNet{
				IP: record.Ip,
			}
			switch len(record.Ip) {
			case 4:
				n.Mask = net.CIDRMask(int(record.Prefix), 32)
			case 16:
				n.Mask = net.CIDRMask(int(record.Prefix), 128)
			}
			_, err := o.Write([]byte(n.String() + "\n"))
			if err != nil {
				return nil, err
			}
		}
	}
	d, err := ioutil.ReadAll(o)
	if err != nil {
		return nil, err
	}
	return d, nil
}

func Translate46(data []byte) ([]netip.Prefix, []netip.Prefix) {
	var WorkGroup sync.WaitGroup
	Chan4 := make(chan netip.Prefix, 1024)
	Chan6 := make(chan netip.Prefix, 1024)
	CIDRv4 := make([]netip.Prefix, 0)
	CIDRv6 := make([]netip.Prefix, 0)
	for _, v := range bytes.Split(data, []byte("\n")) {
		if len(v) <= 0 {
			continue
		}
		WorkGroup.Add(1)
		go func(ip []byte) {
			defer WorkGroup.Done()
			CIDR, err := netip.ParsePrefix(string(ip))
			if err != nil {
				return
			}
			if CIDR.Addr().Is4() {
				Chan4 <- CIDR
			} else if CIDR.Addr().Is6() {
				Chan6 <- CIDR
			}
		}(v)
	}
	WorkGroup.Add(1)
	go func() {
		defer WorkGroup.Done()
		for {
			Break := false
			select {
			case cidr := <-Chan4:
				CIDRv4 = append(CIDRv4, cidr)
			default:
				if len(Chan4) <= 0 {
					<-time.After(50 * time.Millisecond)
					if len(Chan4) <= 0 {
						Break = true
					}
				}
			}
			if Break {
				break
			}
		}
	}()
	WorkGroup.Add(1)
	go func() {
		defer WorkGroup.Done()
		for {
			Break := false
			select {
			case cidr := <-Chan6:
				CIDRv6 = append(CIDRv6, cidr)
			default:
				if len(Chan6) <= 0 {
					<-time.After(50 * time.Millisecond)
					if len(Chan6) <= 0 {
						Break = true
					}
				}
			}
			if Break {
				break
			}
		}
	}()
	WorkGroup.Wait()
	return CIDRv4, CIDRv6
}
