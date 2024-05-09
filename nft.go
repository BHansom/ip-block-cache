package main

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"strings"
	"time"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
)

// NetFirstAndLastIP takes the beginning address of an entire network in CIDR
// notation (e.g. 192.168.1.0/24) and returns the first and last IP addresses
// within the network (e.g. first 192.168.1.0, last 192.168.1.255).
//
// Note that these are the first and last IP addresses, not the first and last
// *usable* IP addresses (which would be 192.168.1.1 and 192.168.1.254,
// respectively, for 192.168.1.0/24).
//copied from google/nftables/util.go  not released code
func NetFirstAndLastIP(networkCIDR string) (first, last net.IP, err error) {
	_, subnet, err := net.ParseCIDR(networkCIDR)
	if err != nil {
		return nil, nil, err
	}

	first = make(net.IP, len(subnet.IP))
	last = make(net.IP, len(subnet.IP))

	switch len(subnet.IP) {
	case net.IPv4len:
		mask := binary.BigEndian.Uint32(subnet.Mask)
		ip := binary.BigEndian.Uint32(subnet.IP)
		// To achieve the first IP address, we need to AND the IP with the mask.
		// The AND operation will set all bits in the host part to 0.
		binary.BigEndian.PutUint32(first, ip&mask)
		// To achieve the last IP address, we need to OR the IP network with the inverted mask.
		// The AND between the IP and the mask will set all bits in the host part to 0, keeping the network part.
		// The XOR between the mask and 0xffffffff will set all bits in the host part to 1, and the network part to 0.
		// The OR operation will keep the host part unchanged, and sets the host part to all 1.
		binary.BigEndian.PutUint32(last, (ip&mask)|(mask^0xffffffff))
	case net.IPv6len:
		mask1 := binary.BigEndian.Uint64(subnet.Mask[:8])
		mask2 := binary.BigEndian.Uint64(subnet.Mask[8:])
		ip1 := binary.BigEndian.Uint64(subnet.IP[:8])
		ip2 := binary.BigEndian.Uint64(subnet.IP[8:])
		binary.BigEndian.PutUint64(first[:8], ip1&mask1)
		binary.BigEndian.PutUint64(first[8:], ip2&mask2)
		binary.BigEndian.PutUint64(last[:8], (ip1&mask1)|(mask1^0xffffffffffffffff))
		binary.BigEndian.PutUint64(last[8:], (ip2&mask2)|(mask2^0xffffffffffffffff))
	}

    //the last ip is not included by default  [first, last) half-open interval, so last++
    last[3]++
    if last[3]==0{
        last[2]++
    }
    if last[2]==0{
        last[1]++
    }
    if last[1]==0{
        last[0]++
    }

	return first, last, nil
}

//initialize the nft
func initNftChains(){
    conn,err := nftables.New()
    if err!=nil{
        log.Println("error initializing nftables")
        panic(err)
    }
    table := conn.AddTable(&nftables.Table{
        //ipv4 
        Family: nftables.TableFamilyIPv4,
        Name: "filter",
    })
    policy:= nftables.ChainPolicyAccept
    newChain := &nftables.Chain {
        Name: "blackhole",
        Table: table,
        Type: nftables.ChainTypeFilter,
        Hooknum: nftables.ChainHookInput,
        Priority: nftables.ChainPrioritySecurity,
        Policy: &policy,
    }
    
    conn.AddChain(newChain)
    daySet :=  &nftables.Set{
        Table: table,
        Name: "dayhole",
        Timeout: 24 * time.Hour,
        HasTimeout: true,
        Interval: true,
        KeyType: nftables.TypeIPAddr,
        //Concatenation: true,
    } 

    err=conn.AddSet(daySet, nil)
    if err!=nil{
        log.Println(err)
        return
    }

    //24 blackhole
    conn.AddRule(&nftables.Rule{
        Chain: newChain,
        Table: table,
        Exprs: []expr.Any{
            &expr.Payload{
                DestRegister: 1,
                Base: expr.PayloadBaseNetworkHeader,
                Offset: uint32(12),
                Len: uint32(4),
            },
            &expr.Lookup{
                SourceRegister: 1,
                SetName: daySet.Name,
                SetID:   daySet.ID,
            },
            &expr.Verdict{
                Kind: expr.VerdictDrop,
            },
        },

    })
    //7 days blackhole
    // conn.AddRule(&nftables.Rule{
    //     Chain: newChain,
    //     Table: table,
    //     Exprs: []expr.Any{
    //         &expr.Payload{
    //             DestRegister: 1,
    //             Base: expr.PayloadBaseNetworkHeader,
    //             Offset: uint32(12),
    //             Len: uint32(4),
    //         },
    //         &expr.Lookup{
    //             SourceRegister: 1,
    //             SetName: weekSet.Name,
    //             SetID:   weekSet.ID,
    //         },
    //         &expr.Verdict{
    //             Kind: expr.VerdictDrop,
    //         },
    //     },
    //
    // })
    err= conn.Flush()
    if err!=nil{
        log.Println("error flush rules")
        panic(err)
    }
}

//nftables block the subnet of ip in 24hours 
func nftBlock(ip string){
    if strings.Index(ip, "/")<0{
        ip=ip + "/24"
    }
    conn,err := nftables.New()
    if err!=nil{
        log.Println("error adding ip element")
        panic(err)
    }

    table := conn.AddTable(&nftables.Table{
        //ipv4 
        Family: nftables.TableFamilyIPv4,
        Name: "filter",
    })
    var setName string 
    setName = "dayhole" 
    set,err := conn.GetSetByName(table,setName)
    if err!=nil{
        log.Println("error get set by name")
        panic(err)
    }
    
    first,last,err := NetFirstAndLastIP(ip)
    if err!=nil{
        log.Println("error parsing cidr ", ip)
        log.Println(err)
        return 
    }

    //TODO what if add duplicated elements
    err= conn.SetAddElements(set, []nftables.SetElement{
        //use key and keyEnd will get wrong， 
        //two elements with intervalEnd specified will get success
        //IntervalEnd => https://github.com/sbezverk/nftableslib/blob/master/nfranges.go#L111
        {
            Key: first,
        },
        {
            Key: last,
            IntervalEnd: true,
        },
    })
    if err!=nil{
        fmt.Errorf("error add element to set: %v\n", err)
        return
    }
    err=conn.Flush()
    if err!=nil{
        fmt.Errorf("error flush add element operation : %v\n", err)
    }
    

}
// unblock a ip
func nftUnblock(ip string){
    conn,err := nftables.New()
    if err!=nil{
        log.Println("error getting connection of nftables")
        panic(err)
    }

    table := conn.AddTable(&nftables.Table{
        //ipv4 
        Family: nftables.TableFamilyIPv4,
        Name: "filter",
    })
    var setName string 
    setName = "dayhole" 
    set,err := conn.GetSetByName(table,setName)
    if err!=nil{
        log.Println("error get set by name")
        panic(err)
    }
    
    first,last,err := NetFirstAndLastIP(ip)
    if err!=nil{
        log.Println("error parsing cidr ", ip)
        return 
    }

    err= conn.SetDeleteElements(set, []nftables.SetElement{
        {
            Key: first,
        },
        {
            Key: last,
            IntervalEnd: true,
        },
    })
    if err!=nil{
        fmt.Errorf("error add element to set: %v\n", err)
        return
    }
    err=conn.Flush()
    if err!=nil{
        fmt.Errorf("error flush add element operation : %v\n", err)
    }
}

//clear the nft
func clearNftChains(){

    conn,err := nftables.New()
    if err!=nil{
        log.Println(err)
        return
    }

    //Name Family  
    //Name
    conn.DelChain(&nftables.Chain{
        Table: &nftables.Table{Name: "filter", Family: nftables.TableFamilyIPv4},
        Name: "blackhole",
    })
    conn.DelSet(&nftables.Set{
        Table: &nftables.Table{Name: "filter", Family: nftables.TableFamilyIPv4},
        Name: "dayhole",
    })
    err = conn.Flush()
    if err!=nil{
        log.Println("error clearing nftables rules")
        log.Println(err)
    }
}

