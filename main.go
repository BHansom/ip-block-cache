package main

import (
	"encoding/json"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/patrickmn/go-cache"
)

var block_ips           *cache.Cache= cache.New(24*time.Hour, 12*time.Hour)
var block_domains       *cache.Cache= cache.New(cache.NoExpiration, cache.NoExpiration)
var block_ehlo_domains  *cache.Cache= cache.New(cache.NoExpiration, cache.NoExpiration)
var limit               int64       = 2
var port                int         = 10000
// do not block domains in this list
var exclude_list        []string = []string{}
var ehlo_substr          []string = []string{
    "scan",
    "monitor",
    "example",
}
type config struct{
  IpList       map[string]cache.Item
  EhloList     map[string]cache.Item
  DomainList   map[string]cache.Item
  ExcludeList  []string
  Limit        int64
  Port         int
  EhloSubstr    []string
}
func initConfig(){
    
    var c config
    var s []byte = []byte{} 
    _, err := os.Stat("config.json")
    if err==nil {
        s, err= os.ReadFile("config.json")
        if err!=nil {
            log.Fatal("error reading config.json: %v", err)
        }
    }else{
        log.Fatal("no config.json found")
    }
    if len(s)>0{
        err = json.Unmarshal(s, &c)
        if err!=nil{
            log.Fatal(err)
        }

        for key,value := range c.IpList{
            i := int64(value.Object.(float64))
            block_ips.Set(key, i, cache.DefaultExpiration)
            nftBlock(key);
        }
        for key,value := range c.EhloList{
            i := int64(value.Object.(float64))
            block_ehlo_domains.Set(key, i, cache.DefaultExpiration)
        }
        for key,value := range c.DomainList{
            i := int64(value.Object.(float64))
            block_domains.Set(key, i, cache.DefaultExpiration)
        }
        
        limit    = c.Limit  
        exclude_list = c.ExcludeList
        ehlo_substr   = c.EhloSubstr
        if c.Port!=0{
            port         = c.Port
        }
    }
}

/**
found and rank >= limit   
*/
func check_rank(x interface{}, found bool, rate int64) (bool){
    return found && x.(int64)>=rate

}
/**
* block the /24 subnet of ip 
*/
func banIp(ip string){
    rank, found := block_ips.Get(ip)
    
    if check_rank(rank, found, limit   ) {return}
    
    if found {
        get, err := block_ips.IncrementInt(ip, 1)
        if err!=nil{
            log.Panic("error setting variable: %v", err)
        }
        if get==int(limit) {
            nftBlock(ip)
        }
    }else{
        block_ips.Set(ip, int64(1), cache.DefaultExpiration)
    }
}
/*
block the ehlo domain
case insensitive
*/
func banEHLO(ehlo string){
    if ehloFindSubstr(ehlo) {return}
    rank, found := block_ehlo_domains.Get(ehlo)
    if check_rank(rank, found, 1) {return}
    
    //exclude ehlo in exclude_list
    exclude:= slices.ContainsFunc(exclude_list, func(e string) (bool){
        return strings.HasSuffix(ehlo, e)
    })
    if exclude { 
        return
    }
    
    if found {
        err := block_ehlo_domains.Increment(ehlo, 1)
        if err!=nil{
            log.Panic("error setting variable: %v", err)
        }
    }else{
        block_ehlo_domains.Set(ehlo, int64(1), cache.DefaultExpiration)
    }
}
/**
block the domain
no rank
*/
func banDomain(domain string){
    if ehloFindSubstr(domain) {return}
    _, found := block_domains.Get(domain)
    if found {
        return
    }else{
        exclude := slices.ContainsFunc(exclude_list, func(e string)(bool){
            return strings.HasSuffix(domain, e)
        })
        if exclude {
            return
        }

        block_domains.Set(domain, int64(1), cache.DefaultExpiration)
    }
}
func bannedDomain(domain string) (bool){
    if ehloFindSubstr(domain) {return true}
    _, found := block_domains.Get(domain)
    return found
}
func ehloFindSubstr(domain string)(bool){
    return slices.ContainsFunc(ehlo_substr, func(e string) bool {
        return strings.Index(domain, e)>=0
    })
}

//substr find and cache find
func bannedEHLO(domain string) (bool){
    substrMatch := ehloFindSubstr(domain)
    if substrMatch {return true}
    rank, found := block_ehlo_domains.Get(domain)
    return check_rank(rank, found, 1)
}
func bannedIp(ip string) (bool){
    if len(ip) ==0 {return true}
    rank, found := block_ips.Get(ip)
    return check_rank(rank, found, 2)
}

func canConnect(ip string) (bool){
    return !bannedIp(ip)
}

func canEhlo(ip string, domain string) (bool){
    if len(ip)==0|| len(domain)==0 {return false}
    if !bannedIp(ip) && !bannedEHLO(domain) {return true}


    banIp(ip)
    banEHLO(domain)
    //any how , block
    return false

}
func canMail(ip string, ehlo_domain string, domain string) (bool){
    if !bannedIp(ip)&& !bannedEHLO(ehlo_domain) && !bannedDomain(domain){return true}

    banIp(ip)
    banEHLO(ehlo_domain)
    banDomain(domain)
    return false
}
func canRcpt(ip string, ehlo_domain string, from string, to string) (bool){
    if !bannedDomain(from) && !bannedDomain(to) {return true}
    
    banIp(ip)
    banEHLO(ehlo_domain)
    // banDomain(from)
    banDomain(to)
    return false
}

func getCIDR(ip string) (string){
    if net.ParseIP(ip) == nil { return ""}
    const mask = "/24"
    _, ipNet, err := net.ParseCIDR(ip + mask)
    if err!=nil {
        log.Printf("error parsing cidr %s \n", ip+mask)
        return ""
    }

    return ipNet.String()
}
func lowercase(s string) (string){
    return strings.ToLower(s)
}
func getDomainOfEmail(mail string) (string){
    s := strings.Split(mail, "@")
    return s[len(s)-1]
}
func validParam(args ...string) (bool){
    for _,s := range args{
        if len(s)==0 {return false}
    }
    return true
}
func handleSignals() chan os.Signal{
    sigs := make (chan os.Signal, 1)
    signal.Notify(sigs, syscall.SIGINT, syscall.SIGSTOP, syscall.SIGTERM)
    return sigs
}
func initHttp(){
  r := gin.Default()
  r.GET("/ehlo", func(ctx *gin.Context) {
      ip:= getCIDR(ctx.Query("ip"))
      ehlo:= lowercase(ctx.Query("ehlo"))
      if !validParam(ip, ehlo) {
          ctx.String(http.StatusOK, "false") 
      }else{
          log.Printf("ehlo   ip=%s, ehlo=%s\n", ip, ehlo)
          res := canEhlo(ip, ehlo)
          ctx.String(http.StatusOK, strconv.FormatBool(res))
      }
  })

  r.GET("/connect", func(ctx *gin.Context){
      ip := getCIDR(ctx.Query("ip"))
      if !validParam(ip) { 
          ctx.String(http.StatusOK, "false") 
      } else{
          log.Printf("connect ip=%s\n", ip)
          res := canConnect(ip)
          ctx.String(http.StatusOK, strconv.FormatBool(res))
      }
  })
  r.GET("/mail", func(ctx *gin.Context){
      ip:= getCIDR(ctx.Query("ip"))
      ehlo:= lowercase(ctx.Query("ehlo"))
      mail:= getDomainOfEmail(lowercase(ctx.Query("mail")))
      if !validParam(ip, ehlo, mail){
          ctx.String(http.StatusOK, "false") 
      }else{
          log.Printf("mail ip=%s ehlo=%s mail=%s\n", ip, ehlo, mail)
          res := canMail(ip, ehlo, mail)
          ctx.String(http.StatusOK, strconv.FormatBool(res))
      }
  })

  r.GET("/rcpt", func(ctx *gin.Context){
      ip:= getCIDR(ctx.Query("ip"))
      ehlo:= lowercase(ctx.Query("ehlo"))
      mail:= getDomainOfEmail(lowercase(ctx.Query("mail")))
      rcpt:= getDomainOfEmail(lowercase(lowercase(ctx.Query("rcpt"))))
      if !validParam(ip, ehlo, mail, rcpt){
          ctx.String(http.StatusOK, "false") 
      }else{
          log.Printf("rcpt ip=%s ehlo=%s mail=%s rcpt=%s\n", ip, ehlo, mail, rcpt)
          res := canRcpt(ip, ehlo, mail, rcpt)
          ctx.String(http.StatusOK, strconv.FormatBool(res))
      }
  })
  // block /24 subnet of ip 
  r.GET("/block", func(ctx *gin.Context){
      ip:=ctx.Query("ip")
      if validParam(ip){
          nftBlock(ip)
      }
      ctx.String(http.StatusOK, "ok")
  })
  //unblock /24 subnet of ip
  r.GET("/unblock", func(ctx *gin.Context){
      ip:=ctx.Query("ip")
      if validParam(ip){
          nftUnblock(ip)
      }
      ctx.String(http.StatusOK, "ok")
  })

  type formattedCacheItem struct{
      Object interface{} 
      Expiration string
  }
  r.GET("/dump", func(ctx *gin.Context){
      format := ctx.Query("format")
      var ip_list interface{}
      if format == "date"{
          items := block_ips.Items()
          formatted := map[string]formattedCacheItem{}
          for ip := range items{
              item := items[ip]
              sec := item.Expiration/1000000000
              nsec:= item.Expiration%1000000000
              t := time.Unix(sec, nsec)
              formatted[ip] = formattedCacheItem{
                  Object: item.Object,
                  Expiration: t.String(),
              }
          }
          ip_list = formatted
      }else{
          //default timestamp format
          ip_list = block_ips.Items()
      }
      
      ehlo_list:= block_ehlo_domains.Items()
      domain_list:= block_domains.Items()
      ctx.JSON(http.StatusOK, gin.H{
          "IpList": ip_list,
          "EhloList": ehlo_list,
          "DomainList": domain_list,
          "ExcludeList": exclude_list,
          "Limit": limit   ,
          "EhloSubstr": ehlo_substr,
          "Port": port,
      })
  })
  r.Run("localhost:" + strconv.Itoa(port))
}
func main() {

  go initHttp()
  initNftChains()
  initConfig()
  sigs:=handleSignals()
  select {
  case <-sigs:
      break;
  }
  clearNftChains()
}
