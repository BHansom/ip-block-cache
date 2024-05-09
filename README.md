
# ip-block-cache 

Block an cidr/24 subnet using rest api.


## how 

For email stages, every ip has default 2 times to try. If the limit is hit, ip will be blocked for 24H.

## rest endpoints

1. GET    /connect       
query: ip
resp: bool
email connect stage check

2. GET    /ehlo          
query: ip,ehlo
resp: bool
email ehlo stage check

3. GET    /mail          
query: ip,ehlo,mail
resp: bool
email mail stage check

4. GET    /rcpt          
query: ip,ehlo,mail,rcpt
resp: bool
email rcpt stage check

5. GET    /block         
query: ip
resp:  ok
directly block an ip

7. GET    /unblock       
query: ip
resp:  ok
directly unblock an ip

8. GET    /dump          
query format('date' or absent)
dump the cache in json format(can be used as config later).

## config

```json
{
   "DomainList": {
       //the domains to block in for emails
      "spam domain": {
         "Expiration": 0,
         "Object": 1
      }
   },
   "EhloList": {
       //the ehlo list to block for emails
      "domain": {
         "Expiration": 0,
         "Object": 1
      },
      "gmail.com": {
         "Expiration": 0,
         "Object": 1
      },
      "masscan": {
         "Expiration": 0,
         "Object": 1
      },
      "user": {
         "Expiration": 0,
         "Object": 1
      }
   },
   "EhloSubstr": [
       //the ehlo substring to block for emails
      "scan",
      "monitor",
      "example"
   ],
   "ExcludeList": [
   //excluded domain or ehlo list for emails
      "your own domains",
      "google.com",
      "gmail.com"
   ],
   "IpList": {
       //ip subnet to block
      "reported bad ip": {
         "Expiration": 1636607700828210877,
         "Object": 2
      }
   },
   //tolerant times
   "Limit": 2
}
```
