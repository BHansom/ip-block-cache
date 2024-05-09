
# ip-block-cache 

Block an cidr/24 subnet using rest api.


## how 

For email stages, every ip has default 2 times to try. If the limit is hit, ip will be blocked for 24H.

## rest endpoints

|name | query| resp | description| 
|-------|--------| -----| ---|
|GET    /connect|ip |bool, allow or not|email connect stage check|
|GET    /ehlo   | ip,ehlo | bool| email ehlo stage check|
|GET    /mail   | ip,ehlo,mail | bool| email mail stage check|
|GET    /rcpt   | ip,ehlo,mail,rcpt | bool| email rcpt stage check|
|GET    /block  | ip| 'ok' | directly block an ip|
|GET    /unblock| ip| 'ok' | directly unblock an ip|
|GET    /dump   | format, 'date' if not timestamp | json content| dump the cache in json format(can be used as config later).|

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
