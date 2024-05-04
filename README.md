# XdgOpenSaml
retrieve saml token using external browser and write it to standar out

use xdg-open to open a browser

## usage
if [jbang](https://www.jbang.dev/) is intalled set executable permission permission to `XdgOpenSaml.java` 

```
   XdgOpenSaml.java <vpn-url> 
```
else

```
./jbang XdgOpenSaml.java <vpn-url> 
```

if graalvm is installed it's possible to create a native executable with

```
   jbang export native XdgOpenSaml.java 
```
a native executable [XdgOpenSaml](XdgOpenSaml) for linux x86-64 is committed 

this can be used with [openconnect](https://www.infradead.org/openconnect/)

```
sudo openconnect --protocol fortinet --cookie $(XdgOpenSaml <host>:<port>) --server <host>:<port> --servercert pin-sha256:xxxxxxxxxxxxxxxxxxx
```
with [openfortivpn](https://github.com/adrienverge/openfortivpn)

```
XdgOpenSaml <host>:<port> 2>/dev/null | sudo openfortivpn <host>:<port> --cookie-on-stdin

```
```
sudo openfortivpn <host>:<port> --cookie=`XdgOpenSaml.java <host>:<port>`
```

there is a version of the script that retrieve only the id 
source [XdgOpenSamlId.java](XdgOpenSamlId.java) binary [XdgOpenSamlId](XdgOpenSamlId)
this print on standard output "`remote/saml/auth_id?id=<id>`"

and  can be used with [openconnect](https://www.infradead.org/openconnect/)

```
sudo ./openconnect --protocol fortinet --server <host>:<port> --servercert pin-sha256:xxxxxxxxxx -g $(XdgOpenSamlId.java  <host>:<port>)
```
when prompted for Username and Password insert any value will be ignored

## options

```
Usage: XdgOpenSaml [-htV] [-p=<port>] [-r=<realm>] <server>
retrieve saml token with xdg open
      <server>          The server to call
  -h, --help            Show this help message and exit.
  -p, --port=<port>     port to listen for redirect
  -r, --realm=<realm>   The authentication realm.
  -t, --trust-all       ignore  ssl certificate validation
  -V, --version         Print version information and exit.
```
