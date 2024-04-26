# XdgOpenSaml
retrieve saml token using external browser and write it to standar out

use xdg-open to open a browser

## usage
if jbang is intalled set executable permission permission to `XdgOpenSaml.java` 
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
a native executable XdgOpenSaml for linux x86-64 is committed 

## options

```
Usage: XdgOpenSamlgit [-htV] [-p=<port>] [-r=<realm>] <server>
retrieve saml token with xdg open
      <server>          The server to call
  -h, --help            Show this help message and exit.
  -p, --port=<port>     port to listen for redirect
  -r, --realm=<realm>   The authentication realm.
  -t, --trust-all       ignore  ssl certificate validation
  -V, --version         Print version information and exit.
```
