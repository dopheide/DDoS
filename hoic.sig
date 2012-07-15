
## We have to look at the TCP payload directly because one of the key
## HOIC signatures is an extra space in the headers which is normally
## obscured by Bro's parsing prior to the http_header event.

signature ddos-hoic {
    ip-proto == tcp
    dst-port == 80
    payload /.*HTTP\/1\.0.*:  .*Host.*/
    event "HOIC Attack Signature"
}
