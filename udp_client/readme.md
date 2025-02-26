go run . -host 192.168.1.100 -port 8125 -size 1400 -pps 1000 -report 1


go run . -host 192.168.1.100 -port 8125 -size 1400 -pps 10000 -report 1

go run . -host localhost -port 8125 -size 1400 -pps 100000 -report 1


go run . -host localhost -port 8125 -size 1400 -pps 1000000 -report 1



go run . -interface eth0 -destip 255.255.255.255 -port 8125 -size 1400 -pps 1000