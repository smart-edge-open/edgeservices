package main

import (
	"os"
	"fmt"
	"errors"
	"encoding/json"
	"io/ioutil"
	"crypto/x509"
	"time"
	"crypto/tls"
	
	
	"net"
	"context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	pb "ipchange/pb"
)

var(
cert="/var/lib/appliance/certs/cert.pem"
cacerts="/var/lib/appliance/certs/cacerts.pem"
key="/var/lib/appliance/certs/key.pem"


)

func main() {
	endpoint:=loadconfig()
	iprev:=""
	for{
	ip, err := externalIP()
	if err != nil {
		fmt.Println(err)
	}
	if ip!=iprev{
	//if IP Changed
	iprev=ip
	time.Sleep(10*time.Second)
	ctx,cancel:=context.WithTimeout(context.Background(),60*time.Second)
	defer cancel()
	creds,err:=loadTLSCredentials()
	if err!=nil{
		fmt.Println(err)
}
	conn,err:=grpc.DialContext(ctx,endpoint,grpc.WithTransportCredentials(creds))
	if err != nil {
		fmt.Println("%s",err)
		return 

	}
	defer func() {
		if err1 := conn.Close(); err1 != nil {
			
		}
	}()
	ip1:=&pb.IP{IP:ip}
	ipCLI:=pb.NewIPUpdateClient(conn)
	resp,err:=ipCLI.NewIP(ctx,ip1)
	if err!=nil{
		fmt.Println(err)
}
	fmt.Println("%s",string(resp.Reply))
	}else{
	//fmt.Println("Same IP")
	iprev=ip
	}
	
}
}

func externalIP() (string, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return "", err
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 {
			continue // interface down
		}
		if iface.Flags&net.FlagLoopback != 0 {
			continue // loopback interface
		}
		addrs, err := iface.Addrs()
		if err != nil {
			return "", err
		}
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip == nil || ip.IsLoopback() {
				continue
			}
			ip = ip.To4()
			if ip == nil {
				continue // not an ipv4 address
			}
			return ip.String(), nil
		}
	}
	return "", errors.New("are you connected to the network?")
}
func loadTLSCredentials()(credentials.TransportCredentials,error){

certificate,err:=tls.LoadX509KeyPair(cert,key)
if err != nil {
        return nil,fmt.Errorf("could not load client key pair: %s", err)
    }
    certPool := x509.NewCertPool()
    ca, err := ioutil.ReadFile(cacerts)
    if err != nil {
        return nil,fmt.Errorf("could not read ca certificate: %s", err)
    }

    // Append the certificates from the CA
    if ok := certPool.AppendCertsFromPEM(ca); !ok {
        return nil,errors.New("failed to append ca certs")
    }

    creds := credentials.NewTLS(&tls.Config{
        ServerName:   "controller.openness", // NOTE: this is required!
        Certificates: []tls.Certificate{certificate},
        RootCAs:      certPool,
    })
return creds,nil
}
func loadconfig()(string){
jsonFile,err:=os.Open("/var/lib/appliance/configs/eva.json")
if err!=nil{
fmt.Println(err)
}
defer jsonFile.Close()
byte1,_:=ioutil.ReadAll(jsonFile)
var result map[string]interface{}
json.Unmarshal([]byte(byte1),&result)
str:=fmt.Sprint(result["ControllerEndpoint"])
return str
}
