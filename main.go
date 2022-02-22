package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"

	mqtt "github.com/eclipse/paho.mqtt.golang"
)

var connectHandler mqtt.OnConnectHandler = func(client mqtt.Client) {
	fmt.Println("Client connected")
}

var publishHandler mqtt.MessageHandler = func(client mqtt.Client, msg mqtt.Message) {
	fmt.Printf("Message revieced on topic %s. Message: %s\n", msg.Topic(), msg.Payload())
}

var connctionLostHandler mqtt.ConnectionLostHandler = func(clinet mqtt.Client, err error) {
	fmt.Printf("Connection lost. Error: %s", err.Error())
}

func NewTlsConfig() *tls.Config {
	clientKeyPair, err := tls.LoadX509KeyPair("./certs/chainCert.cert", "./certs/devicePrivateKey.key")
	if err != nil {
		panic(err)
	}

	return &tls.Config{
		Certificates:       []tls.Certificate{clientKeyPair},
		ClientAuth:         tls.RequestClientCert,
		InsecureSkipVerify: true,
		KeyLogWriter:       os.Stdout,
	}
}

func main() {
	host := "mqtt.eu-latest.cumulocity.com"
	client_id := "my_super_client_id_1337"

	port := "8883"

	var root_cert *x509.Certificate

	var err error
	//Create certificates if requiered
	_, err = loadCert("./certs/rootCert.cert")
	if err != nil {
		root_cert, err = createCACert()
		root_key, err2 := loadKey("./certs/rootPrivateKey.key")
		if err != nil && err2 != nil {
			panic("Error create root cert")
		}
		_, err = createDeviceCert(client_id, root_cert, root_key)
		if err != nil {
			panic(err)
		}
	}
	_, err = loadCert("./certs/deviceCert.cert")
	if err != nil {
		root_cert, err := loadCert("./certs/rootCert.cert")
		root_key, err2 := loadKey("./certs/rootPrivateKey.key")
		if err != nil && err2 != nil {
			panic("Error create root cert")
		}
		_, err = createDeviceCert(client_id, root_cert, root_key)
		if err != nil {
			panic(err)
		}
	}

	_, err = loadCert("./certs/chainCert.cert")
	if err != nil {
		certs := [2]string{"./certs/deviceCert.cert", "./certs/rootCert.cert"}
		err = createChainOfCertificates(certs[:], "./certs/chainCert.cert")
		if err != nil {
			panic(err)
		}
	}

	//Create TLS Config
	opts := mqtt.NewClientOptions()
	//Connection opts
	opts.AddBroker("ssl://" + host + ":" + port)
	//Login Via User PW
	opts.SetClientID(client_id)

	tlsConfig := NewTlsConfig()
	opts.SetTLSConfig(tlsConfig)
	//Connection handler
	opts.SetDefaultPublishHandler(publishHandler)
	opts.SetConnectionLostHandler(connctionLostHandler)
	opts.SetOnConnectHandler(connectHandler)
	//Connect
	client := mqtt.NewClient(opts)
	if token := client.Connect(); token.Wait() && token.Error() != nil {
		panic(token.Error())
	}
	fmt.Println("Sample Publisher Started")
	println("Somehow i got here. Seems like i am connected")
}
