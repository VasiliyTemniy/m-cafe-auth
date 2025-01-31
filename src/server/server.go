package server

import (
	"fmt"
	"log"
	"net"

	"simple-micro-auth/src/cert"
	"simple-micro-auth/src/configs"
	pb "simple-micro-auth/src/proto"
	"simple-micro-auth/src/services"

	"google.golang.org/grpc"
)

var grpcServer *grpc.Server

/*  TODO - Make it accept connections from docker network only  */

// func getDockerNetworkInterface() (string, error) {
// 	interfaces, err := net.Interfaces()
// 	if err != nil {
// 			return "", err
// 	}

// 	for _, interf := range interfaces {
// 			if interf.Name == "docker0" || strings.Contains(interf.Name, "br-") {
// 					addrs, err := interf.Addrs()
// 					if err != nil {
// 							return "", err
// 					}

// 					for _, addr := range addrs {
// 							ip, ok := addr.(*net.IPNet)
// 							if ok && !ip.IP.IsLoopback() {
// 									return ip.IP.String(), nil
// 							}
// 					}
// 			}
// 	}

// 	return "", errors.New("docker network interface not found")
// }

// func RunServer() {
// 	cert.ReadCertificates("token")

// 	var host string

// 	if configs.EnvDockerized == "true" {
// 			host, err := getDockerNetworkInterface()
// 			if err != nil {
// 					log.Fatalf("failed to get docker network interface: %v", err)
// 			}
// 	} else {
// 			host = "127.0.0.1"
// 	}

// 	listenPort := fmt.Sprintf("%s:%s", host, configs.EnvPort)

// 	lis, err := net.Listen("tcp", listenPort)

// 	if err != nil {
// 			log.Fatalf("failed to listen: %v", err)
// 	} else {
// 			fmt.Println("Listening on " + listenPort)
// 	}

// 	grpcServer := grpc.NewServer()
// 	service := &services.AuthServiceServer{}

// 	pb.RegisterAuthServiceServer(grpcServer, service)
// 	err = grpcServer.Serve(lis)

// 	if err != nil {
// 			log.Fatalf("Error starting server: %v", err)
// 	}
// }

/*  END TODO */

/*  TODO - Introduce the mTLS to secure the connection  */

// func RunServer() {
// 	cert.ReadCertificates("token")

// 	var host string

// 	if configs.EnvDockerized == "true" {
// 			host, err := getDockerNetworkInterface()
// 			if err != nil {
// 					log.Fatalf("failed to get docker network interface: %v", err)
// 			}
// 	} else {
// 			host = "127.0.0.1"
// 	}

// 	listenPort := fmt.Sprintf("%s:%s", host, configs.EnvPort)

// 	// Load server certificate and private key
// 	serverCert, err := tls.LoadX509KeyPair("server-cert.pem", "server-key.pem")
// 	if err != nil {
// 			log.Fatalf("failed to load server certificate: %v", err)
// 	}

// 	// Load client certificate authority (CA)
// 	clientCACert, err := ioutil.ReadFile("client-ca-cert.pem")
// 	if err != nil {
// 			log.Fatalf("failed to load client CA certificate: %v", err)
// 	}

// 	// Create a TLS config with client certificate authentication
// 	tlsConfig := &tls.Config{
// 			Certificates: []tls.Certificate{serverCert},
// 			ClientCAs:    x509.NewCertPool(),
// 			ClientAuth:   tls.RequireAndVerifyClientCert,
// 	}

// 	tlsConfig.ClientCAs.AppendCertsFromPEM(clientCACert)

// 	// Create a gRPC server with TLS
// 	grpcServer := grpc.NewServer(grpc.Creds(credentials.NewTLS(tlsConfig)))

// 	service := &services.AuthServiceServer{}

// 	pb.RegisterAuthServiceServer(grpcServer, service)

// 	lis, err := net.Listen("tcp", listenPort)
// 	if err != nil {
// 			log.Fatalf("failed to listen: %v", err)
// 	}

// 	err = grpcServer.Serve(lis)
// 	if err != nil {
// 			log.Fatalf("Error starting server: %v", err)
// 	}
// }

/*  END TODO */

// STEPS!
// 1. DONE! Make it work the same but with UUIDs instead of ints
// 2. Add ORM (gorm)
// 3. Add HTTP GIN server as option
// 4. Make it accept connections from docker network only
// 5. Introduce the mTLS to secure the connection
// 6. Make something like api keys to access the server from different services

func RunServer() {

	cert.ReadCertificates("token")

	var host string

	if configs.EnvDockerized == "true" {
		host = "0.0.0.0"
	} else {
		host = "127.0.0.1"
	}

	listenPort := fmt.Sprintf("%s:%s", host, configs.EnvPort)

	lis, err := net.Listen("tcp", listenPort)

	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	} else {
		fmt.Println("Listening on " + listenPort)
	}

	grpcServer := grpc.NewServer()
	service := &services.AuthServiceServer{}

	pb.RegisterAuthServiceServer(grpcServer, service)
	err = grpcServer.Serve(lis)

	if err != nil {
		log.Fatalf("Error strating server: %v", err)
	}
}

func StopServer() {
	grpcServer.Stop()
}
