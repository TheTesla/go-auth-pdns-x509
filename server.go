package main

import (
	//"crypto/rand"
	//"errors"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	//"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"strings"
	//"math/big"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	//"time"
	"sync"
)


type certReloader struct {
	certMu   sync.RWMutex
	cert     *tls.Certificate
	certPath string
	keyPath  string
}

func NewCertReloader(certPath, keyPath string) (*certReloader, error) {
        result := &certReloader{
                certPath: certPath,
                keyPath:  keyPath,
        }




        if err := result.init(); err != nil {
                return nil, err
        }

        return result, nil
}

func (cr *certReloader) init() error {
        if err := cr.maybeReload(); err != nil {
                return err
        }
        go func() {
                c := make(chan os.Signal, 1)
                signal.Notify(c, syscall.SIGHUP)
                for range c {
                        log.Printf("Received SIGHUP, reloading TLS certificate and key from %q and %q", cr.certPath, cr.keyPath)
                        if err := cr.maybeReload(); err != nil {
                                log.Printf("Keeping old TLS certificate because the new one could not be loaded: %v", err)
                        }
                }
        }()
	return nil
}

func (cr *certReloader) maybeReload() error {
        newCert, err := tls.LoadX509KeyPair(cr.certPath, cr.keyPath)
        if err != nil {
                return err
        }
        cr.certMu.Lock()
        defer cr.certMu.Unlock()
        cr.cert = &newCert
        return nil
}

func (cr *certReloader) GetCertificateFunc() func(*tls.ClientHelloInfo) (*tls.Certificate, error) { 
        return func(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error) {
                cr.certMu.RLock()
                defer cr.certMu.RUnlock()
                return cr.cert, nil
        }
}


func main() {

	certPath := "/etc/ssl/api.smartrns.net"
	//caCert, err := ioutil.ReadFile("/var/www/api/ca/certs/ca.cert.pem")
	caCert, err := ioutil.ReadFile("ca-root.pem")
	if err != nil {
		log.Fatal(err)
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)
	cfg := &tls.Config{
		//ClientAuth: tls.RequestClientCert,
		ClientAuth: tls.RequireAndVerifyClientCert,
		ClientCAs:  caCertPool,
	}
	h := handler{}
	c := make(chan os.Signal, 1)
	signal.Notify(c, syscall.SIGHUP)
	go func() {
		for sig := range c {
			println(sig)
			fmt.Printf("Got A HUP Signal! Now Reloading Conf....\n")
		}
	}()
	srv := &http.Server{
		Addr:      ":8443",
		Handler:   &h,
		TLSConfig: cfg,
	}
	cr, err := NewCertReloader(certPath+"/fullchain.pem", certPath+"/privkey.pem")
	if err != nil {
		log.Fatal(err)
	}
	srv.TLSConfig.GetCertificate = cr.GetCertificateFunc()

	//log.Fatal(srv.ListenAndServeTLS(certPath+"/fullchain.pem", certPath+"/privkey.pem"))
	log.Fatal(srv.ListenAndServeTLS("",""))
}

type handler struct {
	//caKeyPriv interface{}
	//caCert    *x509.Certificate
}


type JSONrequest struct {
	method		string
	urlpath		string
	jsonInterface	interface{}
	decodeErr	interface{}
}

func (j *JSONrequest) DecodeReq(req *http.Request) {
	j.method = req.Method
	j.urlpath = req.URL.Path
	decoder := json.NewDecoder(req.Body)
	j.decodeErr = decoder.Decode(&j.jsonInterface)
	defer req.Body.Close()
}

func decodeJSONrequest(req *http.Request) (JSONrequest){
	var jsonReq JSONrequest
	jsonReq.DecodeReq(req)
	return jsonReq
}

func handleJSONdecodeError(jsonReq JSONrequest, w http.ResponseWriter) (interface{}) {
	if jsonReq.decodeErr != nil {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("{\"error\": \"json decode error\"}"))
	}
	return jsonReq.decodeErr
}

func contactPDNS(jsonReq JSONrequest, baseURL string, apiKey string) (respBody string, respStatusCode int) {
	body, _ := json.Marshal(jsonReq.jsonInterface)
	bodyrdr := strings.NewReader(string(body))
	r, _ := http.NewRequest(jsonReq.method, baseURL+jsonReq.urlpath, bodyrdr)
	r.Header.Set("X-Api-Key", apiKey)
	resp, _ := http.DefaultClient.Do(r)
	respBA, _ := ioutil.ReadAll(resp.Body)
	respBody = string(respBA)
	defer resp.Body.Close()
	return respBody, resp.StatusCode
}

func (h *handler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	jsonReq := decodeJSONrequest(req)
	if err := handleJSONdecodeError(jsonReq, w); err != nil {
		return
	}

	peerCerts := req.TLS.PeerCertificates

	peerDNSNames := peerCerts[0].DNSNames

	DNSName := getDNSName(jsonReq.urlpath, jsonReq.jsonInterface)

	fmt.Println(DNSName)
	if ok, name := IsSubset([]string{DNSName}, peerDNSNames); ok {
		respBody, respStatusCode := contactPDNS(jsonReq, "http://localhost:8081", "changeme")
		w.WriteHeader(respStatusCode)
		w.Write([]byte(respBody))
	} else {
		fmt.Printf("DNS name not authorized by client certificate: %s\n", name)
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte(fmt.Sprintf("{\"error\": \"name '%s' not authorized by client certificate\"}", DNSName)))
	}
}


func getDNSName(urlpath string, jsonInterface interface{}) (string) {
	urlPathSplit := strings.Split(urlpath, "/")
	DNSName := ""
	if "/api/v1/servers" == strings.Join(urlPathSplit[:4], "/") {
		if "zones" == urlPathSplit[5] {
			fmt.Printf("len: %d\n", len(urlPathSplit))
			if 7 == len(urlPathSplit) {
				DNSName = urlPathSplit[6]
			}
			if "" == DNSName {
				DNSName = jsonInterface.(map[string]interface{})["name"].(string)
			}
		}
	}
	return DNSName
}

func IsSubset(x, y []string) (bool, string) {
	set := make(map[string]bool)
	for _, v := range y {
		set[v] = true
	}
	for _, v := range x {
		if _, found := set[v]; !found {
			return false, v
		}
	}
	return true, ""
}
