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



type ClientConfigReloader struct {
	configMu	sync.RWMutex
	config		*tls.Config
	certPath	string
	keyPath		string
	caPath		string
}

func NewClientConfigReloader(certPath, keyPath, caPath string) (*ClientConfigReloader, error) {
        result := &ClientConfigReloader{
		config:		&tls.Config{},
                certPath:	certPath,
                keyPath:	keyPath,
		caPath:		caPath,
        }
        if err := result.init(); err != nil {
                return nil, err
        }
        return result, nil
}

func (ccr *ClientConfigReloader) init() error {
        if err := ccr.reloadServerCert(); err != nil {
                return err
        }
	ccr.config.ClientAuth = tls.RequireAndVerifyClientCert
	ccr.reloadCaCertPool()
        go func() {
                c := make(chan os.Signal, 1)
                signal.Notify(c, syscall.SIGHUP)
                for range c {
                        log.Printf("Received SIGHUP, reloading TLS certificate and key from %q and %q", ccr.certPath, ccr.keyPath)
                        if err := ccr.reloadServerCert(); err != nil {
                                log.Printf("Keeping old TLS certificate because the new one could not be loaded: %v", err)
                        }
			ccr.reloadCaCertPool()
                }
        }()
	return nil
}
func (ccr *ClientConfigReloader) GetConfigForClientFunc() func(*tls.ClientHelloInfo) (*tls.Config, error) {
        return func(clientHello *tls.ClientHelloInfo) (*tls.Config, error) {
                ccr.configMu.RLock()
                defer ccr.configMu.RUnlock()
                return ccr.config, nil
        }
}

func (ccr *ClientConfigReloader) reloadServerCert() error {
        newCert, err := tls.LoadX509KeyPair(ccr.certPath, ccr.keyPath)
        if err != nil {
                return err
        }
        ccr.configMu.Lock()
        defer ccr.configMu.Unlock()
        ccr.config.Certificates = []tls.Certificate{newCert}
        return nil
}

func (ccr *ClientConfigReloader) reloadCaCertPool() error {
	files, err := ioutil.ReadDir(ccr.caPath)
	if err != nil {
	    log.Fatal(err)
	}

	caCertPool := x509.NewCertPool()
	for _, f := range files {
	        fmt.Println(f.Name())
		if f.IsDir() {
			continue
		}
		caCert, err := ioutil.ReadFile(ccr.caPath+f.Name())
		if err != nil {
			log.Fatal(err)
		}
		if false == caCertPool.AppendCertsFromPEM(caCert) {
			//log.Fatal("not a pem file")
			fmt.Println("not a pem file")
		}
	}

        ccr.configMu.Lock()
        defer ccr.configMu.Unlock()
	ccr.config.ClientCAs = caCertPool
	return nil
}

func main() {

	certPath := "/etc/ssl/api.smartrns.net"
	//caCert, err := ioutil.ReadFile("/var/www/api/ca/certs/ca.cert.pem")
	caCert, err := ioutil.ReadFile("./ca/ca-root.pem")
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
	ccr, err := NewClientConfigReloader(certPath+"/fullchain.pem", certPath+"/privkey.pem", "ca/")
	if err != nil {
		log.Fatal(err)
	}
	srv.TLSConfig.GetConfigForClient = ccr.GetConfigForClientFunc()

	//log.Fatal(srv.ListenAndServeTLS(certPath+"/fullchain.pem", certPath+"/privkey.pem"))
	log.Fatal(srv.ListenAndServeTLS(certPath+"/fullchain.pem", certPath+"/privkey.pem"))
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

func contactPDNS(jsonReq JSONrequest, baseURL string, apiKey string) (string, int, error) {
	var err		error
	var body	[]byte
	var r		*http.Request
	var resp	*http.Response
	var respBA	[]byte
	if body, err = json.Marshal(jsonReq.jsonInterface); nil != err {
		return "{\"error\": \"internal error - unable to generate json string\"}", 0, err
	}
	bodyrdr := strings.NewReader(string(body))
	if r, err = http.NewRequest(jsonReq.method, baseURL+jsonReq.urlpath, bodyrdr); nil != err {
		return "{\"error\": \"internal error - unable to create backend request\"}", 0, err
	}
	r.Header.Set("X-Api-Key", apiKey)
	if resp, err = http.DefaultClient.Do(r); nil != err {
		return "{\"error\": \"internal error - unable to contact pdns api\"}", 0, err
	}
	defer resp.Body.Close()
	if respBA, err = ioutil.ReadAll(resp.Body); nil != err {
		return "{\"error\": \"internal error - unable to read body of pdns api response\"}", 0, err
	}
	respBody := string(respBA)
	return respBody, resp.StatusCode, nil
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
		respBody, respStatusCode, _ := contactPDNS(jsonReq, "http://localhost:8081", "changeme")
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
