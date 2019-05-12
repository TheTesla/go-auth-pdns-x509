package main

import (
	"flag"
	"path/filepath"
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

type SystemConfigReloader struct {
	ConfigPath	string
	InternalURL	string
	ExternalAddr	string
	ApiKey		string
	CertPath	string
	KeyPath		string
	CaPaths		[]string
}

func NewSystemConfigReloader(configPath string) (*SystemConfigReloader, error) {
	result := &SystemConfigReloader{
		ConfigPath:	configPath,
		InternalURL:	"http://localhost:8081",
		ExternalAddr:	":8443",
		ApiKey:		"changeme",
		CertPath:	"/etc/ssl/api.smartrns.net/fullchain.pem", 
		KeyPath:	"/etc/ssl/api.smartrns.net/privkey.pem",
		CaPaths:	[]string{"ca/"},
	}
	if err := result.init(); err != nil {
		return result, err
	}
	return result, nil
}

func (cfg *SystemConfigReloader) init() error {
	if err := cfg.reload(); err != nil {
		log.Printf("Using default configuration because the new one could not be loaded: %v", err)
		return err
	}
	return nil
}

func (cfg *SystemConfigReloader) reload() error {
	var err		error
	var cfgBA	[]byte
	if cfgBA, err = ioutil.ReadFile(cfg.ConfigPath); err != nil {
		return err
	}

	if err = json.Unmarshal(cfgBA, &cfg); err != nil {
		return err
	}
	log.Printf("Reading config: %v", cfg)
	return nil
}

type ClientConfigReloader struct {
	configMu	sync.RWMutex
	config		*tls.Config
	systemCfg	*SystemConfigReloader
}

func NewClientConfigReloader(systemCfg *SystemConfigReloader) (*ClientConfigReloader, error) {
        result := &ClientConfigReloader{
		config:		&tls.Config{},
		systemCfg:	systemCfg,
        }
        if err := result.init(); err != nil {
                return nil, err
        }
        return result, nil
}

func (ccr *ClientConfigReloader) init() error {
	ccr.config.ClientAuth = tls.RequireAndVerifyClientCert
	if err := ccr.reloadServerCert(); err != nil {
		return err
	}
	if err := ccr.reloadCaCertPool(); err != nil {
		return err
	}
	return nil
}

func (ccr *ClientConfigReloader) GetConfigForClientFunc() func(*tls.ClientHelloInfo) (*tls.Config, error) {
        return func(clientHello *tls.ClientHelloInfo) (*tls.Config, error) {
                ccr.configMu.RLock()
                defer ccr.configMu.RUnlock()
                return ccr.config, nil
        }
}

func (ccr *ClientConfigReloader) reload() {
	if err := ccr.reloadServerCert(); err != nil {
		log.Printf("Keeping old TLS certificate because the new one could not be loaded: %v", err)
	}
	if err := ccr.reloadCaCertPool(); err != nil {
		log.Printf("Keeping old CA certificates because the new one could not be loaded: %v", err)
	}
}

func (ccr *ClientConfigReloader) reloadServerCert() error {
	var err		error
	var newCert	tls.Certificate

	log.Printf("Loading server certificate: %s", ccr.systemCfg.CertPath)
	log.Printf("               ... and key: %s", ccr.systemCfg.KeyPath)
        if newCert, err = tls.LoadX509KeyPair(ccr.systemCfg.CertPath, ccr.systemCfg.KeyPath); err != nil {
                return err
        }
        ccr.configMu.Lock()
        defer ccr.configMu.Unlock()
        ccr.config.Certificates = []tls.Certificate{newCert}
        return nil
}

func (ccr *ClientConfigReloader) reloadCaCertPool() error {
	var caCert	[]byte
	var files	[]os.FileInfo
	caCertPool := x509.NewCertPool()
	for _, cadir := range ccr.systemCfg.CaPaths {
		log.Printf("Reading ca path: %s", cadir)
		file, err := os.Stat(cadir)
		if err != nil {
			return err
		}
		if !file.IsDir() {
			files = []os.FileInfo{file}
			cadir = filepath.Dir(cadir)
		} else {
			if files, err = ioutil.ReadDir(cadir); err != nil {
				return err
			}
		}
		log.Printf("Adding CA certificates to pool")
		for _, f := range files {
			if f.IsDir() {
				continue
			}
			capath := filepath.Join(cadir, f.Name())
			if caCert, err = ioutil.ReadFile(capath); err != nil {
				return err
			}
			if false == caCertPool.AppendCertsFromPEM(caCert) {
				continue
			}
			log.Printf(" - %s", capath)
		}
	}
        ccr.configMu.Lock()
        defer ccr.configMu.Unlock()
	ccr.config.ClientCAs = caCertPool
	return nil
}

func main() {
	var configPath string
	flag.StringVar(&configPath, "c", "go-auth-pdns-x509.cfg", "configfile")
	flag.Parse()
	syscfg, err := NewSystemConfigReloader(configPath)
	if err != nil {
		log.Println(err)
	}
	ccr, err := NewClientConfigReloader(syscfg)
	if err != nil {
		log.Fatal(err)
	}
	c := make(chan os.Signal, 1)
	signal.Notify(c, syscall.SIGHUP)
	go func() {
		for sig := range c {
			log.Printf("Received signal: %v", sig)
			if err := syscfg.reload(); err != nil {
				log.Printf("SystemConfigReload error: %v", err)
			}
			ccr.reload()
		}
	}()
	srv := &http.Server{
		Addr:      syscfg.ExternalAddr,
		Handler:   &handler{syscfg: syscfg},
		TLSConfig: &tls.Config{},
	}
	srv.TLSConfig.GetConfigForClient = ccr.GetConfigForClientFunc()
	log.Fatal(srv.ListenAndServeTLS(syscfg.CertPath, syscfg.KeyPath))
}

type handler struct {
	syscfg		*SystemConfigReloader
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
		return "{\"error\": \"internal error - unable to generate json string\"}", 500, err
	}
	bodyrdr := strings.NewReader(string(body))
	if r, err = http.NewRequest(jsonReq.method, baseURL+jsonReq.urlpath, bodyrdr); nil != err {
		return "{\"error\": \"internal error - unable to create backend request\"}", 500, err
	}
	r.Header.Set("X-Api-Key", apiKey)
	if resp, err = http.DefaultClient.Do(r); nil != err {
		return "{\"error\": \"internal error - unable to contact pdns api\"}", 502, err
	}
	defer resp.Body.Close()
	if respBA, err = ioutil.ReadAll(resp.Body); nil != err {
		return "{\"error\": \"internal error - unable to read body of pdns api response\"}", 502, err
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
		respBody, respStatusCode, err := contactPDNS(jsonReq, h.syscfg.InternalURL, h.syscfg.ApiKey)
		if err != nil {
			log.Printf("error in contactPDNS: %v", err)
		}
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
