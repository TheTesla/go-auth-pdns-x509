package main

import (
	"bytes"
	"flag"
	"path"
	"path/filepath"
	//"crypto/rand"
	//"errors"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"strings"
	//"math/big"
	"net/http"
	"net/url"
	"golang.org/x/net/html"
	"os"
	"os/signal"
	"syscall"
	"time"
	"sync"
	"io"
)

type SystemConfigReloader struct {
	ConfigPath	string
	InternalURL	string
	ExternalAddr	string
	ApiKey		string
	CertPath	string
	KeyPath		string
	CaPaths		[]string
	CaTempPath	string
	ReloadInterval	int
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
		CaTempPath:	"catmp/",
		ReloadInterval:	10,
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
	pretty, err := json.MarshalIndent(cfg, "                    ", "    ")
	log.Printf("Reading config: %s", pretty)
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


func getRemoteCerts(caPaths []string, caTempPath string) ([]string, error) {
	var dests	[]string
	log.Printf("Downloading remote ca paths")
	for _, capath := range caPaths {
		if strings.HasPrefix(capath,"https://") {
			log.Printf("  -> %s", capath)
			caTempFilename := filepath.Join(caTempPath, strings.Replace(capath[8:], "/", "_", -1))
			destsrec, err := fileGet(caTempFilename, capath)
			dests = append(dests, destsrec...)
			if err != nil {
				return dests, err
			}
		}
	}
	return dests, nil
}



func getLocalCertsSingle(caPath string) ([]string, error) {
	var casubpaths	[]string
	path, err := os.Stat(caPath)
	if err != nil {
		return []string{caPath}, err
	}
	if !path.IsDir() {
		// if given path is a certificate file -> use this file as certificate
		return []string{caPath}, nil
	}
	// if given path is a directory -> use all certificate files in this directory
	subfiles, err := ioutil.ReadDir(caPath)
	if err != nil {
		return []string{caPath}, err
	}
	for _, f := range subfiles {
		casubpath := filepath.Join(caPath, f.Name())
		casubpaths = append(casubpaths, casubpath)
	}
	return casubpaths, nil
}

func getLocalCerts(caPaths []string) ([]string, error) {
	var casubpathscol	[]string
	for _, capath := range caPaths {
		casubpaths, err := getLocalCertsSingle(capath)
		if err != nil {
			continue
		}
		casubpathscol = append(casubpathscol, casubpaths...)
	}
	return casubpathscol, nil
}

func getNonExpCerts(caPaths []string) ([]string, error) {
	var nonExpCerts	[]string
	for _, capath := range caPaths {
		cert, _ := readCert(capath)
		if cert == nil {
			continue
		}
		now := time.Now()
		if cert.NotAfter.Before(now) {
			log.Printf("  %s", capath)
			log.Printf("    expires: %s", cert.NotAfter)
			log.Printf("      -> expired")
			continue
		}
		nonExpCerts = append(nonExpCerts, capath)
	}
	return nonExpCerts, nil
}

func contains(needle string, haystack []string) bool {
	for _, h := range haystack {
		if h == needle {
			return true
		}
	}
	return false
}

func getRMpaths(rmPaths []string, presrvPaths []string) []string {
	var toRemove []string
	for _, rmpath := range rmPaths {
		if contains(rmpath, presrvPaths) {
			continue
		}
		toRemove = append(toRemove, rmpath)
	}
	return toRemove
}

func rmFiles(rmPaths []string, presrvPaths []string) {
	toRM := getRMpaths(rmPaths, presrvPaths)
	for _, d := range toRM {
		err := os.Remove(d)
		if err != nil {
			log.Printf("Error removing file: %v", err)
		}
	}
}

// this interally used method deletes all files not being certificates not expired
func (ccr *ClientConfigReloader) cleanUpCerts(fileNames []string) {
	nonExp, _ := getNonExpCerts(fileNames)
	allTempFiles, _ := getLocalCerts(append(ccr.systemCfg.CaPaths, ccr.systemCfg.CaTempPath))
	rmFiles(allTempFiles, nonExp)
}


func readCert(certpath string) (*x509.Certificate, error) {
	certPEM, err := ioutil.ReadFile(certpath)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}
	return cert, nil
}

func showExpInfo(capath string) error {
	log.Printf("  -> %s", capath)
	cert, err := readCert(capath)
	if err != nil {
		log.Println("      Error load Certificate!")
		return err
	}
	log.Printf("       expires:   %s", cert.NotAfter)
	now := time.Now()
	log.Printf("       remaining: %s", cert.NotAfter.Sub(now))
	return nil
}

func (ccr *ClientConfigReloader) reloadCaCertPool() error {

	destsr, err := getRemoteCerts(ccr.systemCfg.CaPaths, ccr.systemCfg.CaTempPath)
	destsl, _ := getLocalCerts(ccr.systemCfg.CaPaths)
	dests := append(destsr, destsl...)
	// cleanup all local and temporary certifcates (and other files), but only if new ones are retrieved without error
	if err == nil {
		ccr.cleanUpCerts(dests)
	}

	log.Printf("Adding CA certificates to pool")
	caCertPool := x509.NewCertPool()
	for _, capath := range dests {
		caCert, err := ioutil.ReadFile(capath)
		if err != nil {
			continue
		}
		if false == caCertPool.AppendCertsFromPEM(caCert) {
			continue
		}
		showExpInfo(capath)


	}

        ccr.configMu.Lock()
        defer ccr.configMu.Unlock()
	ccr.config.ClientCAs = caCertPool
	return nil
}

func reloadAll (syscfg *SystemConfigReloader, ccr *ClientConfigReloader) {
	if err := syscfg.reload(); err != nil {
		log.Printf("SystemConfigReload error: %v", err)
	}
	ccr.reload()
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
			reloadAll(syscfg, ccr)
		}
	}()
	reloadTicker := time.NewTicker(time.Second)
	go func() {
		cnt := 0
		for _ = range reloadTicker.C {
			cnt += 1
			if cnt > syscfg.ReloadInterval {
				log.Printf("Reload config by time interval: %d s", cnt)
				cnt = 0
				reloadAll(syscfg, ccr)
			}
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

func subdomainMatches(cmdName string, certNames []string) bool {
	for _, upperLabels := range splitLabels(cmdName) {
		log.Printf("  Debug: %s -- %s", upperLabels, certNames)
		if ok, _ := IsSubset([]string{upperLabels}, certNames); ok {
			log.Printf("- break")
			return true
		}
	}
	return false
}

func isNameInChain(cmdName string, verifiedChains [][]*x509.Certificate) (bool, string) {
	var name string
	var ok bool
	for _, chain := range verifiedChains {
		log.Printf("next chain")
		for _, cert := range chain {
			log.Printf("Debug: %s -- %s", splitLabels(cmdName), cert.DNSNames)
			ok = subdomainMatches(cmdName, cert.DNSNames)
			if !ok {
				break
			}
			//for _, upperLabels := range splitLabels(cmdName) {
			//	log.Printf("  Debug: %s -- %s", upperLabels, cert.DNSNames)
			//	if ok, name = IsSubset([]string{upperLabels}, cert.DNSNames); !ok {
			//		log.Printf("- break")
			//		break
			//	}
			//}
		}
		if ok {
			return true, name
		}
	}
	return false, ""
}

func (h *handler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	log.Printf("PeerCerts: %v", req.TLS.PeerCertificates)
	log.Printf("Verified: %v", req.TLS.VerifiedChains)
	jsonReq := decodeJSONrequest(req)
	if err := handleJSONdecodeError(jsonReq, w); err != nil {
		return
	}

	DNSName := getDNSName(jsonReq.urlpath, jsonReq.jsonInterface)

	fmt.Println(DNSName)
	if ok, name := isNameInChain(DNSName, req.TLS.VerifiedChains); ok {
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


func splitLabels(x string) []string {
	labels := strings.Split(x, ".")
	labelChains := make([]string, len(labels))
	for i, _ := range labels {
		labelChains[i] = strings.Join(labels[i:], ".")
	}
	return labelChains
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


func fileGet(dest string, srcurl string) ([]string, error) {
    var dests	[]string
    dests = append(dests, dest)
    // Get the data
    resp, err := http.Get(srcurl)
    if err != nil {
        return dests, err
    }
    defer resp.Body.Close()

    buf := new(bytes.Buffer)
    buf.ReadFrom(resp.Body)
    s := buf.String() // Does a complete copy of the bytes in the buffer.
    //log.Println(s)

    // if srcurl is a directorylisting -> download all files
    links := collectLinks(strings.NewReader(s))
    for _, link := range(links) {
	if link[0] == '?' {
	    continue
	}
	u, _ := url.Parse(srcurl)
	u.Path = path.Join(u.Path, link)
	//log.Println(u.String())
        destsrec, err := fileGet(dest+strings.Replace(path.Base(link), "/", "_", -1), u.String())
	dests = append(dests, destsrec...)
        if err != nil {
            return dests, err
        }
    }
    // Create the file
    out, err := os.Create(dest)
    if err != nil {
        return dests, err
    }
    defer out.Close()

    // Write the body to file
    _, err = io.Copy(out, strings.NewReader(s))
    return dests, err
}

func getDirectoryListing(url string) (error, []string) {
    // Get the data
    resp, err := http.Get(url)
    if err != nil {
        return err, []string{}
    }
    defer resp.Body.Close()
    return nil, collectLinks(resp.Body)
}

// http://tstra.us/code/golinkgrabber/
func collectLinks(httpBody io.Reader) []string {
    links := make([]string, 0)
    page := html.NewTokenizer(httpBody)
    for {
        tokenType := page.Next()
        if tokenType == html.ErrorToken {
            return links
        }
        token := page.Token()
        if tokenType == html.StartTagToken && token.DataAtom.String() == "a" {
            for _, attr := range token.Attr {
                if attr.Key == "href" {
                    links = append(links, attr.Val)
                }
            }
        }
    }
}

