package dkron

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"time"

	version "github.com/hashicorp/go-version"
	"github.com/hashicorp/serf/serf"
)

var (
	// projectURL is the project URL.
	projectURL = "https://dkron.io/"
)

type int64arr []int64

func (a int64arr) Len() int           { return len(a) }
func (a int64arr) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }
func (a int64arr) Less(i, j int) bool { return a[i] < a[j] }

// ServerParts is used to return the parts of a server role
type ServerParts struct {
	Name         string
	ID           string
	Region       string
	Datacenter   string
	Port         int
	Bootstrap    bool
	Expect       int
	RaftVersion  int
	BuildVersion *version.Version
	Addr         net.Addr
	RPCAddr      net.Addr
	Status       serf.MemberStatus
}

// String returns a representation of this instance
func (s *ServerParts) String() string {
	return fmt.Sprintf("%s (Addr: %s) (DC: %s)",
		s.Name, s.Addr, s.Datacenter)
}

// Copy returns a copy of this struct
func (s *ServerParts) Copy() *ServerParts {
	ns := new(ServerParts)
	*ns = *s
	return ns
}

// UserAgent returns the consistent user-agent string
func UserAgent() string {
	return fmt.Sprintf("Dkron/%s (+%s;)", Version, projectURL)
}

// IsServer Returns if a member is a Dkron server. Returns a boolean,
// and a struct with the various important components
func isServer(m serf.Member) (bool, *ServerParts) {
	if m.Tags["role"] != "dkron" {
		return false, nil
	}

	if m.Tags["server"] != "true" {
		return false, nil
	}

	id := m.Name
	region := m.Tags["region"]
	datacenter := m.Tags["dc"]
	_, bootstrap := m.Tags["bootstrap"]

	expect := 0
	expectStr, ok := m.Tags["expect"]
	var err error
	if ok {
		expect, err = strconv.Atoi(expectStr)
		if err != nil {
			return false, nil
		}
	}
	// TODO
	if expect == 1 {
		bootstrap = true
	}

	// If the server is missing the rpc_addr tag, default to the serf advertise addr
	rpcIP := net.ParseIP(m.Tags["rpc_addr"])
	if rpcIP == nil {
		rpcIP = m.Addr
	}

	portStr := m.Tags["port"]
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return false, nil
	}

	buildVersion, err := version.NewVersion(m.Tags["version"])
	if err != nil {
		buildVersion = &version.Version{}
	}

	addr := &net.TCPAddr{IP: m.Addr, Port: port}
	rpcAddr := &net.TCPAddr{IP: rpcIP, Port: port}
	parts := &ServerParts{
		Name:         m.Name,
		ID:           id,
		Region:       region,
		Datacenter:   datacenter,
		Port:         port,
		Bootstrap:    bootstrap,
		Expect:       expect,
		Addr:         addr,
		RPCAddr:      rpcAddr,
		BuildVersion: buildVersion,
		Status:       m.Status,
	}
	return true, parts
}

func exists(path string) (bool, error) {
	_, err := os.Stat(path)
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return true, err
}

func verifyHMToken(verifyURL, token string) (*hmUser, error) {
	res, err := httpClient.PostForm(verifyURL, url.Values{"app_token": []string{token}})
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	data, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}
	var user hmUser
	err = json.Unmarshal(data, &user)
	return &user, err
}

var httpClient = &http.Client{
	Transport: &http.Transport{
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
			DualStack: true,
		}).DialContext,
		MaxIdleConns:        100,
		IdleConnTimeout:     90 * time.Second,
		MaxIdleConnsPerHost: 1000,
	},
}

type hmUser struct {
	UserID string `json:"user_id,omitempty"`
	Email  string `json:"tid,omitempty"`
}
