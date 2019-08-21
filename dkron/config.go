package dkron

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/hashicorp/go-sockaddr/template"
	flag "github.com/spf13/pflag"
)

// Config stores all configuration options for the dkron package.
type Config struct {
	NodeName                string `mapstructure:"node-name"`
	BindAddr                string `mapstructure:"bind-addr"`
	HTTPAddr                string `mapstructure:"http-addr"`
	Profile                 string
	Interface               string
	AdvertiseAddr           string            `mapstructure:"advertise-addr"`
	Tags                    map[string]string `mapstructure:"tags"`
	SnapshotPath            string            `mapstructure:"snapshot-path"`
	ReconnectInterval       time.Duration     `mapstructure:"reconnect-interval"`
	ReconnectTimeout        time.Duration     `mapstructure:"reconnect-timeout"`
	TombstoneTimeout        time.Duration     `mapstructure:"tombstone-timeout"`
	DisableNameResolution   bool              `mapstructure:"disable-name-resolution"`
	KeyringFile             string            `mapstructure:"keyring-file"`
	RejoinAfterLeave        bool              `mapstructure:"rejoin-after-leave"`
	Server                  bool
	EncryptKey              string        `mapstructure:"encrypt"`
	StartJoin               []string      `mapstructure:"join"`
	RetryJoinLAN            []string      `mapstructure:"retry-join"`
	RetryJoinMaxAttemptsLAN int           `mapstructure:"retry-max"`
	RetryJoinIntervalLAN    time.Duration `mapstructure:"retry-interval"`
	RPCPort                 int           `mapstructure:"rpc-port"`
	AdvertiseRPCPort        int           `mapstructure:"advertise-rpc-port"`
	LogLevel                string        `mapstructure:"log-level"`
	Datacenter              string
	Region                  string

	// Bootstrap mode is used to bring up the first Dkron server.  It is
	// required so that it can elect a leader without any other nodes
	// being present
	Bootstrap bool

	// BootstrapExpect tries to automatically bootstrap the Dkron cluster,
	// by withholding peers until enough servers join.
	BootstrapExpect int `mapstructure:"bootstrap-expect"`

	// DataDir is the directory to store our state in
	DataDir string `mapstructure:"data-dir"`

	// DevMode is used for development purposes only and limits the
	// use of persistence or state.
	DevMode bool

	// ReconcileInterval controls how often we reconcile the strongly
	// consistent store with the Serf info. This is used to handle nodes
	// that are force removed, as well as intermittent unavailability during
	// leader election.
	ReconcileInterval time.Duration

	MailHost          string `mapstructure:"mail-host"`
	MailPort          uint16 `mapstructure:"mail-port"`
	MailUsername      string `mapstructure:"mail-username"`
	MailPassword      string `mapstructure:"mail-password"`
	MailFrom          string `mapstructure:"mail-from"`
	MailPayload       string `mapstructure:"mail-payload"`
	MailSubjectPrefix string `mapstructure:"mail-subject-prefix"`

	WebhookURL     string   `mapstructure:"webhook-url"`
	WebhookPayload string   `mapstructure:"webhook-payload"`
	WebhookHeaders []string `mapstructure:"webhook-headers"`

	// DogStatsdAddr is the address of a dogstatsd instance. If provided,
	// metrics will be sent to that instance
	DogStatsdAddr string `mapstructure:"dog-statsd-addr"`
	// DogStatsdTags are the global tags that should be sent with each packet to dogstatsd
	// It is a list of strings, where each string looks like "my_tag_name:my_tag_value"
	DogStatsdTags []string `mapstructure:"dog-statsd-tags"`
	StatsdAddr    string   `mapstructure:"statsd-addr"`
}

// DefaultBindPort is the default port that dkron will use for Serf communication
const (
	DefaultBindPort int = 8946
	DefaultRPCPort  int = 6868
)

// DefaultConfig returns a Config struct pointer with sensible
// default settings.
func DefaultConfig() *Config {
	hostname, err := os.Hostname()
	if err != nil {
		log.Panic(err)
	}

	tags := map[string]string{}

	return &Config{
		NodeName:          hostname,
		BindAddr:          fmt.Sprintf("0.0.0.0:%d", DefaultBindPort),
		HTTPAddr:          ":8080",
		Profile:           "lan",
		LogLevel:          "info",
		RPCPort:           DefaultRPCPort,
		MailSubjectPrefix: "[Dkron]",
		Tags:              tags,
		DataDir:           "dkron.data",
		Datacenter:        "dc1",
		Region:            "global",
		ReconcileInterval: 60 * time.Second,
	}
}

// ConfigFlagSet creates all of our configuration flags.
func ConfigFlagSet() *flag.FlagSet {
	c := DefaultConfig()
	cmdFlags := flag.NewFlagSet("agent flagset", flag.ContinueOnError)

	cmdFlags.Bool("server", false, "This node is running in server mode")
	cmdFlags.String("node-name", c.NodeName, "Name of this node. Must be unique in the cluster")
	cmdFlags.String("bind-addr", c.BindAddr, "Address to bind network listeners to")
	cmdFlags.String("advertise-addr", "", "Address used to advertise to other nodes in the cluster. By default, the bind address is advertised")
	cmdFlags.String("http-addr", c.HTTPAddr, "Address to bind the UI web server to. Only used when server")
	cmdFlags.String("profile", c.Profile, "Profile is used to control the timing profiles used")
	cmdFlags.StringSlice("join", []string{}, "An initial agent to join with. This flag can be specified multiple times")
	cmdFlags.StringSlice("retry-join", []string{}, "Address of an agent to join at start time with retries enabled. Can be specified multiple times.")
	cmdFlags.Int("retry-max", 0, "Maximum number of join attempts. Defaults to 0, which will retry indefinitely.")
	cmdFlags.String("retry-interval", "0", "Time to wait between join attempts.")
	cmdFlags.StringSlice("tag", []string{}, "Tag can be specified multiple times to attach multiple key/value tag pairs to the given node, specified as key=value")
	cmdFlags.String("encrypt", "", "Key for encrypting network traffic. Must be a base64-encoded 16-byte key")
	cmdFlags.String("log-level", c.LogLevel, "Log level (debug|info|warn|error|fatal|panic)")
	cmdFlags.Int("rpc-port", c.RPCPort, "RPC Port used to communicate with clients. Only used when server. The RPC IP Address will be the same as the bind address")
	cmdFlags.Int("advertise-rpc-port", 0, "Use the value of rpc-port by default")
	cmdFlags.Int("bootstrap-expect", 0, "Provides the number of expected servers in the datacenter. Either this value should not be provided or the value must agree with other servers in the cluster. When provided, Dkron waits until the specified number of servers are available and then bootstraps the cluster. This allows an initial leader to be elected automatically. This flag requires server mode.")
	cmdFlags.String("data-dir", c.DataDir, "Specifies the directory to use for server-specific data, including the replicated log. By default, this is the top-level data-dir, like [/var/lib/dkron]")
	cmdFlags.String("datacenter", c.Datacenter, "Specifies the data center of the local agent. All members of a datacenter should share a local LAN connection.")
	cmdFlags.String("region", c.Region, "Specifies the region the Dkron agent is a member of. A region typically maps to a geographic region, for example us, with potentially multiple zones, which map to datacenters such as us-west and us-east")

	// Notifications
	cmdFlags.String("mail-host", "", "Mail server host address to use for notifications")
	cmdFlags.Uint16("mail-port", 0, "Mail server port")
	cmdFlags.String("mail-username", "", "Mail server username used for authentication")
	cmdFlags.String("mail-password", "", "Mail server password to use")
	cmdFlags.String("mail-from", "", "From email address to use")
	cmdFlags.String("mail-payload", "", "Notification mail payload")
	cmdFlags.String("mail-subject-prefix", c.MailSubjectPrefix, "Notification mail subject prefix")

	cmdFlags.String("webhook-url", "", "Webhook url to call for notifications")
	cmdFlags.String("webhook-payload", "", "Body of the POST request to send on webhook call")
	cmdFlags.StringSlice("webhook-header", []string{}, "Headers to use when calling the webhook URL. Can be specified multiple times")

	cmdFlags.String("dog-statsd-addr", "", "DataDog Agent address")
	cmdFlags.StringSlice("dog-statsd-tags", []string{}, "Datadog tags, specified as key:value")
	cmdFlags.String("statsd-addr", "", "Statsd address")

	return cmdFlags
}

// normalizeAddrs normalizes Addresses and AdvertiseAddrs to always be
// initialized and have sane defaults.
func (c *Config) normalizeAddrs() error {
	if c.BindAddr != "" {
		ipStr, err := parseSingleIPTemplate(c.BindAddr)
		if err != nil {
			return fmt.Errorf("Bind address resolution failed: %v", err)
		}
		c.BindAddr = ipStr
	}

	if c.HTTPAddr != "" {
		ipStr, err := parseSingleIPTemplate(c.HTTPAddr)
		if err != nil {
			return fmt.Errorf("Bind address resolution failed: %v", err)
		}
		c.HTTPAddr = ipStr
	}

	addr, err := normalizeAdvertise(c.AdvertiseAddr, c.BindAddr, DefaultBindPort, c.DevMode)
	if err != nil {
		return fmt.Errorf("Failed to parse HTTP advertise address (%v, %v, %v, %v): %v", c.AdvertiseAddr, c.BindAddr, DefaultBindPort, c.DevMode, err)
	}
	c.AdvertiseAddr = addr

	return nil
}

// parseSingleIPTemplate is used as a helper function to parse out a single IP
// address from a config parameter.
func parseSingleIPTemplate(ipTmpl string) (string, error) {
	out, err := template.Parse(ipTmpl)
	if err != nil {
		return "", fmt.Errorf("Unable to parse address template %q: %v", ipTmpl, err)
	}

	ips := strings.Split(out, " ")
	switch len(ips) {
	case 0:
		return "", errors.New("No addresses found, please configure one.")
	case 1:
		return ips[0], nil
	default:
		return "", fmt.Errorf("Multiple addresses found (%q), please configure one.", out)
	}
}

// normalizeAdvertise returns a normalized advertise address.
//
// If addr is set, it is used and the default port is appended if no port is
// set.
//
// If addr is not set and bind is a valid address, the returned string is the
// bind+port.
//
// If addr is not set and bind is not a valid advertise address, the hostname
// is resolved and returned with the port.
//
// Loopback is only considered a valid advertise address in dev mode.
func normalizeAdvertise(addr string, bind string, defport int, dev bool) (string, error) {
	addr, err := parseSingleIPTemplate(addr)
	if err != nil {
		return "", fmt.Errorf("Error parsing advertise address template: %v", err)
	}

	if addr != "" {
		// Default to using manually configured address
		_, _, err = net.SplitHostPort(addr)
		if err != nil {
			if !isMissingPort(err) && !isTooManyColons(err) {
				return "", fmt.Errorf("Error parsing advertise address %q: %v", addr, err)
			}

			// missing port, append the default
			return net.JoinHostPort(addr, strconv.Itoa(defport)), nil
		}

		return addr, nil
	}

	// Fallback to bind address first, and then try resolving the local hostname
	ips, err := net.LookupIP(bind)
	if err != nil {
		return "", fmt.Errorf("Error resolving bind address %q: %v", bind, err)
	}

	// Return the first non-localhost unicast address
	for _, ip := range ips {
		if ip.IsLinkLocalUnicast() || ip.IsGlobalUnicast() {
			return net.JoinHostPort(ip.String(), strconv.Itoa(defport)), nil
		}
		if ip.IsLoopback() {
			if dev {
				// loopback is fine for dev mode
				return net.JoinHostPort(ip.String(), strconv.Itoa(defport)), nil
			}
			return "", fmt.Errorf("Defaulting advertise to localhost is unsafe, please set advertise manually")
		}
	}

	// Bind is not localhost but not a valid advertise IP, use first private IP
	addr, err = parseSingleIPTemplate("{{ GetPrivateIP }}")
	if err != nil {
		return "", fmt.Errorf("Unable to parse default advertise address: %v", err)
	}
	return net.JoinHostPort(addr, strconv.Itoa(defport)), nil
}

// isMissingPort returns true if an error is a "missing port" error from
// net.SplitHostPort.
func isMissingPort(err error) bool {
	// matches error const in net/ipsock.go
	const missingPort = "missing port in address"
	return err != nil && strings.Contains(err.Error(), missingPort)
}

// isTooManyColons returns true if an error is a "too many colons" error from
// net.SplitHostPort.
func isTooManyColons(err error) bool {
	// matches error const in net/ipsock.go
	const tooManyColons = "too many colons in address"
	return err != nil && strings.Contains(err.Error(), tooManyColons)
}

// AddrParts returns the parts of the BindAddr that should be
// used to configure Serf.
func (c *Config) AddrParts(address string) (string, int, error) {
	checkAddr := address

START:
	_, _, err := net.SplitHostPort(checkAddr)
	if ae, ok := err.(*net.AddrError); ok && ae.Err == "missing port in address" {
		checkAddr = fmt.Sprintf("%s:%d", checkAddr, DefaultBindPort)
		goto START
	}
	if err != nil {
		return "", 0, err
	}

	// Get the address
	addr, err := net.ResolveTCPAddr("tcp", checkAddr)
	if err != nil {
		return "", 0, err
	}

	return addr.IP.String(), addr.Port, nil
}

// EncryptBytes returns the encryption key configured.
func (c *Config) EncryptBytes() ([]byte, error) {
	return base64.StdEncoding.DecodeString(c.EncryptKey)
}
