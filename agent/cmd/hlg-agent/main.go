package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	goruntime "runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"hlg/internal/agentupdate"
	"hlg/internal/atomicfile"
	"hlg/internal/certstore"
	"hlg/internal/config"
	"hlg/internal/deps"
	"hlg/internal/download"
	"hlg/internal/enroll"
	"hlg/internal/initstring"
	"hlg/internal/iperf"
	"hlg/internal/keyset"
	"hlg/internal/licenses"
	"hlg/internal/logging"
	"hlg/internal/probe"
	"hlg/internal/runtime"
	"hlg/internal/server"
	"hlg/internal/token"
)

var publicIPClient = &http.Client{Timeout: 5 * time.Second}

// resolveLogLevel maps a config string to a logging.Level, warning (on stdout,
// before the logger exists) about unrecognized values.
func resolveLogLevel(value string) logging.Level {
	level, ok := logging.ParseLevel(value)
	if !ok {
		fmt.Fprintf(os.Stderr, "unknown log level %q, using info\n", value)
	}
	return level
}

// downloadTokenWindow is the replay-budget window for download tokens;
// it matches the controller's 15-minute token lifetime.
const downloadTokenWindow = 15 * time.Minute

type publicIPState struct {
	mu        sync.RWMutex
	ipv4      string
	ipv6      string
	override4 string
	override6 string
}

func newPublicIPState(cfg config.Config) *publicIPState {
	state := &publicIPState{override4: cfg.PublicIPv4, override6: cfg.PublicIPv6}
	state.set(cfg.PublicIPv4, cfg.PublicIPv6)
	return state
}

func (s *publicIPState) set(ipv4, ipv6 string) {
	s.mu.Lock()
	if s.override4 != "" {
		ipv4 = s.override4
	}
	if s.override6 != "" {
		ipv6 = s.override6
	}
	s.ipv4 = ipv4
	s.ipv6 = ipv6
	s.mu.Unlock()
}

func (s *publicIPState) applyOverrides(cfg *config.Config) {
	if s == nil || cfg == nil {
		return
	}
	s.mu.RLock()
	if s.override4 != "" {
		cfg.PublicIPv4 = s.override4
	}
	if s.override6 != "" {
		cfg.PublicIPv6 = s.override6
	}
	s.mu.RUnlock()
}

func (s *publicIPState) localOverrides() (ipv4, ipv6 string) {
	if s == nil {
		return "", ""
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.override4, s.override6
}

func (s *publicIPState) IPv4() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.ipv4
}

func (s *publicIPState) IPv6() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.ipv6
}

func main() {
	var (
		configFile         string
		upgradeCheck       bool
		upgradeForce       bool
		serviceMode        string
		installDir         string
		binaryName         string
		serviceName        string
		serviceUser        string
		enrollToken        string
		initToken          string
		initString         string
		nodeToken          string
		nodeID             string
		bind               string
		port               string
		dataDir            string
		publicIPv4         string
		publicIPv6         string
		frontendOrigin     string
		iperfDebugOutput   bool
		logLevel           string
		logFile            string
		installDepsYes     bool
		depsSource         string
		depsPath           string
		probeTool          string
		probeTarget        string
		probeIPv4          bool
		probeIPv6          bool
		runInit            bool
		initNonInteractive bool
	)

	flag.StringVar(&configFile, "config", "", "Path to a local agent config file")
	flag.StringVar(&configFile, "c", "", "Alias for --config")
	flag.BoolVar(&upgradeCheck, "check", false, "upgrade: report only, make no changes")
	flag.BoolVar(&upgradeForce, "force", false, "upgrade: reinstall even when already on the current build")
	flag.StringVar(&serviceMode, "service", "auto", "Service manager: auto, systemd, init.d or none")
	flag.StringVar(&installDir, "path", "/opt/looking-glass", "Install directory")
	flag.StringVar(&binaryName, "name", "hlg-agent", "Installed agent binary name")
	flag.StringVar(&serviceName, "service-name", "hlg-agent", "Service name for systemd/OpenRC (default: --name)")
	// Alias kept for the served installer's long flag.
	flag.StringVar(&binaryName, "binary-name", binaryName, "Alias for --name")
	flag.StringVar(&serviceUser, "user", "root", "Existing service user (default: root; never created by init)")
	flag.StringVar(&enrollToken, "enroll-token", "", "Enrollment token (env LG_ENROLL_TOKEN)")
	flag.StringVar(&initToken, "key", "", "One-time node init key, or the full init string host[:port]/lginit_<key> (env LG_INIT_TOKEN)")
	flag.StringVar(&initToken, "k", "", "Alias for --key")
	flag.StringVar(&initString, "init-string", "", "One-line init string: host[:port]/lginit_<key> (env LG_INIT_STRING)")
	flag.StringVar(&nodeToken, "node-token", "", "Node config pull token (env LG_NODE_TOKEN)")
	flag.StringVar(&nodeID, "node-id", "", "Node ID hint (env LG_NODE_ID)")
	flag.StringVar(&bind, "bind", "", "Bind address (env LG_BIND)")
	flag.StringVar(&port, "port", "", "Bind port shorthand (equivalent to --bind :PORT)")
	flag.StringVar(&port, "p", "", "Alias for --port")
	flag.StringVar(&dataDir, "data-dir", "", "Data directory (env LG_DATA_DIR)")
	flag.StringVar(&publicIPv4, "public-ipv4", "", "Reported public IPv4 address (env LG_PUBLIC_IPV4)")
	flag.StringVar(&publicIPv6, "public-ipv6", "", "Reported public IPv6 address (env LG_PUBLIC_IPV6)")
	flag.StringVar(&frontendOrigin, "frontend-origin", "", "Allowed frontend origin (env LG_FRONTEND_ORIGIN)")
	flag.BoolVar(&iperfDebugOutput, "iperf-debug-output", false, "Expose raw iperf3 debug events over control websocket (env LG_IPERF_DEBUG_OUTPUT)")
	flag.StringVar(&logLevel, "log-level", "", "Log level: debug, info, warn, error (env LG_LOG_LEVEL)")
	flag.StringVar(&logFile, "log-file", "", "Write logs to this file instead of stdout (env LG_LOG_FILE)")
	flag.BoolVar(&installDepsYes, "install-deps-yes", false, "init: install every missing runtime dependency without prompting")
	flag.StringVar(&depsSource, "source", "", "deps config: system|builtin|download|path|install|auto (applied to every named tool)")
	flag.StringVar(&depsPath, "tool-path", "", "deps config --source path: the binary path to record")
	flag.BoolVar(&probeIPv4, "4", false, "probe: use IPv4 (default)")
	flag.BoolVar(&probeIPv6, "6", false, "probe: use IPv6")
	flag.BoolVar(&runInit, "i", false, "run: install (init) first if needed, then serve")
	flag.BoolVar(&initNonInteractive, "yes", false, "init: accept defaults for any unset option instead of prompting")
	flag.Usage = usage

	// `hlg-agent <command> [flags]`; a bare invocation prints help. The first
	// non-flag argument is the command, and `service` takes one more.
	command, args := selectCommand(os.Args[1:])
	serviceAction := "status"
	depsAction := "check"
	var depsTools []string

	switch command {
	case "service":
		if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
			serviceAction = args[0]
			args = args[1:]
		}
	case "deps":
		// `deps <check|install|upgrade|builtin|config> [tool...] [--force]`: leading
		// positionals, then flags.
		index := 0
		for ; index < len(args) && !strings.HasPrefix(args[index], "-"); index++ {
		}
		if positional := args[:index]; len(positional) > 0 {
			depsAction = positional[0]
			depsTools = positional[1:]
		}
		args = args[index:]
	case "probe":
		// `probe [-4|-6] <ping|mtr|traceroute> <target>`: flags may precede the
		// positionals, so split them: positionals here, flags left for flag.Parse.
		positional := make([]string, 0, 2)
		flagArgs := make([]string, 0, len(args))
		for _, arg := range args {
			if strings.HasPrefix(arg, "-") {
				flagArgs = append(flagArgs, arg)
				continue
			}
			positional = append(positional, arg)
		}
		if len(positional) > 0 {
			probeTool = positional[0]
		}
		if len(positional) > 1 {
			probeTarget = positional[1]
		}
		args = flagArgs
	}
	flag.CommandLine.Parse(args)

	// Flags the operator actually passed. Maintenance commands (upgrade, doctor,
	// uninstall, service) must not fall back to a flag's compiled-in default when
	// the install used custom names: unset means "derive from the recorded config
	// and the running binary".
	explicitFlags := map[string]bool{}
	flag.Visit(func(f *flag.Flag) { explicitFlags[f.Name] = true })
	if !explicitFlags["service-name"] && explicitFlags["name"] {
		serviceName = binaryName
	}

	// --port is a shorthand for --bind :PORT.
	if bind == "" && port != "" {
		bind = ":" + strings.TrimPrefix(port, ":")
	}

	resolveIdentity := func() (installIdentity, error) {
		return resolveInstallIdentity(explicitFlags, configFile, installDir, dataDir, serviceMode, binaryName, serviceName)
	}

	flagValues := map[string]string{
		"enroll-token":    enrollToken,
		"init-token":      initToken,
		"init-string":     initString,
		"node-token":      nodeToken,
		"node-id":         nodeID,
		"bind":            bind,
		"data-dir":        dataDir,
		"public-ipv4":     publicIPv4,
		"public-ipv6":     publicIPv6,
		"frontend-origin": frontendOrigin,
		"log-level":       logLevel,
		"log-file":        logFile,
	}

	switch command {
	case "run":
		// `run -i` initializes this process in place if no stored node identity
		// exists. It never installs a system service or packages.
		if runInit && configFile == "" {
			configFile = filepath.Join(firstNonEmpty(dataDir, os.Getenv("LG_DATA_DIR"), config.DefaultDataDir), "agent.json")
		}
	case "init":
		// The controller comes from the init string/key, or from LG_CONTROLLER.
		// When interactive, ask for the one-time init string if it was not
		// supplied on the command line or through the environment.
		initStringInput := firstNonEmpty(initString, os.Getenv("LG_INIT_STRING"))
		initTokenInput := firstNonEmpty(initToken, os.Getenv("LG_INIT_TOKEN"))
		if initStringInput == "" && initTokenInput == "" && isTerminal(os.Stdin) && !initNonInteractive {
			answer := promptLine("init key or host[:port]/lginit_<key> [required]:")
			if strings.Contains(answer, "/") {
				initStringInput = answer
			} else {
				initTokenInput = answer
			}
		}
		resolvedController, resolvedKey, err := resolveInitInputs(
			os.Getenv("LG_CONTROLLER"), initStringInput, initTokenInput,
		)
		if err != nil {
			log.Fatal(err)
		}
		if resolvedController == "" && resolvedKey != "" && isTerminal(os.Stdin) && !initNonInteractive {
			resolvedController, _, err = resolveInitInputs(promptLine("controller URL [required]:"), initStringInput, initTokenInput)
			if err != nil {
				log.Fatal(err)
			}
		}
		if resolvedController == "" {
			log.Fatal("init requires the controller in --key/--init-string (host[:port]/lginit_<key>) or LG_CONTROLLER")
		}
		if resolvedKey == "" {
			log.Fatal("init requires --key")
		}
		// Interactive by default: ask for any install option not given on the
		// command line (paths, service settings, listen port). --yes or a non-TTY
		// accepts the defaults; explicit flags always win.
		if err := promptInitOptions(&installDir, &serviceMode, &serviceName, &dataDir, &bind, configFile, explicitFlags, initNonInteractive); err != nil {
			log.Fatal(err)
		}
		// Non-interactive init and --yes both use the automatic source choice:
		// system tools are kept, then a built-in implementation or data-dir
		// download is selected for anything missing.
		installDepsYes = installDepsYes || initNonInteractive || !isTerminal(os.Stdin)
		if err := runInstall(configFile, installDir, dataDir, serviceMode, serviceUser, binaryName, serviceName, resolvedController, resolvedKey, nodeID, bind, frontendOrigin, logLevel, logFile, installDepsYes); err != nil {
			log.Fatal(err)
		}
		return
	case "upgrade":
		identity, err := resolveIdentity()
		if err != nil {
			log.Fatal(err)
		}
		if err := runUpdate(identity, upgradeForce, upgradeCheck); err != nil {
			log.Fatal(err)
		}
		return
	case "doctor":
		identity, err := resolveIdentity()
		if err != nil {
			log.Fatal(err)
		}
		if err := runSelfCheck(identity); err != nil {
			log.Fatal(err)
		}
		return
	case "uninstall":
		identity, err := resolveIdentity()
		if err != nil {
			log.Fatal(err)
		}
		if err := runUninstall(identity); err != nil {
			log.Fatal(err)
		}
		return
	case "service":
		identity, err := resolveIdentity()
		if err != nil {
			log.Fatal(err)
		}
		if err := runServiceAction(serviceAction, identity); err != nil {
			log.Fatal(err)
		}
		return
	case "deps":
		// Discover agent.json like the serving path does, so the controller,
		// data dir, and recorded tools are visible to `deps` (a bare
		// `deps config` otherwise sees no controller and cannot download).
		// Record the resolved path so reads/writes of agent.json#tools use the
		// SAME file as the config load (honoring -c), not a re-discovered one.
		depsConfigPath = discoverConfigFile(configFile)
		depsCfg, _ := config.Load(config.LoadOptions{File: depsConfigPath, Flags: flagValues})
		depsDataDir := strings.TrimSpace(depsCfg.DataDir)
		if depsDataDir == "" {
			identity, err := resolveIdentity()
			if err != nil {
				log.Fatal(err)
			}
			depsDataDir = identity.DataDir
		}
		if err := runDeps(context.Background(), depsCfg.Controller, depsAction, depsTools, depsDataDir, upgradeForce, depsSource, depsPath, log.Printf); err != nil {
			log.Fatal(err)
		}
		// A changed source only takes effect on restart; offer to do it now.
		if depsAction != "check" && (depsAction != "config" || depsConfigChanged) {
			identity, err := resolveIdentity()
			if err != nil {
				log.Fatal(err)
			}
			mode, err := normalizeServiceMode(identity.ServiceMode, false)
			if err != nil {
				log.Fatal(err)
			}
			restartServiceForDeps(mode, identity.ServiceName, log.Printf)
		}
		return
	case "probe":
		if err := runProbe(context.Background(), probeTool, probeTarget, probeIPv4, probeIPv6); err != nil {
			log.Fatal(err)
		}
		return
	case "version":
		fmt.Printf("%s (%s)\n", runtime.Version, runtime.BuildID)
		return
	case "licenses":
		text, err := licenses.Text()
		if err != nil {
			log.Fatal(err)
		}
		fmt.Print(text)
		return
	case "help":
		usage()
		return
	default:
		log.Fatalf("unknown command %q (try: init, run, upgrade, service, deps, probe, doctor, uninstall)", command)
	}

	bootstrapCfg, bootstrapPath, err := discoverBootstrapInput()
	if err != nil {
		log.Fatal(err)
	}

	configFile = discoverConfigFile(configFile)
	cfg, err := config.Load(config.LoadOptions{
		File:  configFile,
		Flags: flagValues,
	})
	if err != nil {
		log.Fatal(err)
	}
	// Plain `run -k` must not enroll. `run -i` accepts a key only when the
	// mounted data dir has no usable stored identity. Host `init` can still
	// finish its persisted bootstrap-input.json on the first service start.
	runInitFresh, err := prepareRunBootstrap(&cfg, runInit, bootstrapCfg)
	if err != nil {
		log.Fatal(err)
	}
	if iperfDebugOutput {
		cfg.IperfDebugOutput = true
	}
	// Install the leveled logger now that every config source (file, env,
	// flags, bootstrap input) has been applied, so log settings are final.
	logger, err := logging.New(logging.Options{Level: resolveLogLevel(cfg.LogLevel), File: cfg.LogFile})
	if err != nil {
		log.Fatalf("logging setup failed: %v", err)
	}
	defer logger.Close()
	logging.SetDefault(logger)
	publicIPs := newPublicIPState(cfg)

	var bundle *config.SignedBundle
	if cfg.Controller != "" {
		refreshPublicIPs(context.Background(), &cfg, publicIPs)
		client := enroll.NewClient(cfg)
		if cfg.NodeToken == "" {
			if storedToken, err := enroll.LoadNodeToken(cfg.DataDir); err == nil {
				cfg.NodeToken = storedToken
			}
		}
		if stored, err := enroll.LoadStoredConfig(cfg.DataDir); err == nil {
			logging.Infof("loaded stored config node_id=%s", stored.NodeID)
			if cfg.NodeID == "" {
				cfg.NodeID = stored.NodeID
			}
			bundle = &stored
		}
		if bundle == nil && cfg.NodeToken != "" {
			client = enroll.NewClient(cfg)
			pulled, err := client.PullConfig(context.Background())
			if err == nil {
				logging.Infof("pulled config node_id=%s", pulled.NodeID)
				bundle = &pulled
			} else {
				logging.Warnf("config pull failed: %v", err)
			}
		}
		if bundle == nil && cfg.InitToken != "" {
			client = enroll.NewClient(cfg)
			resp, err := client.BootstrapOnce(context.Background())
			if err == nil {
				logging.Infof("bootstrap status=%s node_id=%s", resp.Status, resp.NodeID)
				cfg.NodeID = resp.NodeID
				cfg.NodeToken = resp.NodeToken
				bundle = &resp.Config
				if bootstrapPath != "" {
					_ = os.Remove(bootstrapPath)
				}
			} else {
				logging.Warnf("bootstrap failed: %v", err)
			}
		}
		if bundle == nil && cfg.EnrollToken != "" {
			client = enroll.NewClient(cfg)
			for attempt := 0; ; attempt++ {
				resp, err := client.EnrollOnce(context.Background())
				if err == nil {
					logging.Infof("enrollment status=%s node_id=%s", resp.Status, resp.NodeID)
					if resp.Status == "active" {
						cfg.NodeID = resp.NodeID
						bundle = &resp.Config
						break
					}
				} else {
					logging.Warnf("enrollment failed: %v", err)
				}
				time.Sleep(enroll.Backoff(attempt))
			}
		}
	}

	if bundle == nil {
		if stored, err := enroll.LoadStoredConfig(cfg.DataDir); err == nil {
			logging.Warnf("loaded fallback stored config node_id=%s", stored.NodeID)
			if cfg.NodeID == "" {
				cfg.NodeID = stored.NodeID
			}
			bundle = &stored
		}
	}
	if bundle == nil {
		bundle = cfg.RemoteBundle
	}
	if bundle == nil {
		if cfg.Controller == "" {
			logging.Fatalf("signed config bundle is required before starting public services; set a controller URL to bootstrap")
		}
		// No bundle at all (fresh node, or local certificate+config were lost).
		// Nothing can reach us yet — the worker cannot connect to a node without
		// a valid certificate — so recovery is entirely agent-driven: retry
		// acquisition in memory WITHOUT binding a port, until a verified bundle
		// arrives, then continue with normal startup.
		bundle = bootstrapUntilReady(context.Background(), cfg, publicIPs)
	}
	verifyNodeID := cfg.NodeID
	if verifyNodeID == "" {
		verifyNodeID = bundle.NodeID
	}
	if err := config.VerifySignedBundle(*bundle, verifyNodeID, time.Now()); err != nil {
		if errors.Is(err, config.ErrBundleSignature) {
			logging.Warnf("stored signed config invalid; clearing cached bundle and attempting recovery: %v", err)
			_ = os.Remove(filepath.Join(cfg.DataDir, "config.json"))
			if recovered := recoverSignedBundle(context.Background(), cfg); recovered != nil {
				bundle = recovered
				verifyNodeID = cfg.NodeID
				if verifyNodeID == "" {
					verifyNodeID = bundle.NodeID
				}
				if err := config.VerifySignedBundle(*bundle, verifyNodeID, time.Now()); err != nil {
					logging.Fatalf("signed config bundle verification failed after recovery: %v", err)
				}
			} else {
				logging.Fatalf("signed config bundle verification failed: %v", err)
			}
		} else {
			logging.Fatalf("signed config bundle verification failed: %v", err)
		}
	}
	store := certstore.New(cfg.DataDir)
	if cfg.Controller != "" && cfg.NodeToken != "" {
		bundle, _ = syncControllerState(context.Background(), cfg, bundle, store, publicIPs)
	}
	if runInitFresh {
		if err := persistRunBootstrapConfig(configFile, cfg); err != nil {
			logging.Fatalf("persist run init config: %v", err)
		}
	}
	bootstrapControllerURL := cfg.Controller
	bootstrapEnrollToken := cfg.EnrollToken
	bootstrapInitToken := cfg.InitToken
	bootstrapNodeToken := cfg.NodeToken
	cfg, err = config.Load(config.LoadOptions{
		File:   configFile,
		Flags:  flagValues,
		Bundle: bundle,
	})
	if err != nil {
		logging.Fatalf("%v", err)
	}
	applyBootstrapInput(&cfg, bootstrapCfg)
	cfg.Controller = bootstrapControllerURL
	cfg.EnrollToken = bootstrapEnrollToken
	cfg.InitToken = bootstrapInitToken
	cfg.NodeToken = bootstrapNodeToken
	if iperfDebugOutput {
		cfg.IperfDebugOutput = true
	}
	publicIPs.set(cfg.PublicIPv4, cfg.PublicIPv6)
	if cfg.NodeID == "" {
		logging.Fatalf("signed config bundle missing node_id")
	}
	if cfg.Domain == "" {
		logging.Fatalf("signed config bundle missing domain")
	}
	if runInit {
		ensureRunDependencies(context.Background(), &cfg, configFile)
	}

	// Agent-managed downloads remain discoverable after system packages.
	if err := deps.AppendPath(cfg.DataDir); err != nil {
		logging.Warnf("deps: could not prepare %s: %v", cfg.DataDir, err)
	}
	adminKeys := adminKeysFromBundle(bundle)
	if len(adminKeys) == 0 {
		logging.Fatalf("signed config bundle missing admin_verify key")
	}
	syncRunner := newSyncRunner(cfg, bundle, store, publicIPs)
	admin := server.NewAdminVerifier(server.AdminVerifierConfig{
		NodeID:     cfg.NodeID,
		PublicKeys: adminKeys,
		NonceCache: token.NewNonceCache(token.DefaultNonceCacheCapacity, token.DefaultNonceCacheTTL),
	})
	iperfManager := iperf.NewManager(iperf.Config{
		Host:        cfg.Domain,
		PortMin:     cfg.Limits.IperfPortMin,
		PortMax:     cfg.Limits.IperfPortMax,
		TTL:         time.Duration(cfg.Limits.IperfTTLSeconds) * time.Second,
		ActiveLimit: cfg.Limits.IperfActiveSessions,
		MaxDuration: cfg.Limits.IperfMaxDuration,
		MaxParallel: cfg.Limits.IperfMaxParallel,
		MaxRuns:     cfg.Limits.IperfMaxRuns,
		RunBudget:   cfg.Limits.IperfRunBudget,
		DebugOutput: cfg.IperfDebugOutput,
		IperfPath:   deps.UsablePath(cfg.Tools, "iperf3"),
	})
	handler := server.NewControlHandler(server.ControlOptions{
		Iperf:         iperfManager,
		Admin:         admin,
		Bundle:        bundle,
		AllowedOrigin: cfg.FrontendOrigin,
		Reload: func(reloadCtx context.Context) error {
			return syncRunner.run(reloadCtx)
		},
	})
	ks, err := keyset.New(bundle.Keyset)
	if err != nil {
		logging.Fatalf("%v", err)
	}
	verifier := token.NewVerifier(token.VerifierConfig{
		NodeID:               cfg.NodeID,
		Keyset:               ks,
		AllowedDownloadSizes: cfg.Limits.AllowedDownloadSizes,
		AllowedTools:         []string{"ping", "mtr", "traceroute", "nexttrace"},
		IPv4Prefix:           cfg.Limits.TokenIPv4Prefix,
		IPv6Prefix:           cfg.Limits.TokenIPv6Prefix,
		NonceCache:           token.NewNonceCache(token.DefaultNonceCacheCapacity, token.DefaultNonceCacheTTL),
	})
	public := server.NewPublicHandler(server.PublicOptions{
		NodeID:              cfg.NodeID,
		Domain:              cfg.Domain,
		Features:            enabledFeatures(cfg.Features),
		HasIPv4:             cfg.PublicIPv4 != "",
		HasIPv6:             cfg.PublicIPv6 != "",
		PublicIPv4:          cfg.PublicIPv4,
		PublicIPv6:          cfg.PublicIPv6,
		PublicIPv4Provider:  publicIPs.IPv4,
		PublicIPv6Provider:  publicIPs.IPv6,
		Verifier:            verifier,
		DownloadReporter:    newDownloadReporter(cfg.Controller, cfg.NodeToken, cfg.NodeID),
		AllowedOrigin:       cfg.FrontendOrigin,
		DownloadConcurrency: cfg.Limits.DownloadConcurrency,
		DownloadBudget: download.NewBudget(download.BudgetLimits{
			Window:              downloadTokenWindow,
			MaxRequestsPerToken: cfg.Limits.DownloadMaxRequestsPerToken,
			MaxBytesMultiplier:  int64(cfg.Limits.DownloadMaxBytesMultiplier),
		}),
		JobConcurrencyPerIP: cfg.Limits.JobConcurrencyPerIP,
		JobTimeoutSec:       cfg.Limits.JobTimeoutSec,
		JobMaxOutputBytes:   int64(cfg.Limits.JobMaxOutputBytes),
		GuardPrivateIP:      cfg.Limits.GuardPrivateIP,
		JobTools:            cfg.Tools,
	})
	mux := http.NewServeMux()
	mux.Handle("/_lg/control/", handler)
	mux.Handle("/", public)

	logCfg := cfg
	logCfg.EnrollToken = ""
	logCfg.InitToken = ""
	logCfg.InitString = ""
	logCfg.NodeToken = ""
	encoded, _ := json.MarshalIndent(logCfg, "", "  ")
	logging.Infof("HLG agent %s serving on %s with config %s", runtime.Version, cfg.Bind, string(encoded))
	// Prefer a cached managed certificate so a restart does not re-open a
	// self-signed window; otherwise fall back to (or generate) a self-signed
	// pair. The controller is still authoritative: sync re-applies its newest
	// bundle and records the source.
	if managed, expiry := store.HasManagedCertificate(); managed {
		logging.Infof("serving cached managed certificate expires_at=%s", expiry.UTC().Format(time.RFC3339))
	} else if _, _, err := store.EnsureSelfSigned(cfg.Domain); err != nil {
		logging.Fatalf("%v", err)
	}
	certPath := filepath.Join(cfg.DataDir, certstore.CertFile)
	keyPath := filepath.Join(cfg.DataDir, certstore.KeyFile)
	if cfg.Controller != "" && cfg.NodeToken != "" {
		go startControllerSync(context.Background(), syncRunner)
	}
	srv := &http.Server{
		Addr:              cfg.Bind,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		IdleTimeout:       60 * time.Second,
		TLSConfig: &tls.Config{
			MinVersion:     tls.VersionTLS12,
			GetCertificate: dynamicCertificate(certPath, keyPath),
		},
	}
	logging.Fatalf("%v", srv.ListenAndServeTLS("", ""))
}

type controllerDownloadReporter struct {
	controller string
	nodeToken  string
	nodeID     string
	client     *http.Client
}

func newDownloadReporter(controller, nodeToken, nodeID string) server.DownloadReporter {
	if controller == "" || nodeToken == "" || nodeID == "" {
		return nil
	}
	return controllerDownloadReporter{
		controller: strings.TrimRight(controller, "/"),
		nodeToken:  nodeToken,
		nodeID:     nodeID,
		client:     &http.Client{Timeout: 2 * time.Second},
	}
}

func (r controllerDownloadReporter) ReportDownload(ctx context.Context, report server.DownloadReport) error {
	body, err := json.Marshal(map[string]string{
		"type":    "download_used",
		"link_id": report.LinkID,
		"size":    report.Size,
	})
	if err != nil {
		return err
	}
	endpoint := r.controller + "/_lg/control/sync?node=" + url.QueryEscape(r.nodeID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("authorization", "Bearer "+r.nodeToken)
	req.Header.Set("content-type", "application/json")
	resp, err := r.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("download usage report failed: %s", resp.Status)
	}
	return nil
}

func adminKeysFromBundle(bundle *config.SignedBundle) map[string]ed25519.PublicKey {
	keys := map[string]ed25519.PublicKey{}
	if bundle == nil {
		return keys
	}
	for _, item := range bundle.Keyset {
		if item.Use != "admin_verify" || item.Alg != "Ed25519" {
			continue
		}
		raw, err := base64.RawURLEncoding.DecodeString(item.PublicKey)
		if err == nil && len(raw) == ed25519.PublicKeySize {
			keys[item.KID] = ed25519.PublicKey(raw)
		}
	}
	return keys
}

func storeBootstrapState(client *enroll.Client, bootstrap enroll.BootstrapResponse) error {
	if err := client.StoreNodeToken(bootstrap.NodeToken); err != nil {
		return fmt.Errorf("store node token: %w", err)
	}
	if err := client.StoreConfig(bootstrap.Config); err != nil {
		return fmt.Errorf("store bootstrap config: %w", err)
	}
	return nil
}

// syncControllerState pulls config and, when a bundle is present, the latest
// certificate bundle. It returns the (possibly updated) active bundle. It is
// driven both by the periodic loop and, on demand, by controller-triggered
// reload requests.
func syncControllerState(ctx context.Context, cfg config.Config, activeBundle *config.SignedBundle, store certstore.Store, publicIPs *publicIPState) (*config.SignedBundle, error) {
	publicIPs.applyOverrides(&cfg)
	refreshPublicIPs(ctx, &cfg, publicIPs)
	// Keep the self-signed fallback fresh only while it is actually the serving
	// certificate; never clobber a managed pair. Best-effort: a failure here is
	// not a controller-sync failure.
	if source, _ := store.ReadSource(); source != certstore.CertSourceManaged {
		if _, _, err := store.EnsureSelfSigned(cfg.Domain); err != nil {
			logging.Warnf("self-signed certificate check failed: %v", err)
		}
	}
	if cfg.NodeID == "" && activeBundle != nil {
		cfg.NodeID = activeBundle.NodeID
	}
	client := enroll.NewClient(cfg)
	// syncErr accumulates the first genuine failure so the controller-triggered
	// reload can report 502 and retry, while the node keeps serving its cached
	// bundle either way.
	var syncErr error
	if pulled, err := client.PullConfig(ctx); err == nil {
		verifyNodeID := cfg.NodeID
		if verifyNodeID == "" {
			verifyNodeID = pulled.NodeID
		}
		if err := config.VerifySignedBundle(pulled, verifyNodeID, time.Now()); err != nil {
			logging.Warnf("pulled config verification failed: %v", err)
			syncErr = err
		} else {
			if cfg.NodeID == "" {
				cfg.NodeID = pulled.NodeID
			}
			if pulled.PublicIPv4 != "" {
				cfg.PublicIPv4 = pulled.PublicIPv4
			}
			if pulled.PublicIPv6 != "" {
				cfg.PublicIPv6 = pulled.PublicIPv6
			}
			publicIPs.set(cfg.PublicIPv4, cfg.PublicIPv6)
			logging.Infof("synced config node_id=%s version=%d", pulled.NodeID, pulled.Version)
			activeBundle = &pulled
		}
	} else {
		logging.Warnf("config sync failed: %v", err)
		syncErr = err
	}
	if activeBundle == nil {
		return activeBundle, syncErr
	}
	bundle, certErr := pullCertificateBundle(ctx, cfg, activeBundle, store, client)
	if certErr != nil && syncErr == nil {
		syncErr = certErr
	}
	return bundle, syncErr
}

func pullCertificateBundle(ctx context.Context, cfg config.Config, activeBundle *config.SignedBundle, store certstore.Store, client *enroll.Client) (*config.SignedBundle, error) {
	certBundle, err := client.PullCertBundle(ctx)
	if err != nil {
		// No pending bundle is the healthy steady state, not a failure.
		if errors.Is(err, enroll.ErrCertBundleNotFound) {
			return activeBundle, nil
		}
		logging.Warnf("certificate sync failed: %v", err)
		return activeBundle, err
	}
	if err := config.VerifySignedCertificateBundle(certBundle, *activeBundle, cfg.NodeID, time.Now()); err != nil {
		logging.Warnf("certificate bundle verification failed: %v", err)
		return activeBundle, err
	}
	if _, _, err := store.ApplyBundle(certBundle); err != nil {
		logging.Warnf("certificate apply failed: %v", err)
		// Tell the controller the bundle did not land so it stays pending and
		// is re-delivered on the next poll.
		if ackErr := client.AckCertBundle(ctx, certBundle.NodeBundleID, err); ackErr != nil {
			logging.Warnf("certificate ack failed: %v", ackErr)
		}
		return activeBundle, err
	}
	// Acknowledge before anything else can fail, so the controller records the
	// bundle as applied on this node.
	if ackErr := client.AckCertBundle(ctx, certBundle.NodeBundleID, nil); ackErr != nil {
		logging.Warnf("certificate ack failed: %v", ackErr)
	}
	logging.Infof("synced certificate bundle node_id=%s version=%d expires_at=%d", certBundle.NodeID, certBundle.Version, certBundle.CertExpiresAt)
	return activeBundle, nil
}

// syncInterval chooses the periodic pull cadence from the serving certificate
// state: a node without a valid managed certificate retries quickly, while a
// healthy node polls rarely (mainly as an uptime report) because config and
// certificate changes are pushed via controller-triggered reloads.
func syncInterval(cfg config.Config, store certstore.Store) time.Duration {
	if managed, _ := store.HasManagedCertificate(); managed {
		interval := time.Duration(cfg.SyncIntervalHealthySeconds) * time.Second
		if interval <= 0 {
			interval = 45 * time.Minute
		}
		return interval
	}
	return 5 * time.Minute
}

// syncRunner owns the controller-sync state so both the periodic loop and
// controller-triggered reload requests can drive it.
type syncRunner struct {
	mu           sync.Mutex
	cfg          config.Config
	activeBundle *config.SignedBundle
	store        certstore.Store
	publicIPs    *publicIPState
}

func newSyncRunner(cfg config.Config, activeBundle *config.SignedBundle, store certstore.Store, publicIPs *publicIPState) *syncRunner {
	return &syncRunner{cfg: cfg, activeBundle: activeBundle, store: store, publicIPs: publicIPs}
}

// run performs one sync and records the outcome. It locks so a reload request
// and the periodic loop never pull concurrently. The returned error lets the
// controller's /_lg/control/cert/reload trigger see a failure (502) instead of
// a blanket 200, so it can count and retry.
func (s *syncRunner) run(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	bundle, err := syncControllerState(ctx, s.cfg, s.activeBundle, s.store, s.publicIPs)
	s.activeBundle = bundle
	return err
}

func startControllerSync(ctx context.Context, runner *syncRunner) {
	for {
		interval := syncInterval(runner.cfg, runner.store)
		timer := time.NewTimer(interval)
		select {
		case <-timer.C:
			syncCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
			_ = runner.run(syncCtx)
			cancel()
		case <-ctx.Done():
			timer.Stop()
			return
		}
	}
}

func recoverSignedBundle(ctx context.Context, cfg config.Config) *config.SignedBundle {
	client := enroll.NewClient(cfg)
	if cfg.NodeToken != "" {
		if pulled, err := client.PullConfig(ctx); err == nil {
			return &pulled
		}
	}
	if cfg.InitToken != "" {
		if resp, err := client.BootstrapOnce(ctx); err == nil {
			return &resp.Config
		}
	}
	if cfg.EnrollToken != "" {
		for attempt := 0; attempt < 3; attempt++ {
			if resp, err := client.EnrollOnce(ctx); err == nil && resp.Status == "active" {
				return &resp.Config
			}
			time.Sleep(enroll.Backoff(attempt))
		}
	}
	if stored, err := enroll.LoadStoredConfig(cfg.DataDir); err == nil {
		return &stored
	}
	return nil
}

func dynamicCertificate(certPath, keyPath string) func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	var mu sync.Mutex
	var cached *tls.Certificate
	var lastCertMod time.Time
	var lastKeyMod time.Time
	haveMod := false
	return func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
		mu.Lock()
		defer mu.Unlock()
		certInfo, certErr := os.Stat(certPath)
		keyInfo, keyErr := os.Stat(keyPath)
		if certErr == nil && keyErr == nil {
			certMod, keyMod := certInfo.ModTime(), keyInfo.ModTime()
			if !haveMod || !certMod.Equal(lastCertMod) || !keyMod.Equal(lastKeyMod) {
				if cert, err := tls.LoadX509KeyPair(certPath, keyPath); err == nil {
					cached = &cert
					lastCertMod = certMod
					lastKeyMod = keyMod
					haveMod = true
				} else if cached == nil {
					// Nothing usable cached yet: surface the load error so the
					// handshake fails loudly instead of with a garbage cert.
					return nil, err
				} else {
					logging.Warnf("tls keypair reload failed, serving cached certificate: %v", err)
				}
			}
		} else if cached == nil {
			if certErr != nil {
				return nil, certErr
			}
			return nil, keyErr
		} else {
			if certErr != nil {
				logging.Warnf("tls certificate stat failed, serving cached certificate: %v", certErr)
			} else {
				logging.Warnf("tls private key stat failed, serving cached certificate: %v", keyErr)
			}
		}
		return cached, nil
	}
}

func enabledFeatures(features map[string]bool) []string {
	out := make([]string, 0, len(runtime.Capabilities))
	for _, feature := range runtime.Capabilities {
		if features[feature] {
			out = append(out, feature)
		}
	}
	return out
}

// bootstrapUntilReady acquires a verified signed config bundle without binding
// any port. It is the "no bundle" startup state: the node is unreachable from
// the controller until it has a valid certificate, so the only recovery path is
// this outbound retry loop. It returns only once a bundle verifies, so the
// caller can proceed to normal startup; the process stays alive (and visible in
// logs) meanwhile.
func bootstrapUntilReady(ctx context.Context, cfg config.Config, publicIPs *publicIPState) *config.SignedBundle {
	logging.Warnf("no config bundle available; entering bootstrap retry loop (port not bound) node_id=%q", cfg.NodeID)
	for attempt := 0; ; attempt++ {
		refreshPublicIPs(ctx, &cfg, publicIPs)
		client := enroll.NewClient(cfg)
		if pulled, err := client.PullConfig(ctx); err == nil {
			verifyNodeID := cfg.NodeID
			if verifyNodeID == "" {
				verifyNodeID = pulled.NodeID
			}
			if err := config.VerifySignedBundle(pulled, verifyNodeID, time.Now()); err == nil {
				logging.Infof("bootstrap: pulled verified config node_id=%s", pulled.NodeID)
				return &pulled
			}
			logging.Warnf("bootstrap: pulled config failed verification")
		}
		if storedToken, err := enroll.LoadNodeToken(cfg.DataDir); err == nil && cfg.NodeToken == "" {
			cfg.NodeToken = storedToken
		}
		if cfg.NodeToken != "" {
			if pulled, err := client.PullConfig(ctx); err == nil {
				verifyNodeID := cfg.NodeID
				if verifyNodeID == "" {
					verifyNodeID = pulled.NodeID
				}
				if err := config.VerifySignedBundle(pulled, verifyNodeID, time.Now()); err == nil {
					logging.Infof("bootstrap: pulled verified config node_id=%s", pulled.NodeID)
					return &pulled
				}
			}
		}
		if cfg.InitToken != "" {
			if resp, err := client.BootstrapOnce(ctx); err == nil && resp.NodeToken != "" {
				logging.Infof("bootstrap: init exchange complete node_id=%s", resp.NodeID)
				cfg.NodeID = resp.NodeID
				cfg.NodeToken = resp.NodeToken
				return &resp.Config
			}
		}
		if cfg.EnrollToken != "" {
			if resp, err := client.EnrollOnce(ctx); err == nil && resp.Status == "active" {
				logging.Infof("bootstrap: enrolled node_id=%s", resp.NodeID)
				cfg.NodeID = resp.NodeID
				return &resp.Config
			}
		}
		time.Sleep(enroll.Backoff(attempt))
	}
}

func discoverConfigFile(explicit string) string {
	if explicit != "" {
		return explicit
	}
	for _, path := range candidateConfigFiles() {
		if _, err := os.Stat(path); err == nil {
			return path
		}
	}
	return ""
}

func discoverBootstrapInput() (config.Config, string, error) {
	for _, path := range candidateBootstrapFiles() {
		body, err := os.ReadFile(path)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			return config.Config{}, "", err
		}
		var cfg config.Config
		if err := json.Unmarshal(body, &cfg); err != nil {
			return config.Config{}, "", fmt.Errorf("parse bootstrap input %s: %w", path, err)
		}
		return cfg, path, nil
	}
	return config.Config{}, "", nil
}

func applyBootstrapInput(dst *config.Config, src config.Config) {
	if dst == nil {
		return
	}
	if dst.Controller == "" && src.Controller != "" {
		dst.Controller = src.Controller
	}
	if dst.InitToken == "" && src.InitToken != "" {
		dst.InitToken = src.InitToken
	}
	if dst.NodeID == "" && src.NodeID != "" {
		dst.NodeID = src.NodeID
	}
	if dst.DataDir == "" && src.DataDir != "" {
		dst.DataDir = src.DataDir
	}
	if dst.Bind == "" && src.Bind != "" {
		dst.Bind = src.Bind
	}
	if dst.FrontendOrigin == "" && src.FrontendOrigin != "" {
		dst.FrontendOrigin = src.FrontendOrigin
	}
}

// resolveInitInputs turns a bare init key or a compact init string
// ("[https://]host[:port]/lginit_<key>") plus an optional controller into a
// concrete (controller, key) pair. An explicit controller always wins.
func resolveInitInputs(controller, initString, initToken string) (string, string, error) {
	if strings.TrimSpace(initString) != "" {
		payload, err := initstring.Parse(initString)
		if err != nil {
			return "", "", err
		}
		if strings.TrimSpace(controller) == "" {
			controller = payload.Controller
		}
		return controller, payload.Key, nil
	}
	parsedController, key, err := parseKeyOrInitString(initToken)
	if err != nil {
		return "", "", err
	}
	if strings.TrimSpace(controller) == "" {
		controller = parsedController
	}
	return controller, key, nil
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value = strings.TrimSpace(value); value != "" {
			return value
		}
	}
	return ""
}

func selectCommand(args []string) (string, []string) {
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		return args[0], args[1:]
	}
	return "help", args
}

func controllerFromConfigFile(configFile string) string {
	path := discoverConfigFile(configFile)
	if path == "" {
		return ""
	}
	cfg, err := config.Load(config.LoadOptions{File: path})
	if err != nil {
		return ""
	}
	return cfg.Controller
}

// resolveRunInitInputs consumes init credentials only when `run -i` is
// explicit. Plain `run -k ...` must not enroll or bootstrap a node.
func resolveRunInitInputs(enabled bool, controller, initString, initToken string) (string, string, error) {
	if !enabled {
		return "", "", nil
	}
	return resolveInitInputs(controller, initString, initToken)
}

// prepareRunBootstrap keeps `run` config-only while allowing `run -i` to
// initialize a fresh mounted data dir without performing a host installation.
// A stored token plus a node ID (in agent.json or the signed bundle) means the
// one-time key must be ignored on every subsequent container start.
func prepareRunBootstrap(cfg *config.Config, enabled bool, bootstrap config.Config) (bool, error) {
	if !enabled {
		cfg.InitToken = ""
		cfg.InitString = ""
		applyBootstrapInput(cfg, bootstrap)
		applyInitString(cfg)
		return false, nil
	}

	hasToken := strings.TrimSpace(cfg.NodeToken) != ""
	if !hasToken {
		storedToken, err := enroll.LoadNodeToken(cfg.DataDir)
		hasToken = err == nil && strings.TrimSpace(storedToken) != ""
	}
	hasNodeID := strings.TrimSpace(cfg.NodeID) != ""
	if !hasNodeID {
		stored, err := enroll.LoadStoredConfig(cfg.DataDir)
		hasNodeID = err == nil && stored.NodeID != ""
	}
	if hasToken && hasNodeID {
		if cfg.Controller == "" {
			controller, _, err := resolveInitInputs("", cfg.InitString, cfg.InitToken)
			if err != nil {
				return false, err
			}
			cfg.Controller = controller
		}
		cfg.InitToken = ""
		cfg.InitString = ""
		if cfg.Controller == "" {
			return false, fmt.Errorf("stored node identity requires a controller URL in agent.json or LG_CONTROLLER")
		}
		return false, nil
	}

	applyBootstrapInput(cfg, bootstrap)
	controller, key, err := resolveRunInitInputs(true, cfg.Controller, cfg.InitString, cfg.InitToken)
	if err != nil {
		return false, err
	}
	if controller == "" || key == "" {
		return false, fmt.Errorf("run -i requires LG_INIT_STRING or a controller URL with --key when no stored node identity exists")
	}
	cfg.Controller = controller
	cfg.InitToken = key
	return true, nil
}

func persistRunBootstrapConfig(path string, cfg config.Config) error {
	if path == "" {
		return fmt.Errorf("run -i has no config path")
	}
	record := readRawConfig(path)
	if record == nil {
		record = map[string]any{}
	}
	record["controller"] = cfg.Controller
	record["node_id"] = cfg.NodeID
	record["data_dir"] = cfg.DataDir
	record["bind"] = cfg.Bind
	delete(record, "init_token")
	delete(record, "init_string")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return writeJSONFile(path, record)
}

// parseKeyOrInitString accepts a bare init key or the compact init string form
// and returns the controller (empty for a bare key) and the key.
func parseKeyOrInitString(value string) (string, string, error) {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return "", "", nil
	}
	if strings.Contains(trimmed, "/") {
		payload, err := initstring.Parse(trimmed)
		if err != nil {
			return "", "", err
		}
		return payload.Controller, payload.Key, nil
	}
	if !initstring.LooksLikeInitKey(trimmed) {
		return "", "", fmt.Errorf("invalid init key: expected lginit_<base64url> or [https://]host[:port]/lginit_<key>")
	}
	return "", trimmed, nil
}

// applyInitString fills the controller and one-time init key from a one-line
// init string or a key that carries one (LG_INIT_STRING / --init-string, or
// LG_INIT_TOKEN / --key), when they are not otherwise configured. Explicit
// flags, env and agent.json win; the string never carries the node domain or id
// (the signed config bundle is authoritative for those).
func applyInitString(cfg *config.Config) {
	if cfg == nil {
		return
	}
	if strings.TrimSpace(cfg.InitString) == "" && strings.TrimSpace(cfg.InitToken) == "" {
		return
	}
	controller, key, err := resolveInitInputs(cfg.Controller, cfg.InitString, cfg.InitToken)
	if err != nil {
		log.Fatalf("%v", err)
	}
	cfg.Controller = controller
	cfg.InitToken = key
	if key != "" {
		log.Printf("init key: controller=%s key=%s", controller, maskSecret(key))
	}
}

// maskSecret logs a short irreversible fingerprint without exposing any key bytes.
func maskSecret(value string) string {
	fingerprint := sha256.Sum256([]byte(value))
	return fmt.Sprintf("sha256:%x", fingerprint[:4])
}

func candidateConfigFiles() []string {
	paths := make([]string, 0, 4)
	if exe, err := os.Executable(); err == nil {
		paths = append(paths, filepath.Join(filepath.Dir(exe), "agent.json"))
	}
	if cwd, err := os.Getwd(); err == nil {
		paths = append(paths, filepath.Join(cwd, "agent.json"))
	}
	paths = append(paths, filepath.Join("/opt/looking-glass", "agent.json"))
	return uniqueStrings(paths)
}

func candidateBootstrapFiles() []string {
	paths := make([]string, 0, 4)
	if exe, err := os.Executable(); err == nil {
		paths = append(paths, filepath.Join(filepath.Dir(exe), "bootstrap-input.json"))
	}
	if cwd, err := os.Getwd(); err == nil {
		paths = append(paths, filepath.Join(cwd, "bootstrap-input.json"))
	}
	paths = append(paths, filepath.Join("/opt/looking-glass", "bootstrap-input.json"))
	return uniqueStrings(paths)
}

func uniqueStrings(values []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(values))
	for _, value := range values {
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}

func runInstall(configFile, installDir, dataDir, serviceMode, serviceUser, binaryName, serviceName, controller, initToken, nodeID, bind, frontendOrigin, logLevel, logFile string, installDepsYes bool) error {
	binaryName = normalizeUnitName(binaryName, "hlg-agent")
	serviceName = normalizeUnitName(serviceName, "hlg-agent")
	resolvedMode, err := normalizeServiceMode(serviceMode, false)
	if err != nil {
		return err
	}
	seed, err := installSeedConfig(configFile)
	if err != nil {
		return err
	}
	if controller != "" {
		seed.Controller = controller
	}
	if initToken != "" {
		seed.InitToken = initToken
	}
	if nodeID != "" {
		seed.NodeID = nodeID
	}
	if bind != "" {
		seed.Bind = bind
	}
	// Always persist a concrete listener address: a bare init would otherwise
	// write no bind and the agent's compiled default would silently apply. The
	// controller dials <domain>:443, so that is the default.
	if strings.TrimSpace(seed.Bind) == "" {
		seed.Bind = config.DefaultBind
	}
	if !isValidListenAddr(seed.Bind) {
		return fmt.Errorf("invalid --bind %q: expected [host]:port", seed.Bind)
	}
	if frontendOrigin != "" {
		seed.FrontendOrigin = frontendOrigin
	}
	if logLevel != "" {
		seed.LogLevel = logLevel
	}
	if logFile != "" {
		seed.LogFile = logFile
	}
	if installDir == "" {
		installDir = "/opt/looking-glass"
	}
	if dataDir == "" {
		dataDir = filepath.Join(installDir, "data")
	}
	seed.DataDir = dataDir
	if serviceUser == "" {
		serviceUser = "root"
	}
	if err := validateServiceUser(serviceUser); err != nil {
		return err
	}

	log.Printf("install: install_dir=%s data_dir=%s service=%s service_name=%s binary=%s user=%s", installDir, dataDir, resolvedMode, serviceName, binaryName, serviceUser)

	// Warn/abort early if the listen address is already taken, so a silent
	// bind failure later does not masquerade as an unreachable node.
	if err := checkInstallPort(seed.Bind, installDepsYes); err != nil {
		return err
	}

	// If the binary was invoked from a path that is not the target install dir,
	// copy it into place first. This lets the admin run a downloaded binary from
	// /tmp (or anywhere) and still end up with a self-contained install; the
	// installer script normally places the binary first, in which case the
	// running path equals the target and nothing is copied.
	runPath := filepath.Join(installDir, binaryName)
	if exe := executablePath(); exe != "" && exe != runPath {
		if err := os.MkdirAll(installDir, 0o755); err != nil {
			return err
		}
		src, err := os.Open(exe)
		if err != nil {
			return fmt.Errorf("copy bootstrap binary from %s: %w", exe, err)
		}
		defer src.Close()
		if err := os.Remove(runPath); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("remove stale binary at %s: %w", runPath, err)
		}
		dst, err := os.OpenFile(runPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
		if err != nil {
			return fmt.Errorf("create installed binary at %s: %w", runPath, err)
		}
		if _, err := io.Copy(dst, src); err != nil {
			dst.Close()
			return fmt.Errorf("copy binary to %s: %w", runPath, err)
		}
		if err := dst.Close(); err != nil {
			return fmt.Errorf("close installed binary: %w", err)
		}
		log.Printf("install: copied bootstrap binary to %s", runPath)
	}

	if err := os.MkdirAll(installDir, 0o755); err != nil {
		return err
	}
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return err
	}
	if _, err := os.Stat(runPath); err != nil {
		return fmt.Errorf("agent binary not found at %s", runPath)
	}
	// Runtime tools are installed by the `init` flow (see installDepsInteractive),
	// which prompts per tool unless --install-deps-yes is passed.
	runtimeCfg := map[string]any{
		"controller":      seed.Controller,
		"node_id":         seed.NodeID,
		"data_dir":        dataDir,
		"bind":            seed.Bind,
		"frontend_origin": seed.FrontendOrigin,
		// Record the install identity so maintenance subcommands act on the same
		// names/paths instead of falling back to flag defaults.
		"install_dir":  installDir,
		"binary_path":  runPath,
		"binary_name":  binaryName,
		"service_name": serviceName,
		"service_mode": resolvedMode,
		"user":         serviceUser,
	}
	if seed.LogLevel != "" {
		runtimeCfg["log_level"] = seed.LogLevel
	}
	if seed.LogFile != "" {
		runtimeCfg["log_file"] = seed.LogFile
	}
	bootstrapPath := filepath.Join(installDir, "bootstrap-input.json")
	if seed.InitToken != "" {
		if err := writeJSONFile(bootstrapPath, map[string]any{
			"controller":      seed.Controller,
			"init_token":      seed.InitToken,
			"node_id":         seed.NodeID,
			"data_dir":        dataDir,
			"bind":            seed.Bind,
			"frontend_origin": seed.FrontendOrigin,
		}); err != nil {
			return err
		}
		log.Printf("install: wrote bootstrap input %s", bootstrapPath)
	} else {
		_ = os.Remove(bootstrapPath)
	}
	// Install runtime dependencies last and interactively: they need network and
	// (for the OS packages) root, and the operator should confirm each one.
	if err := installDepsInteractive(context.Background(), seed.Controller, dataDir, installDepsYes); err != nil {
		return err
	}
	// Record where each dependency landed so the runtime invokes a known binary
	// instead of searching PATH on every call. Written after install so the map
	// reflects what is actually present and any built-in/path choices.
	runtimeCfg["tools"] = applyDependencyChoices(deps.RecordedPaths(dataDir))
	if err := writeJSONFile(filepath.Join(installDir, "agent.json"), runtimeCfg); err != nil {
		return err
	}
	// agent.json is written with mode 0600. Assign ownership only after writing
	// it, or a service running as an existing non-root user cannot read it.
	if err := ensureInstallOwnership(installDir, dataDir, serviceUser); err != nil {
		return err
	}
	log.Printf("install: wrote runtime config %s", filepath.Join(installDir, "agent.json"))
	switch resolvedMode {
	case "systemd":
		return installSystemdService(installDir, dataDir, serviceUser, binaryName, serviceName)
	case "init.d":
		return installInitDService(installDir, dataDir, serviceUser, binaryName, serviceName)
	case "none":
		log.Printf("install: service installation skipped")
		return nil
	default:
		return fmt.Errorf("unsupported service mode: %s", resolvedMode)
	}
}

func runUninstall(identity installIdentity) error {
	installDir := identity.InstallDir
	binaryName := identity.BinaryName
	serviceName := identity.ServiceName
	dataDir := identity.DataDir
	// Never destroy an install we could not identify: without an agent.json
	// (the recorded layout) the defaults would point at a possibly-unrelated
	// installation. Refuse instead of guessing, unless the operator named the
	// target explicitly with --path/--name.
	if !identity.ExplicitTarget && strings.TrimSpace(identity.ConfigFile) == "" {
		return fmt.Errorf("refusing to uninstall: no agent.json found for %s; pass --path/--name to confirm the target, or run the installed binary directly", installDir)
	}
	resolvedMode, err := normalizeServiceMode(identity.ServiceMode, true)
	if err != nil {
		return err
	}
	// Safety rails: never treat "/" (or a relative dir) as an install target —
	// the deletes below would otherwise reach far beyond this install.
	if !filepath.IsAbs(installDir) || filepath.Clean(installDir) == "/" {
		return fmt.Errorf("refusing to uninstall: unsafe install dir %q", installDir)
	}
	if !filepath.IsAbs(dataDir) || filepath.Clean(dataDir) == "/" {
		return fmt.Errorf("refusing to uninstall: unsafe data dir %q", dataDir)
	}
	binaryPath := identity.BinaryPath
	if binaryPath == "" {
		binaryPath = filepath.Join(installDir, binaryName)
	}
	configPath := identity.ConfigFile
	if configPath == "" {
		configPath = filepath.Join(installDir, "agent.json")
	}
	// Final guard against acting on the wrong install: unless the operator
	// explicitly named the target, the resolved binary must be the binary that
	// is running right now. Otherwise a stale default could tear down a
	// different installation's files or service.
	if !identity.ExplicitTarget {
		if exe := executablePath(); exe != "" && exe != binaryPath && fileExists(binaryPath) {
			return fmt.Errorf("uninstall target mismatch: running binary is %s but the resolved target is %s; run the installed binary directly, or pass --install-dir/--binary-name to confirm the target", exe, binaryPath)
		}
	}

	log.Printf("uninstall: install_dir=%s data_dir=%s service=%s service_name=%s binary=%s", installDir, dataDir, resolvedMode, serviceName, binaryName)
	if resolvedMode == "systemd" || resolvedMode == "all" {
		_ = exec.Command("systemctl", "disable", "--now", serviceName+".service").Run()
		_ = os.Remove(filepath.Join(systemdUnitDir, serviceName+".service"))
		_ = exec.Command("systemctl", "daemon-reload").Run()
	}
	if resolvedMode == "init.d" || resolvedMode == "all" {
		_ = exec.Command("rc-service", serviceName, "stop").Run()
		_ = exec.Command("rc-update", "del", serviceName, "default").Run()
		_ = os.Remove(filepath.Join(openrcInitDir, serviceName))
	}
	for _, path := range []string{
		configPath,
		filepath.Join(installDir, "bootstrap-input.json"),
		binaryPath,
		binaryPath + ".bak",
	} {
		_ = os.Remove(path)
	}
	_ = os.RemoveAll(dataDir)
	_ = os.RemoveAll(filepath.Join(installDir, "data"))
	// If the install dir is now empty, remove it too.
	if entries, _ := os.ReadDir(installDir); len(entries) == 0 {
		_ = os.Remove(installDir)
	}
	return nil
}

func installSystemdService(installDir, dataDir, serviceUser, binaryName, serviceName string) error {
	if err := validateServiceUser(serviceUser); err != nil {
		return err
	}
	servicePath := filepath.Join("/etc/systemd/system", serviceName+".service")
	service := fmt.Sprintf(`[Unit]
Description=Looking Glass Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=%s
Group=%s
ExecStart=%s run --config %s
Restart=always
RestartSec=3
AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_RAW CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=%s %s

[Install]
WantedBy=multi-user.target
`, serviceUser, serviceUser, filepath.Join(installDir, binaryName), filepath.Join(installDir, "agent.json"), installDir, dataDir)
	if err := os.WriteFile(servicePath, []byte(service), 0o644); err != nil {
		return err
	}
	if err := runCommand("systemctl", "daemon-reload"); err != nil {
		return err
	}
	if err := runCommand("systemctl", "enable", "--now", serviceName+".service"); err != nil {
		return err
	}
	if err := runCommand("systemctl", "is-active", "--quiet", serviceName+".service"); err != nil {
		return fmt.Errorf("systemd service did not become active: %w", err)
	}
	log.Printf("install: systemd service %s.service enabled and active", serviceName)
	return nil
}

func installInitDService(installDir, dataDir, serviceUser, binaryName, serviceName string) error {
	if err := validateServiceUser(serviceUser); err != nil {
		return err
	}
	servicePath := filepath.Join("/etc/init.d", serviceName)
	script := fmt.Sprintf(`#!/sbin/openrc-run
name="%s"
description="Looking Glass Agent"
command="%s"
command_args="run --config %s"
command_user="%s:%s"
command_background="yes"
pidfile="/run/${name}.pid"
depend() {
	need net
}
`, serviceName, filepath.Join(installDir, binaryName), filepath.Join(installDir, "agent.json"), serviceUser, serviceUser)
	if err := os.WriteFile(servicePath, []byte(script), 0o755); err != nil {
		return err
	}
	if err := runCommand("rc-update", "add", serviceName, "default"); err != nil {
		return err
	}
	if commandExists("rc-service") {
		if err := runCommand("rc-service", serviceName, "restart"); err != nil {
			return err
		}
	}
	log.Printf("install: init.d/OpenRC service %s installed", serviceName)
	return nil
}

const doctorNetworkTimeout = 10 * time.Second

func runSelfCheck(identity installIdentity) error {
	installDir := identity.InstallDir
	dataDir := identity.DataDir
	binaryName := identity.BinaryName
	serviceName := identity.ServiceName
	resolvedMode, err := normalizeServiceMode(identity.ServiceMode, false)
	if err != nil {
		return err
	}
	log.Printf("self-check: install_dir=%s data_dir=%s service=%s service_name=%s binary=%s", installDir, dataDir, resolvedMode, serviceName, binaryName)
	log.Printf("doctor: agent version=%s build=%s", runtime.Version, runtime.BuildID)
	_ = deps.AppendPath(dataDir)

	var problems []string

	// ── 1. Service status ────────────────────────────────────────────────────
	log.Printf("doctor: [1/3] service (%s)", resolvedMode)
	configPath := identity.ConfigFile
	if configPath == "" {
		configPath = filepath.Join(installDir, "agent.json")
	}
	problems = append(problems, checkService(resolvedMode, serviceName)...)

	// Effective tool sources come from agent.json#tools (the same map the
	// runtime uses), so doctor reports what will actually run.
	recordedTools := map[string]string{}
	if record := readRawConfig(configPath); record != nil {
		if raw, ok := record["tools"].(map[string]any); ok {
			for k, v := range raw {
				if s, ok := v.(string); ok {
					recordedTools[k] = s
				}
			}
		}
	}

	checkBinary := identity.BinaryPath
	if checkBinary == "" {
		checkBinary = filepath.Join(installDir, binaryName)
	}
	// Unless the operator explicitly named the target, the checked binary should
	// be the binary performing the check; a mismatch means the identity resolved
	// to a different install than the one running.
	if !identity.ExplicitTarget {
		if exe := executablePath(); exe != "" && exe != checkBinary {
			problems = append(problems, fmt.Sprintf("running binary path %s does not match expected install binary %s", exe, checkBinary))
		}
	}
	if _, err := os.Stat(checkBinary); err == nil {
		log.Printf("doctor: binary present at %s", checkBinary)
		if sum, hashErr := sha256File(checkBinary); hashErr == nil {
			log.Printf("doctor: installed agent sha256=%s", sum)
		} else {
			problems = append(problems, fmt.Sprintf("cannot hash agent binary at %s: %v", checkBinary, hashErr))
		}
	} else {
		problems = append(problems, fmt.Sprintf("agent binary missing at %s", checkBinary))
	}
	if executable := executablePath(); executable != "" {
		if sum, hashErr := sha256File(executable); hashErr == nil {
			log.Printf("doctor: running agent sha256=%s", sum)
		} else {
			log.Printf("doctor: running agent hash unavailable: %v", hashErr)
		}
	}
	for _, tool := range deps.All() {
		ok, detail := deps.Effective(recordedTools, dataDir, tool.Name)
		if !ok {
			problems = append(problems, fmt.Sprintf("missing dependency: %s (%s)", tool.Name, detail))
			continue
		}
		log.Printf("doctor: dependency ok: %s (%s)", tool.Name, detail)
		problems = append(problems, checkDoctorDependency(tool, detail, dataDir, checkControllerURL(configPath))...)
	}

	checkCfg := config.Config{}
	if configPath != "" {
		loaded, loadErr := config.Load(config.LoadOptions{File: configPath, Flags: map[string]string{"data-dir": dataDir}})
		if loadErr != nil {
			problems = append(problems, fmt.Sprintf("runtime config invalid: %s (%v)", configPath, loadErr))
		} else {
			checkCfg = loaded
			log.Printf("doctor: runtime config ok: %s", configPath)
		}
	} else {
		log.Printf("doctor: runtime config file not found; relying on stored signed config if present")
	}

	bootstrapPath := filepath.Join(installDir, "bootstrap-input.json")
	if _, err := os.Stat(bootstrapPath); err == nil {
		body, readErr := os.ReadFile(bootstrapPath)
		if readErr != nil {
			problems = append(problems, fmt.Sprintf("bootstrap input unreadable: %s (%v)", bootstrapPath, readErr))
		} else {
			var bootstrapCfg config.Config
			if unmarshalErr := json.Unmarshal(body, &bootstrapCfg); unmarshalErr != nil {
				problems = append(problems, fmt.Sprintf("bootstrap input invalid: %s (%v)", bootstrapPath, unmarshalErr))
			} else {
				log.Printf("doctor: bootstrap input present: %s", bootstrapPath)
				if checkCfg.Controller == "" {
					checkCfg.Controller = bootstrapCfg.Controller
				}
			}
		}
	}

	if stored, err := enroll.LoadStoredConfig(dataDir); err == nil {
		log.Printf("doctor: stored signed config present in %s", dataDir)
		if checkCfg.NodeID == "" {
			checkCfg.NodeID = stored.NodeID
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		problems = append(problems, fmt.Sprintf("stored signed config unreadable: %v", err))
	}
	if _, err := enroll.LoadNodeToken(dataDir); err == nil {
		log.Printf("doctor: node token present in %s", dataDir)
	} else if !errors.Is(err, os.ErrNotExist) {
		problems = append(problems, fmt.Sprintf("stored node token unreadable: %v", err))
	}
	if checkCfg.Controller != "" {
		checkAgentRelease(identity, checkCfg, &problems)
	}
	if !fileExists(filepath.Join(dataDir, "config.json")) && !fileExists(bootstrapPath) {
		problems = append(problems, "neither stored signed config nor bootstrap input is present")
	}

	// ── 2. TLS status ────────────────────────────────────────────────────────
	log.Printf("doctor: [2/3] tls")
	// A fresh install has not served yet (no stored signed config), so a missing
	// certificate is expected then; once enrolled, a missing/unloadable pairing
	// is a real problem.
	storedConfig := fileExists(filepath.Join(dataDir, "config.json"))
	problems = append(problems, checkTLS(dataDir, checkCfg.Bind, checkCfg.Domain, storedConfig)...)

	// ── 3. Controller connectivity ───────────────────────────────────────────
	log.Printf("doctor: [3/3] controller")
	problems = append(problems, checkController(checkCfg, dataDir)...)

	if len(problems) > 0 {
		return fmt.Errorf("self-check failed:\n - %s", strings.Join(problems, "\n - "))
	}
	log.Printf("self-check: ok")
	return nil
}

func checkDoctorDependency(tool deps.Tool, source, dataDir, controller string) []string {
	if source == deps.BuiltinMarker {
		return nil
	}
	var problems []string
	if sum, err := sha256File(source); err == nil {
		log.Printf("doctor: %s sha256=%s", tool.Name, sum)
	} else {
		problems = append(problems, fmt.Sprintf("cannot hash dependency %s at %s: %v", tool.Name, source, err))
	}
	// A stale managed copy must not make doctor fail when another source is
	// selected. The selected binary is the only one relevant to this check.
	if filepath.Clean(source) != filepath.Clean(deps.BinaryPath(dataDir, tool.Name)) {
		return problems
	}
	if expected, actual, managed, hashErr := deps.CheckManagedSHA512(dataDir, tool.Name); managed {
		if hashErr != nil {
			problems = append(problems, fmt.Sprintf("managed dependency %s hash check failed: %v", tool.Name, hashErr))
		} else if !strings.EqualFold(expected, actual) {
			problems = append(problems, fmt.Sprintf("managed dependency %s sha512 mismatch (run `hlg-agent deps upgrade`)", tool.Name))
		} else {
			log.Printf("doctor: %s matches its recorded sha512", tool.Name)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), doctorNetworkTimeout)
	defer cancel()
	if known, matches := deps.UpdateCheck(ctx, controller, dataDir, tool); known && !matches {
		problems = append(problems, fmt.Sprintf("%s does not match the controller's published checksum (run `hlg-agent deps upgrade`)", tool.Name))
	} else if known {
		log.Printf("doctor: %s matches the controller checksum", tool.Name)
	}
	return problems
}

func checkAgentRelease(identity installIdentity, cfg config.Config, problems *[]string) {
	nodeToken := strings.TrimSpace(cfg.NodeToken)
	if nodeToken == "" {
		if stored, err := enroll.LoadNodeToken(identity.DataDir); err == nil {
			nodeToken = stored
		}
	}
	nodeID := strings.TrimSpace(cfg.NodeID)
	if nodeID == "" {
		if stored, err := enroll.LoadStoredConfig(identity.DataDir); err == nil {
			nodeID = stored.NodeID
		}
	}
	if cfg.Controller == "" || nodeToken == "" || nodeID == "" {
		log.Printf("doctor: latest agent release check unavailable (controller/node credentials not installed)")
		return
	}
	arch := runtimeArch()
	if arch == "" {
		log.Printf("doctor: latest agent release check unavailable (unsupported architecture %s)", goruntime.GOARCH)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), doctorNetworkTimeout)
	defer cancel()
	result, err := agentupdate.Run(ctx, agentupdate.Options{
		Controller:     cfg.Controller,
		NodeToken:      nodeToken,
		NodeID:         nodeID,
		DataDir:        identity.DataDir,
		InstallDir:     identity.InstallDir,
		BinaryName:     identity.BinaryName,
		Arch:           arch,
		CurrentBuildID: runtime.BuildID,
		Check:          true,
	})
	if err != nil {
		*problems = append(*problems, fmt.Sprintf("latest agent release check failed: %v", err))
		return
	}
	log.Printf("doctor: latest agent build=%s sha256=%s", result.ReleaseBuildID, result.ReleaseSHA256)
	if runtime.BuildID != "" && runtime.BuildID != "unknown" && runtime.BuildID != result.ReleaseBuildID {
		*problems = append(*problems, fmt.Sprintf("agent build %s is behind controller build %s (run `hlg-agent upgrade`)", runtime.BuildID, result.ReleaseBuildID))
	}
	installedPath := identity.BinaryPath
	if installedPath == "" {
		installedPath = filepath.Join(identity.InstallDir, identity.BinaryName)
	}
	if actual, hashErr := sha256File(installedPath); hashErr == nil && !strings.EqualFold(actual, result.ReleaseSHA256) {
		*problems = append(*problems, fmt.Sprintf("installed agent sha256 differs from controller release (run `hlg-agent upgrade`): %s", installedPath))
	}
	if runningPath := executablePath(); runningPath != "" && runningPath != installedPath {
		if actual, hashErr := sha256File(runningPath); hashErr == nil && !strings.EqualFold(actual, result.ReleaseSHA256) {
			*problems = append(*problems, fmt.Sprintf("running agent sha256 differs from controller release (run `hlg-agent upgrade`): %s", runningPath))
		}
	}
}

func sha256File(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", hash.Sum(nil)), nil
}

// checkService reports on the configured service manager's state.
func checkService(mode, serviceName string) []string {
	switch mode {
	case "systemd":
		if !commandExists("systemctl") || !fileExists("/run/systemd/system") {
			return []string{"systemd selected but systemctl or /run/systemd/system is unavailable"}
		}
		if !fileExists(filepath.Join(systemdUnitDir, serviceName+".service")) {
			return []string{fmt.Sprintf("systemd unit %s.service is not installed", serviceName)}
		}
		active, _ := exec.Command("systemctl", "is-active", serviceName+".service").Output()
		state := strings.TrimSpace(string(active))
		if state != "active" {
			return []string{fmt.Sprintf("systemd service %s.service is not active (%s)", serviceName, orUnknown(state))}
		}
		log.Printf("doctor: systemd service %s.service is active", serviceName)
	case "init.d":
		if !commandExists("rc-service") {
			return []string{"init.d/OpenRC selected but rc-service is unavailable"}
		}
		if out, err := exec.Command("rc-service", serviceName, "status").CombinedOutput(); err != nil {
			return []string{fmt.Sprintf("OpenRC service %s is not running (%s)", serviceName, orUnknown(strings.TrimSpace(string(out))))}
		}
		log.Printf("doctor: OpenRC service %s is running", serviceName)
	default:
		log.Printf("doctor: service mode none (managed externally, e.g. a container)")
	}
	return nil
}

// checkTLS validates the serving certificate and, when the agent is listening,
// completes a real local handshake — the failure the worker observes as
// "unexpected eof" is exactly a listener that accepts TCP but presents no cert.
func checkTLS(dataDir, bind, domain string, expectServing bool) []string {
	var problems []string
	certPath := filepath.Join(dataDir, certstore.CertFile)
	keyPath := filepath.Join(dataDir, certstore.KeyFile)
	if !fileExists(certPath) || !fileExists(keyPath) {
		if !expectServing {
			log.Printf("doctor: no TLS certificate yet (fresh install; the agent generates one on first start)")
			return nil
		}
		return []string{fmt.Sprintf("no TLS certificate pair in %s (the agent cannot serve HTTPS)", dataDir)}
	}
	pair, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return []string{fmt.Sprintf("TLS certificate/key in %s does not load: %v", dataDir, err)}
	}
	source, _ := certstore.New(dataDir).ReadSource()
	if len(pair.Certificate) > 0 {
		if leaf, parseErr := x509.ParseCertificate(pair.Certificate[0]); parseErr == nil {
			log.Printf("doctor: certificate source=%s expires=%s dns=%s", source, leaf.NotAfter.UTC().Format(time.RFC3339), strings.Join(leaf.DNSNames, ","))
		}
	}
	if source != certstore.CertSourceManaged {
		log.Printf("doctor: serving a %s certificate; the controller cannot verify it (it will be unreachable from the worker)", source)
	}

	// Best-effort local handshake against the listening port.
	addr := strings.TrimSpace(bind)
	if addr == "" {
		addr = ":443"
	}
	host, port, splitErr := net.SplitHostPort(addr)
	if splitErr != nil {
		port = strings.TrimPrefix(addr, ":")
	}
	dialHost := host
	if dialHost == "" || dialHost == "0.0.0.0" || dialHost == "::" {
		dialHost = "127.0.0.1"
	}
	serverName := domain
	conn, dialErr := tls.DialWithDialer(
		&net.Dialer{Timeout: 5 * time.Second},
		"tcp",
		net.JoinHostPort(dialHost, port),
		&tls.Config{InsecureSkipVerify: true, ServerName: serverName}, // #nosec G402 -- self-probe of our own cert
	)
	if dialErr != nil {
		// Not listening is informational unless a service manager says it should
		// be running (that mismatch is reported by checkService).
		log.Printf("doctor: local TLS listener not reachable at %s (%v)", net.JoinHostPort(dialHost, port), dialErr)
		return problems
	}
	defer conn.Close()
	if err := conn.Handshake(); err != nil {
		problems = append(problems, fmt.Sprintf("local TLS handshake failed at %s: %v", net.JoinHostPort(dialHost, port), err))
	} else {
		state := conn.ConnectionState()
		if len(state.PeerCertificates) == 0 {
			problems = append(problems, fmt.Sprintf("local TLS handshake at %s presented no certificate", net.JoinHostPort(dialHost, port)))
		} else {
			log.Printf("doctor: local TLS handshake ok (subject=%s)", state.PeerCertificates[0].Subject.CommonName)
		}
	}
	return problems
}

// checkController verifies the agent can reach the controller and that its node
// token is still accepted.
func checkController(cfg config.Config, dataDir string) []string {
	var problems []string
	controller := cfg.Controller
	if controller == "" {
		controller = os.Getenv("LG_CONTROLLER")
	}
	if controller == "" {
		log.Printf("doctor: no controller configured; skipping connectivity check")
		return nil
	}
	if err := probeURL(controller+"/api/public-config", "", 8*time.Second); err != nil {
		problems = append(problems, fmt.Sprintf("controller unreachable at %s: %v", controller, err))
	} else {
		log.Printf("doctor: controller reachable: %s", controller)
	}
	if nodeToken, tokenErr := enroll.LoadNodeToken(dataDir); tokenErr == nil && nodeToken != "" {
		endpoint := controller + "/_lg/control/keyset"
		if cfg.NodeID != "" {
			endpoint += "?node=" + url.QueryEscape(cfg.NodeID)
		}
		if err := probeURL(endpoint, nodeToken, 8*time.Second); err != nil {
			problems = append(problems, fmt.Sprintf("node token not accepted by controller: %v", err))
		} else {
			log.Printf("doctor: node token accepted by controller")
		}
	}
	return problems
}

func orUnknown(value string) string {
	if value == "" {
		return "unknown"
	}
	return value
}

// installIdentity is the resolved install layout that maintenance subcommands
// (upgrade, doctor, service, uninstall) operate on.
type installIdentity struct {
	InstallDir  string
	DataDir     string
	BinaryPath  string
	BinaryName  string
	ServiceName string
	ServiceUser string
	ServiceMode string
	ConfigFile  string
	// ExplicitTarget is set when the operator passed --path or --name on the
	// command line. Destructive commands skip the running-binary/target
	// cross-check in that case: an explicit target is intentional even when it
	// differs from the binary being run.
	ExplicitTarget bool
}

// executablePath returns the absolute path to the currently running binary,
// with symlinks resolved so a service unit that launches via a symlink still
// resolves to the real installed file. A variable so tests can stub it.
var executablePath = func() string {
	exe, err := os.Executable()
	if err != nil {
		return ""
	}
	resolved, err := filepath.EvalSymlinks(exe)
	if err != nil {
		return exe
	}
	return resolved
}

// Service unit locations, variables so tests can point them at temp dirs.
var (
	systemdUnitDir = "/etc/systemd/system"
	openrcInitDir  = "/etc/init.d"
)

// installRecord is the install-layout block the installer writes into
// agent.json. It is read as raw JSON (not config.Load) so compiled-in config
// defaults cannot leak in as phantom recorded values.
type installRecord struct {
	InstallDir  string `json:"install_dir"`
	BinaryPath  string `json:"binary_path"`
	BinaryName  string `json:"binary_name"`
	ServiceName string `json:"service_name"`
	ServiceMode string `json:"service_mode"`
	DataDir     string `json:"data_dir"`
	User        string `json:"user"`
}

func readInstallRecord(path string) installRecord {
	var record installRecord
	if path == "" {
		return record
	}
	body, err := os.ReadFile(path)
	if err != nil {
		return record
	}
	_ = json.Unmarshal(body, &record)
	return record
}

// discoverServiceName finds the service unit (systemd unit file or OpenRC init
// script) whose ExecStart/command launches the given binary. This recovers the
// service name for installs that predate recording the layout in agent.json,
// so `--update` restarts the service the node actually runs instead of the
// compiled-in default.
func discoverServiceName(binaryPath string) (string, bool) {
	if entries, err := os.ReadDir(systemdUnitDir); err == nil {
		for _, entry := range entries {
			name := entry.Name()
			if entry.IsDir() || !strings.HasSuffix(name, ".service") {
				continue
			}
			body, err := os.ReadFile(filepath.Join(systemdUnitDir, name))
			if err != nil {
				continue
			}
			if unitExecStartBinary(string(body)) == binaryPath {
				return strings.TrimSuffix(name, ".service"), true
			}
		}
	}
	if entries, err := os.ReadDir(openrcInitDir); err == nil {
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			body, err := os.ReadFile(filepath.Join(openrcInitDir, entry.Name()))
			if err != nil {
				continue
			}
			if openrcCommandBinary(string(body)) == binaryPath {
				return entry.Name(), true
			}
		}
	}
	return "", false
}

// unitExecStartBinary extracts the program path from a systemd ExecStart= line.
func unitExecStartBinary(body string) string {
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "ExecStart=") {
			continue
		}
		fields := strings.Fields(strings.TrimPrefix(line, "ExecStart="))
		if len(fields) == 0 {
			return ""
		}
		return fields[0]
	}
	return ""
}

// openrcCommandBinary extracts the program path from an OpenRC command= line.
func openrcCommandBinary(body string) string {
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "command=") {
			continue
		}
		value := strings.Trim(strings.TrimPrefix(line, "command="), `"`)
		fields := strings.Fields(value)
		if len(fields) == 0 {
			return ""
		}
		return fields[0]
	}
	return ""
}

// resolveInstallIdentity resolves the install layout for a maintenance command
// (--update, --self-check, --uninstall).
//
// Sources, most specific first:
//  1. Explicit flags the operator passed.
//  2. The layout recorded in agent.json (written by --install).
//  3. The running binary itself: when agent.json sits next to it, the binary is
//     the installed one, so its directory and base name are the install dir and
//     binary name. The service name is additionally recovered from whichever
//     systemd/OpenRC unit launches this binary, which covers installs that
//     predate the recorded layout.
//  4. Compiled-in defaults for anything still missing.
func resolveInstallIdentity(explicitFlags map[string]bool, configFile, installDir, dataDir, serviceMode, binaryName, serviceName string) (installIdentity, error) {
	identity := installIdentity{ServiceMode: serviceMode}

	// Locate agent.json: explicit --config, then next to an explicit
	// --install-dir, then next to the running binary, then standard discovery.
	// An explicit --install-dir with no config there does NOT fall back to other
	// sources: mixing another install's record into an explicit target is how
	// the wrong service gets touched.
	configPath := strings.TrimSpace(configFile)
	recordLocked := false
	if configPath == "" && explicitFlags["path"] {
		candidate := filepath.Join(strings.TrimRight(installDir, "/"), "agent.json")
		if fileExists(candidate) {
			configPath = candidate
		} else {
			recordLocked = true
		}
	}
	exeAdjacent := false
	if configPath == "" && !recordLocked {
		if exe := executablePath(); exe != "" {
			candidate := filepath.Join(filepath.Dir(exe), "agent.json")
			if fileExists(candidate) {
				configPath = candidate
				exeAdjacent = true
			}
		}
	}
	if configPath == "" && !recordLocked {
		configPath = discoverConfigFile("")
	}
	identity.ConfigFile = configPath
	record := readInstallRecord(configPath)

	// Install dir: explicit flag > recorded > the binary's own directory (only
	// when its config sits next to it) > default.
	switch {
	case explicitFlags["path"] && strings.TrimSpace(installDir) != "":
		identity.InstallDir = strings.TrimRight(installDir, "/")
	case record.InstallDir != "":
		identity.InstallDir = record.InstallDir
	case exeAdjacent:
		identity.InstallDir = filepath.Dir(executablePath())
	default:
		identity.InstallDir = "/opt/looking-glass"
	}

	// Binary name: explicit flag > recorded > the running binary's name (same
	// adjacency rule) > default.
	switch {
	case explicitFlags["name"] && strings.TrimSpace(binaryName) != "":
		identity.BinaryName = normalizeUnitName(binaryName, "hlg-agent")
	case record.BinaryName != "":
		identity.BinaryName = record.BinaryName
	case exeAdjacent:
		identity.BinaryName = filepath.Base(executablePath())
	default:
		identity.BinaryName = "hlg-agent"
	}

	// Binary path: the recorded path wins (it is authoritative and handles a
	// binary name that differs from the install dir), otherwise derive it.
	if record.BinaryPath != "" && !explicitFlags["path"] {
		identity.BinaryPath = record.BinaryPath
	} else {
		identity.BinaryPath = filepath.Join(identity.InstallDir, identity.BinaryName)
	}

	// Service name: explicit flag > recorded > whichever unit launches this
	// binary > the binary name (most installs use the same name for both).
	switch {
	case explicitFlags["service-name"] && strings.TrimSpace(serviceName) != "":
		identity.ServiceName = normalizeUnitName(serviceName, "hlg-agent")
	case record.ServiceName != "":
		identity.ServiceName = record.ServiceName
	default:
		if found, ok := discoverServiceName(identity.BinaryPath); ok {
			identity.ServiceName = found
		} else {
			identity.ServiceName = identity.BinaryName
		}
	}

	// Service mode: explicit flag > recorded > the flag value (default "auto",
	// which detects systemd/OpenRC at use time and means "both" for uninstall).
	switch {
	case explicitFlags["service"] && strings.TrimSpace(serviceMode) != "":
		identity.ServiceMode = serviceMode
	case record.ServiceMode != "":
		identity.ServiceMode = record.ServiceMode
	}
	if strings.TrimSpace(identity.ServiceMode) == "" {
		identity.ServiceMode = "auto"
	}

	// Data dir: explicit flag > recorded > installDir/data.
	switch {
	case explicitFlags["data-dir"] && strings.TrimSpace(dataDir) != "":
		identity.DataDir = dataDir
	case record.DataDir != "":
		identity.DataDir = record.DataDir
	default:
		identity.DataDir = filepath.Join(identity.InstallDir, "data")
	}

	// Service user: recorded > default. Maintenance commands have no --user flag;
	// `service install` needs the recorded user to reproduce the same unit.
	identity.ServiceUser = record.User
	if strings.TrimSpace(identity.ServiceUser) == "" {
		identity.ServiceUser = "root"
	}

	identity.ExplicitTarget = explicitFlags["path"] || explicitFlags["name"]
	return identity, nil
}

// runUpdate implements --update / --check-update. It reads the runtime config the
// service actually uses so the controller URL, node id, and tokens match the
// running agent, then delegates to agentupdate.Run with the install's real
// binary/service names.
func runUpdate(identity installIdentity, force, checkOnly bool) error {
	resolvedMode, err := normalizeServiceMode(identity.ServiceMode, false)
	if err != nil {
		return err
	}
	cfg := config.Config{}
	if identity.ConfigFile != "" && fileExists(identity.ConfigFile) {
		loaded, loadErr := config.Load(config.LoadOptions{File: identity.ConfigFile, Flags: map[string]string{"data-dir": identity.DataDir}})
		if loadErr != nil {
			return fmt.Errorf("load runtime config %s: %w", identity.ConfigFile, loadErr)
		}
		cfg = loaded
	}
	if cfg.NodeToken == "" {
		if token, tokenErr := enroll.LoadNodeToken(identity.DataDir); tokenErr == nil {
			cfg.NodeToken = token
		}
	}
	if cfg.NodeID == "" {
		if stored, storedErr := enroll.LoadStoredConfig(identity.DataDir); storedErr == nil {
			cfg.NodeID = stored.NodeID
		}
	}
	if cfg.Controller == "" {
		return fmt.Errorf("controller URL is not configured; cannot check for updates")
	}
	if cfg.NodeToken == "" {
		return fmt.Errorf("node token is missing in %s; is the agent installed?", identity.DataDir)
	}
	if cfg.NodeID == "" {
		return fmt.Errorf("node id is missing; is the agent installed?")
	}
	arch := runtimeArch()
	if arch == "" {
		return fmt.Errorf("unsupported architecture: %s", goruntime.GOARCH)
	}

	log.Printf("update: install_dir=%s binary=%s service=%s mode=%s", identity.InstallDir, identity.BinaryName, identity.ServiceName, resolvedMode)
	opts := agentupdate.Options{
		Controller:     cfg.Controller,
		NodeToken:      cfg.NodeToken,
		NodeID:         cfg.NodeID,
		DataDir:        identity.DataDir,
		InstallDir:     identity.InstallDir,
		BinaryName:     identity.BinaryName,
		ServiceName:    identity.ServiceName,
		ServiceMode:    resolvedMode,
		Arch:           arch,
		CurrentBuildID: runtime.BuildID,
		Check:          checkOnly,
		Force:          force,
		Logf:           log.Printf,
		ApplyCaps: func(path string) error {
			if !commandExists("setcap") {
				return nil
			}
			return runCommand("setcap", "cap_net_raw,cap_net_admin,cap_net_bind_service+eip", path)
		},
	}
	if !checkOnly {
		opts.Restart = func() error { return restartService(resolvedMode, identity.ServiceName) }
	}

	result, err := agentupdate.Run(context.Background(), opts)
	if err != nil {
		return err
	}
	switch {
	case result.UpToDate:
		log.Printf("update: already on build %s", result.ReleaseBuildID)
	case checkOnly:
		log.Printf("update: available %s -> %s", result.CurrentBuildID, result.ReleaseBuildID)
	default:
		log.Printf("update: installed build %s", result.ReleaseBuildID)
	}
	// Keep the runtime deps current too: an upgraded agent may expect a newer
	// nexttrace/iperf3. Best-effort — a deps failure must not fail the upgrade.
	if !checkOnly {
		upgradeDeps(cfg.Controller, identity.DataDir, cfg.Tools)
	}
	return nil
}

// upgradeDeps upgrades every managed runtime tool (best-effort). It is called
// after an agent upgrade so a newer binary is not left with stale tools.
func upgradeDeps(controller, dataDir string, recordedTools map[string]string) {
	for _, tool := range deps.All() {
		if !usesManagedDependency(recordedTools, dataDir, tool) {
			continue
		}
		updated, err := deps.UpgradeManaged(context.Background(), controller, dataDir, tool, log.Printf)
		if err != nil {
			log.Printf("deps: upgrade %s failed: %v", tool.Name, err)
			continue
		}
		if !updated {
			log.Printf("deps: %s already up to date", tool.Name)
		}
	}
}

func usesManagedDependency(recordedTools map[string]string, dataDir string, tool deps.Tool) bool {
	if !deps.HasStandaloneBuild(tool.Name) {
		return false
	}
	ok, where := deps.Effective(recordedTools, dataDir, tool.Name)
	return ok && filepath.Clean(where) == filepath.Clean(deps.BinaryPath(dataDir, tool.Name))
}

func restartService(mode, serviceName string) error {
	switch mode {
	case "systemd":
		return runCommand("systemctl", "restart", serviceName+".service")
	case "init.d":
		if !commandExists("rc-service") {
			return fmt.Errorf("rc-service is unavailable")
		}
		return runCommand("rc-service", serviceName, "restart")
	default:
		return nil
	}
}

// usage prints the subcommand help.
func usage() {
	fmt.Fprint(os.Stderr, `hlg-agent - Looking Glass node agent

The controller comes from the init string/key (host[:port]/lginit_<key>) or
LG_CONTROLLER.

Usage (a bare hlg-agent prints this help):
  hlg-agent init    -k HOST[:PORT]/lginit_<key> [--service auto|systemd|init.d|none]
                    [--name hlg-agent] [--service-name NAME] [--path DIR]
                    [--user USER] [--bind ADDR | --port PORT] [--install-deps-yes] [--yes]
                    Interactive by default (asks key / path / service / service name); --yes accepts defaults.
  hlg-agent run     [-c agent.json] [-i -k HOST[:PORT]/lginit_<key>] [--bind ADDR | --port PORT]
                    -i bootstraps a fresh data dir in place, then serves; stored nodes ignore the key.
                    Without -i, -k is ignored. Use init for host installation.
  hlg-agent upgrade [--check] [--force]
  hlg-agent service status|install|uninstall|start|stop|restart
  hlg-agent deps    check|install|upgrade|builtin|config [tool...] [--source system|builtin|download|path|install|auto]
  hlg-agent probe   [-4|-6] ping|mtr|traceroute TARGET
  hlg-agent doctor
  hlg-agent uninstall
  hlg-agent version
  hlg-agent licenses
`)
}

// runServiceAction manages the installed service unit from the recorded layout.
func runServiceAction(action string, identity installIdentity) error {
	mode, err := normalizeServiceMode(identity.ServiceMode, false)
	if err != nil {
		return err
	}
	switch action {
	case "status":
		return serviceStatus(mode, identity)
	case "install":
		return serviceInstall(mode, identity)
	case "uninstall":
		return serviceUninstall(mode, identity)
	case "start", "stop", "restart":
		return serviceControl(mode, identity.ServiceName, action)
	default:
		return fmt.Errorf("unknown service action %q (want status|install|uninstall|start|stop|restart)", action)
	}
}

func serviceInstall(mode string, identity installIdentity) error {
	switch mode {
	case "systemd":
		return installSystemdService(identity.InstallDir, identity.DataDir, identity.ServiceUser, identity.BinaryName, identity.ServiceName)
	case "init.d":
		return installInitDService(identity.InstallDir, identity.DataDir, identity.ServiceUser, identity.BinaryName, identity.ServiceName)
	default:
		log.Printf("service: mode none; nothing to install")
		return nil
	}
}

func serviceUninstall(mode string, identity installIdentity) error {
	// Refuse to remove a service we could not identify, for the same reason
	// uninstall does: a default name could belong to a different install.
	if !identity.ExplicitTarget && strings.TrimSpace(identity.ConfigFile) == "" {
		return fmt.Errorf("refusing to uninstall service: no agent.json found for %s; pass --path/--name to confirm the target", identity.InstallDir)
	}
	switch mode {
	case "systemd":
		_ = exec.Command("systemctl", "disable", "--now", identity.ServiceName+".service").Run()
		if err := os.Remove(filepath.Join(systemdUnitDir, identity.ServiceName+".service")); err != nil && !os.IsNotExist(err) {
			return err
		}
		_ = exec.Command("systemctl", "daemon-reload").Run()
	case "init.d":
		_ = exec.Command("rc-service", identity.ServiceName, "stop").Run()
		_ = exec.Command("rc-update", "del", identity.ServiceName, "default").Run()
		if err := os.Remove(filepath.Join(openrcInitDir, identity.ServiceName)); err != nil && !os.IsNotExist(err) {
			return err
		}
	default:
		log.Printf("service: mode none; nothing to uninstall")
	}
	return nil
}

func serviceControl(mode, serviceName, action string) error {
	switch mode {
	case "systemd":
		return runCommand("systemctl", action, serviceName+".service")
	case "init.d":
		if !commandExists("rc-service") {
			return fmt.Errorf("rc-service is unavailable")
		}
		return runCommand("rc-service", serviceName, action)
	default:
		return fmt.Errorf("no service manager configured (service mode none)")
	}
}

func serviceStatus(mode string, identity installIdentity) error {
	log.Printf("service: install_dir=%s binary=%s service=%s mode=%s user=%s", identity.InstallDir, identity.BinaryName, identity.ServiceName, mode, identity.ServiceUser)
	switch mode {
	case "systemd":
		printCommand("systemctl", "is-active", identity.ServiceName+".service")
		printCommand("systemctl", "is-enabled", identity.ServiceName+".service")
	case "init.d":
		printCommand("rc-service", identity.ServiceName, "status")
	default:
		log.Printf("service: mode none; no service manager to query")
	}
	return nil
}

func printCommand(name string, args ...string) {
	output, err := exec.Command(name, args...).CombinedOutput()
	if trimmed := strings.TrimSpace(string(output)); trimmed != "" {
		fmt.Printf("%s %s: %s\n", name, strings.Join(args, " "), trimmed)
	}
	if err != nil {
		fmt.Printf("%s %s: %v\n", name, strings.Join(args, " "), err)
	}
}

// portInUse reports whether the listen address is already occupied, with a
// human-readable description of the holder when discoverable.
var portInUse = checkPortInUse

func checkPortInUse(bind string) (bool, string) {
	if strings.TrimSpace(bind) == "" {
		return false, ""
	}
	ln, err := net.Listen("tcp", bind)
	if err != nil {
		return true, describeListener(bind)
	}
	_ = ln.Close()
	return false, ""
}

// describeListener tries to name the process holding the port (best effort,
// Linux/procps). It never fails the caller.
func describeListener(bind string) string {
	_, port, err := net.SplitHostPort(bind)
	if err != nil {
		return ""
	}
	for _, args := range [][]string{
		{"-ltnp", "sport = :" + port},
		{"-ltnp"},
	} {
		if !commandExists("ss") {
			break
		}
		out, err := exec.Command("ss", args...).Output()
		if err != nil {
			continue
		}
		line := matchingListenerLine(string(out), port)
		if line != "" {
			return line
		}
	}
	return ""
}

func matchingListenerLine(out, port string) string {
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, ":"+port) && (strings.Contains(line, "LISTEN") || strings.Contains(line, "users:")) {
			return strings.TrimSpace(line)
		}
	}
	return ""
}

// installDepsInteractive resolves each missing runtime tool with the operator.
//
// Decision tree (per tool):
//
//	system has it:   [k] keep system (default) / [b] built-in / [p] path
//	system lacks it: [i] package (default) / [b] built-in / [d] upstream
//	                 / [p] path / [n] nothing
//
// --install-deps-yes accepts every automatic source choice without prompting.
var installDepsInteractive = func(ctx context.Context, controller, dataDir string, assumeYes bool) error {
	for _, tool := range deps.All() {
		systemPath := deps.SystemPath(tool.Name)
		if systemPath != "" {
			choice := choosePresentTool(tool, systemPath, deps.HasStandaloneBuild(tool.Name), assumeYes)
			applyDepsChoice(ctx, controller, dataDir, tool, choice)
			continue
		}
		choice := chooseMissingTool(tool, deps.HasStandaloneBuild(tool.Name), assumeYes)
		applyDepsChoice(ctx, controller, dataDir, tool, choice)
	}
	return nil
}

// applyDepsChoice records/executes a chosen source for one tool. Keys:
// system, install, builtin, download, path, nothing, auto.
func applyDepsChoice(ctx context.Context, controller, dataDir string, tool deps.Tool, choice string) {
	switch choice {
	case "auto":
		chosenTools[tool.Name] = "" // explicit clear -> automatic
		log.Printf("deps: %s: automatic", tool.Name)
	case "system":
		if p := deps.SystemPath(tool.Name); p != "" {
			chosenTools[tool.Name] = p
			log.Printf("deps: %s: system %s", tool.Name, p)
		} else {
			chosenTools[tool.Name] = ""
			log.Printf("deps: %s: no system binary; automatic", tool.Name)
		}
	case "install":
		if err := deps.Install(ctx, controller, dataDir, tool, false, log.Printf); err != nil {
			log.Printf("deps: warning: install %s failed: %v", tool.Name, err)
			if deps.IsBuiltin(tool.Name) {
				log.Printf("deps: %s: falling back to built-in probe", tool.Name)
				chosenTools[tool.Name] = deps.BuiltinMarker
			}
		} else {
			recordResolved(dataDir, tool)
		}
	case "builtin":
		chosenTools[tool.Name] = deps.BuiltinMarker
		log.Printf("deps: %s: built-in probe", tool.Name)
	case "download":
		if path, err := deps.InstallDownloaded(ctx, controller, dataDir, tool, false, log.Printf); err != nil {
			log.Printf("deps: warning: download %s failed: %v", tool.Name, err)
		} else {
			chosenTools[tool.Name] = path
		}
	case "path":
		if path := promptLine(fmt.Sprintf("path to %s binary:", tool.Name)); path != "" {
			recordToolPath(tool.Name, path)
		}
	case "nothing":
		// No-op: preserve the current source and its persisted choice.
		log.Printf("deps: %s: do nothing", tool.Name)
	default: // "keep" (present, auto-keep)
		if p := deps.SystemPath(tool.Name); p != "" {
			chosenTools[tool.Name] = p
			log.Printf("deps: %s: system %s", tool.Name, p)
		}
	}
}

// chosenTools records resolved paths for tools that are NOT left to PATH, so
// they are persisted into agent.json (system tools are recorded too, pinning the
// verified binary).
var chosenTools = map[string]string{}
var depsConfigChanged bool

func recordChosen(name, path string) {
	chosenTools[name] = path
}

func recordToolPath(name, path string) {
	path = strings.TrimSpace(path)
	if path == "" {
		log.Printf("deps: %s: no path given; skipping", name)
		return
	}
	if !fileExists(path) {
		log.Printf("deps: %s: %s does not exist; skipping", name, path)
		return
	}
	log.Printf("deps: %s: using %s", name, path)
	recordChosen(name, path)
}

// sourceOption is one numbered menu entry.
type sourceOption struct {
	key   string
	label string
}

// sourceOptions builds the numbered choices for a tool, adapting to what is
// available. Full labels (never bare letters) so the operator sees what each
// option does; `builtin` states that the agent implements the probe.
func sourceOptions(tool deps.Tool) []sourceOption {
	opts := make([]sourceOption, 0, 6)
	if p := deps.SystemPath(tool.Name); p != "" {
		opts = append(opts, sourceOption{"system", fmt.Sprintf("system binary (%s)", p)})
	} else if deps.HasPackage(tool) {
		opts = append(opts, sourceOption{"install", "install via the system package manager"})
	}
	if deps.IsBuiltin(tool.Name) {
		opts = append(opts, sourceOption{"builtin", "built-in probe (implemented by the agent)"})
	}
	if deps.HasStandaloneBuild(tool.Name) {
		opts = append(opts, sourceOption{"download", "download from the controller (stored under data)"})
	}
	opts = append(opts,
		sourceOption{"path", "use an explicit binary path"},
		sourceOption{"nothing", "do nothing"},
		sourceOption{"auto", "automatic (system when present, else built-in/package)"},
	)
	return opts
}

func optionIndex(opts []sourceOption, key string) int {
	for i, o := range opts {
		if o.key == key {
			return i + 1
		}
	}
	return 1
}

// promptSource prints the numbered menu for one tool and returns the chosen key.
func promptSource(tool deps.Tool, defaultKey string) string {
	opts := sourceOptions(tool)
	fmt.Fprintf(os.Stderr, "\n%s: choose its source\n", tool.Name)
	for i, o := range opts {
		suffix := ""
		if o.key == defaultKey {
			suffix = "  (default)"
		}
		fmt.Fprintf(os.Stderr, "  %d. %s%s\n", i+1, o.label, suffix)
	}
	label := fmt.Sprintf("change (%s)", numberList(len(opts)))
	n := promptIndex(label, len(opts), optionIndex(opts, defaultKey))
	return opts[n-1].key
}

func numberList(n int) string {
	parts := make([]string, n)
	for i := 0; i < n; i++ {
		parts[i] = fmt.Sprint(i + 1)
	}
	return strings.Join(parts, "/")
}

// promptIndex reads a 1-based number in [1,max], returning the default on empty
// or invalid input.
func promptIndex(question string, max, def int) int {
	answer := strings.TrimSpace(promptLine(question + ":"))
	if answer == "" {
		return def
	}
	n, err := strconv.Atoi(answer)
	if err != nil || n < 1 || n > max {
		return def
	}
	return n
}

// currentSource renders a tool's effective source for the list view.
func currentSource(ctx context.Context, controller, dataDir string, tool deps.Tool) string {
	if chosen, ok := chosenTools[tool.Name]; ok {
		switch {
		case deps.IsAutomaticChoice(chosen):
			return "current: auto"
		case chosen == deps.BuiltinMarker:
			return "current: built-in"
		case filepath.Dir(chosen) == deps.DepsDir(dataDir):
			// The agent-managed copy (downloaded): name it as the tool itself.
			return fmt.Sprintf("current: %s [%s]", tool.Name, chosen)
		case chosen == deps.SystemPath(tool.Name):
			return "current: system [" + chosen + "]"
		default:
			return "current: custom [" + chosen + "]"
		}
	}
	if p := deps.SystemPath(tool.Name); p != "" {
		return "current: system [" + p + "]"
	}
	if deps.IsBuiltin(tool.Name) {
		return "current: auto (built-in when needed)"
	}
	if deps.HasStandaloneBuild(tool.Name) {
		return "current: auto (download/package when needed)"
	}
	return "current: auto (package when needed)"
}

// choosePresentTool / chooseMissingTool now share the numbered promptSource; they
// only differ in the default option.
func choosePresentTool(tool deps.Tool, systemPath string, downloadable, assumeYes bool) string {
	if assumeYes {
		return "keep"
	}
	if !isTerminal(os.Stdin) {
		return "keep"
	}
	return promptSource(tool, "system")
}

func chooseMissingTool(tool deps.Tool, downloadable, assumeYes bool) string {
	defaultChoice := missingToolDefault(tool, downloadable)
	if assumeYes {
		return defaultChoice
	}
	if !isTerminal(os.Stdin) {
		return defaultChoice
	}
	return promptSource(tool, defaultChoice)
}

// missingToolDefault follows the non-interactive automatic policy: use a
// built-in probe where available, then a managed download into data, and use
// the system package manager only when neither source exists.
func missingToolDefault(tool deps.Tool, downloadable bool) string {
	switch {
	case deps.IsBuiltin(tool.Name):
		return "builtin"
	case downloadable:
		return "download"
	case deps.HasPackage(tool):
		return "install"
	default:
		return "nothing"
	}
}

// promptInitOptions asks for any init option the operator did not pass on the
// command line: install/data paths, service settings, and the agent listen
// port. It is skipped when --yes is set or stdin is not a terminal, in which
// case the config/default values apply. Explicit flags always win.
func promptInitOptions(installDir, serviceMode, serviceName, dataDir, bind *string, configFile string, explicit map[string]bool, assumeYes bool) error {
	if assumeYes || !isTerminal(os.Stdin) {
		return nil
	}
	if !explicit["path"] {
		if answer := promptLine(fmt.Sprintf("install directory [%s]:", *installDir)); answer != "" {
			*installDir = answer
		}
	}
	if !explicit["data-dir"] {
		defaultDataDir := *dataDir
		if defaultDataDir == "" {
			defaultDataDir = filepath.Join(*installDir, "data")
		}
		if answer := promptLine(fmt.Sprintf("data directory [%s]:", defaultDataDir)); answer != "" {
			*dataDir = answer
		} else {
			*dataDir = defaultDataDir
		}
	}
	if !explicit["service"] {
		detected := detectServiceMode()
		if promptYesNoDefault(fmt.Sprintf("install a service (detected %s)?", detected), detected != "none") {
			*serviceMode = detected
		} else {
			*serviceMode = "none"
		}
	}
	if !explicit["service-name"] {
		if answer := promptLine(fmt.Sprintf("service name [%s]:", *serviceName)); answer != "" {
			*serviceName = answer
		}
	}
	if !explicit["bind"] && !explicit["port"] && !explicit["p"] {
		seed, err := installSeedConfig(configFile)
		if err != nil {
			return err
		}
		defaultBind := firstNonEmpty(*bind, seed.Bind, config.DefaultBind)
		_, defaultPort, err := net.SplitHostPort(defaultBind)
		if err != nil {
			return fmt.Errorf("invalid default bind address %q: %w", defaultBind, err)
		}
		for {
			answer := promptLine(fmt.Sprintf("agent listen port [%s]:", defaultPort))
			if answer == "" {
				break
			}
			updatedBind, err := bindWithPort(defaultBind, answer)
			if err != nil {
				fmt.Fprintf(os.Stderr, "invalid agent listen port: %v\n", err)
				continue
			}
			*bind = updatedBind
			break
		}
	}
	// Keep the data dir coherent with a changed install path unless pinned.
	if !explicit["data-dir"] && *dataDir == "" {
		*dataDir = filepath.Join(*installDir, "data")
	}
	return nil
}

func bindWithPort(defaultBind, rawPort string) (string, error) {
	host, _, err := net.SplitHostPort(defaultBind)
	if err != nil {
		return "", fmt.Errorf("invalid default bind address %q: %w", defaultBind, err)
	}
	port, err := strconv.Atoi(strings.TrimSpace(rawPort))
	if err != nil || port < 1 || port > 65535 {
		return "", fmt.Errorf("port must be an integer from 1 to 65535")
	}
	return net.JoinHostPort(host, strconv.Itoa(port)), nil
}

// promptLine asks a question and returns the trimmed answer ("" to keep the
// default shown in the question).
func promptLine(question string) string {
	fmt.Fprintf(os.Stderr, "%s ", question)
	line, _ := readPromptLine()
	return strings.TrimSpace(line)
}

var promptInputFile *os.File
var promptInputReader *bufio.Reader

func readPromptLine() (string, error) {
	if promptInputReader == nil || promptInputFile != os.Stdin {
		promptInputFile = os.Stdin
		promptInputReader = bufio.NewReader(os.Stdin)
	}
	return promptInputReader.ReadString('\n')
}

// applyDependencyChoices merges the resolved decisions into a tools map. A
// chosen value of "" means "clear this entry" (automatic).
func applyDependencyChoices(tools map[string]string) map[string]string {
	if tools == nil {
		tools = map[string]string{}
	}
	for name, path := range chosenTools {
		if path == "" {
			delete(tools, name)
			continue
		}
		tools[name] = path
	}
	return tools
}

// ensureRunDependencies applies the automatic init policy for `run -i`:
// preserve working configured/system tools, use built-in probes where possible,
// and otherwise download managed binaries into the mounted data directory.
func ensureRunDependencies(ctx context.Context, cfg *config.Config, configPath string) {
	depsConfigPath = configPath
	chosenTools = map[string]string{}
	for _, tool := range deps.All() {
		configured := cfg.Tools[tool.Name]
		if configured == deps.BuiltinMarker {
			continue
		}
		if configured != "" && executableFile(configured) {
			continue
		}
		if systemPath := deps.SystemPath(tool.Name); systemPath != "" {
			chosenTools[tool.Name] = systemPath
			continue
		}
		managedPath := deps.BinaryPath(cfg.DataDir, tool.Name)
		if executableFile(managedPath) {
			chosenTools[tool.Name] = managedPath
			continue
		}
		chosenTools[tool.Name] = ""
		choice := missingToolDefault(tool, deps.HasStandaloneBuild(tool.Name))
		applyDepsChoice(ctx, cfg.Controller, cfg.DataDir, tool, choice)
	}
	refreshRecordedTools(cfg.DataDir, log.Printf)
	cfg.Tools = applyDependencyChoices(cfg.Tools)
}

func executableFile(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.Mode().IsRegular() && info.Mode()&0o111 != 0
}

// guardInstallPort warns (or, with --install-deps-yes, fails) when the agent's
// listen port is already taken, so the operator notices before the service
// silently fails to bind.
func checkInstallPort(bind string, assumeYes bool) error {
	used, who := portInUse(bind)
	if !used {
		log.Printf("install: listen address %s is free", bind)
		return nil
	}
	detail := ""
	if who != "" {
		detail = " (" + who + ")"
	}
	if assumeYes {
		return fmt.Errorf("listen address %s is already in use%s", bind, detail)
	}
	log.Printf("install: WARNING: listen address %s is already in use%s", bind, detail)
	if !promptYesNo(fmt.Sprintf("port %s is occupied; continue anyway?", bind)) {
		return fmt.Errorf("aborted: %s is in use", bind)
	}
	return nil
}

func isTerminal(file *os.File) bool {
	info, err := file.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0
}

func promptYesNo(question string) bool {
	fmt.Fprintf(os.Stderr, "%s [y/N] ", question)
	line, err := readPromptLine()
	if err != nil && line == "" {
		return false
	}
	switch strings.ToLower(strings.TrimSpace(line)) {
	case "y", "yes":
		return true
	default:
		return false
	}
}

func promptYesNoDefault(question string, defaultYes bool) bool {
	if defaultYes {
		fmt.Fprintf(os.Stderr, "%s [Y/n] ", question)
	} else {
		fmt.Fprintf(os.Stderr, "%s [y/N] ", question)
	}
	line, err := readPromptLine()
	if err != nil && line == "" {
		return defaultYes
	}
	switch strings.ToLower(strings.TrimSpace(line)) {
	case "y", "yes":
		return true
	case "n", "no":
		return false
	default:
		return defaultYes
	}
}

// recordedToolsMap reads agent.json#tools (best-effort).
// depsConfigPath is the agent.json the deps command reads and writes. It is set
// from -c / discovery in main so recorded tools are read/written in the SAME
// file the config was loaded from (using -c must not redirect the tools map to
// a re-discovered agent.json).
var depsConfigPath string

// recordedToolsMap reads agent.json#tools (best-effort) from depsConfigPath.
func recordedToolsMap() map[string]string {
	out := map[string]string{}
	if depsConfigPath == "" {
		return out
	}
	if record := readRawConfig(depsConfigPath); record != nil {
		if raw, ok := record["tools"].(map[string]any); ok {
			for k, v := range raw {
				if s, ok := v.(string); ok {
					out[k] = s
				}
			}
		}
	}
	return out
}

// runDeps implements `hlg-agent deps <check|install|upgrade|builtin|config> [tool...]`.
// install/remove/upgrade/config require root; without it the command re-executes
// through sudo.
func runDeps(ctx context.Context, controller, action string, tools []string, dataDir string, force bool, source, sourcePath string, logf func(string, ...any)) error {
	action = strings.ToLower(strings.TrimSpace(action))
	if action == "" {
		action = "check"
	}
	switch action {
	case "check", "install", "upgrade", "builtin", "config":
	default:
		return fmt.Errorf("unknown deps action %q (want check|install|upgrade|builtin|config)", action)
	}
	if action == "config" {
		return configureDeps(ctx, controller, tools, dataDir, source, sourcePath, logf)
	}
	if action != "check" {
		if err := requireRoot("deps " + action); err != nil {
			return err
		}
	}
	selected, err := selectDepsTools(tools)
	if err != nil {
		return err
	}
	recordedTools := recordedToolsMap()
	if action == "builtin" && len(tools) == 0 {
		return fmt.Errorf("deps builtin requires at least one tool name")
	}
	for _, tool := range selected {
		switch action {
		case "builtin":
			if !deps.IsBuiltin(tool.Name) {
				return fmt.Errorf("%s has no built-in implementation", tool.Name)
			}
			recordChosen(tool.Name, deps.BuiltinMarker)
			logf("deps: %s: using built-in probe", tool.Name)
		case "check":
			ok, detail := deps.Effective(recordedTools, dataDir, tool.Name)
			state := "missing"
			if ok {
				state = "ok"
			}
			logf("deps: %s: %s (%s)", tool.Name, state, detail)
		case "install":
			if err := deps.Install(ctx, controller, dataDir, tool, force, logf); err != nil {
				return err
			}
			recordResolved(dataDir, tool)
		case "upgrade":
			updated, err := deps.Upgrade(ctx, controller, dataDir, tool, logf)
			if err != nil {
				return err
			}
			if !updated {
				logf("deps: %s: no update needed", tool.Name)
			} else {
				recordResolved(dataDir, tool)
			}
		}
	}
	if action != "check" {
		refreshRecordedTools(dataDir, logf)
	}
	return nil
}

// recordResolved pins the tool's current resolved path, or clears it when the
// tool now falls back to a built-in probe / is absent.
func recordResolved(dataDir string, tool deps.Tool) {
	if ok, where := deps.Effective(recordedToolsMap(), dataDir, tool.Name); ok {
		if where == deps.BuiltinMarker {
			recordChosen(tool.Name, deps.BuiltinMarker)
		} else {
			recordChosen(tool.Name, where)
		}
	} else {
		recordChosen(tool.Name, "")
	}
}

// configureDeps implements `deps config`: show every tool with its current
// source, then let the operator change tools by number. Each tool's menu lists
// every available source in full (system / install / built-in probe / download /
// path / do nothing / automatic). `--source` applies one choice to the named
// tools non-interactively.
func configureDeps(ctx context.Context, controller string, tools []string, dataDir, source, sourcePath string, logf func(string, ...any)) error {
	depsConfigChanged = false
	source = strings.ToLower(strings.TrimSpace(source))
	if source != "" && source != "system" && source != "builtin" && source != "download" && source != "path" && source != "install" && source != "nothing" && source != "auto" {
		return fmt.Errorf("unknown --source %q (want system|builtin|download|path|install|nothing|auto)", source)
	}
	if err := requireRoot("deps config"); err != nil {
		return err
	}
	// Seed the working set from agent.json#tools so the list shows the recorded
	// choices, not just what happens to be on PATH.
	seedChosenTools(dataDir)
	selected, err := selectToolsForConfig(tools)
	if err != nil {
		return err
	}

	// Non-interactive (--source given, or a named subset): apply directly.
	if source != "" {
		for _, tool := range selected {
			if err := applyDepsSource(ctx, controller, dataDir, tool, source, sourcePath, logf); err != nil {
				return err
			}
		}
		if depsConfigChanged {
			refreshRecordedTools(dataDir, logf)
		}
		return nil
	}
	if !isTerminal(os.Stdin) {
		log.Printf("deps: no TTY; specify --source to change a source non-interactively")
		return nil
	}

	// Interactive: list the tools with their current source, then edit the
	// chosen one. Loop so several tools can be changed in one session.
	for {
		fmt.Fprintf(os.Stderr, "\nDependencies:\n")
		for i, tool := range selected {
			fmt.Fprintf(os.Stderr, "  %d. %-11s %s\n", i+1, tool.Name, currentSource(ctx, controller, dataDir, tool))
		}
		fmt.Fprintf(os.Stderr, "  %d. done\n", len(selected)+1)
		n := promptIndex(fmt.Sprintf("change (%s)", numberList(len(selected)+1)), len(selected)+1, len(selected)+1)
		if n == len(selected)+1 {
			break
		}
		tool := selected[n-1]
		choice := promptSource(tool, "")
		if err := applyDepsSource(ctx, controller, dataDir, tool, choice, sourcePath, logf); err != nil {
			log.Printf("deps: %s: %v", tool.Name, err)
		}
	}
	if depsConfigChanged {
		refreshRecordedTools(dataDir, logf)
	}
	return nil
}

// seedChosenTools loads agent.json#tools into the working set, then resets it
// after the command so repeated runs in one process re-read the file.
func seedChosenTools(dataDir string) {
	chosenTools = recordedToolsMap()
}

// restartServiceForDeps offers to restart the agent service so a deps source
// change takes effect. It only prompts interactively; non-interactive callers
// just get the reminder.
func restartServiceForDeps(mode, serviceName string, logf func(string, ...any)) {
	logf("deps: restart the agent for the new sources to take effect")
	if !isTerminal(os.Stdin) {
		return
	}
	if !promptYesNo("restart the agent now?") {
		return
	}
	if err := serviceControl(mode, serviceName, "restart"); err != nil {
		logf("deps: restart failed: %v", err)
	}
}

// selectToolsForConfig resolves the tool list, defaulting to every tool.
func selectToolsForConfig(names []string) ([]deps.Tool, error) {
	if len(names) == 0 {
		return deps.All(), nil
	}
	return selectDepsTools(names)
}

// applyDepsSource records the chosen source for a tool (non-interactive path).
func applyDepsSource(ctx context.Context, controller, dataDir string, tool deps.Tool, choice, sourcePath string, logf func(string, ...any)) error {
	switch choice {
	case "auto":
		chosenTools[tool.Name] = ""
		logf("deps: %s: automatic", tool.Name)
	case "system":
		path := deps.SystemPath(tool.Name)
		if path == "" {
			return fmt.Errorf("no system binary found (use automatic, or install it first)")
		}
		chosenTools[tool.Name] = path
		logf("deps: %s: system %s", tool.Name, path)
	case "builtin":
		if !deps.IsBuiltin(tool.Name) {
			return fmt.Errorf("has no built-in implementation")
		}
		chosenTools[tool.Name] = deps.BuiltinMarker
		logf("deps: %s: built-in probe", tool.Name)
	case "install":
		if err := deps.Install(ctx, controller, dataDir, tool, false, logf); err != nil {
			return err
		}
		recordResolved(dataDir, tool)
	case "download":
		if !deps.HasStandaloneBuild(tool.Name) {
			return fmt.Errorf("has no standalone build")
		}
		path, err := deps.InstallDownloaded(ctx, controller, dataDir, tool, false, logf)
		if err != nil {
			return err
		}
		chosenTools[tool.Name] = path
	case "nothing":
		// No-op: preserve the current source and its persisted choice.
		logf("deps: %s: do nothing", tool.Name)
	case "path":
		path := strings.TrimSpace(sourcePath)
		if path == "" {
			path = promptLine(fmt.Sprintf("path to %s binary:", tool.Name))
		}
		if !fileExists(path) {
			return fmt.Errorf("path %q does not exist", path)
		}
		chosenTools[tool.Name] = path
		logf("deps: %s: path %s", tool.Name, path)
	default:
		return fmt.Errorf("unknown source %q", choice)
	}
	if choice != "nothing" {
		depsConfigChanged = true
	}
	return nil
}

// runProbe runs the built-in probe directly, for local testing:
// `hlg-agent probe [-4|-6] <ping|mtr|traceroute> <target>`.
// It needs CAP_NET_RAW (root or setcap), like the running agent.
func runProbe(ctx context.Context, tool, target string, ipv4, ipv6 bool) error {
	tool = strings.ToLower(strings.TrimSpace(tool))
	switch tool {
	case "ping", "mtr", "traceroute":
	default:
		return fmt.Errorf("probe tool must be ping, mtr or traceroute (got %q)", tool)
	}
	if strings.TrimSpace(target) == "" {
		return fmt.Errorf("probe requires a target: hlg-agent probe [-4|-6] %s <host|ip>", tool)
	}
	if ipv4 && ipv6 {
		return fmt.Errorf("-4 and -6 are mutually exclusive")
	}
	family := "ipv4"
	if ipv6 {
		family = "ipv6"
	}
	log.Printf("probe %s %s (%s)", tool, target, family)
	return probe.Run(ctx, tool, target, family, 5, os.Stdout)
}

// refreshRecordedTools updates the tools map in agent.json after a deps change
// so the runtime keeps invoking known paths. It merges the explicit choices into
// the existing map (an "auto" choice clears its entry), leaving untouched tools
// as they were. Best-effort: a missing/unwritable config is logged, never fatal.
func refreshRecordedTools(dataDir string, logf func(string, ...any)) {
	path := depsConfigPath
	if path == "" {
		return
	}
	record := readRawConfig(path)
	if record == nil {
		return
	}
	existing := map[string]string{}
	if raw, ok := record["tools"].(map[string]any); ok {
		for k, v := range raw {
			if s, ok := v.(string); ok {
				existing[k] = s
			}
		}
	}
	record["tools"] = applyDependencyChoices(existing)
	if err := writeJSONFile(path, record); err != nil {
		logf("deps: warning: could not update %s: %v", path, err)
		return
	}
	logf("deps: updated tools map in %s", path)
}

// readRawConfig reads agent.json as a generic map so unknown keys (the install
// record, tools, etc.) are preserved on write.
func readRawConfig(path string) map[string]any {
	body, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var out map[string]any
	if err := json.Unmarshal(body, &out); err != nil {
		return nil
	}
	return out
}

func selectDepsTools(names []string) ([]deps.Tool, error) {
	if len(names) == 0 {
		names = deps.Names()
	}
	seen := map[string]bool{}
	out := make([]deps.Tool, 0, len(names))
	for _, name := range names {
		trimmed := strings.TrimSpace(name)
		if trimmed == "" || seen[trimmed] {
			continue
		}
		tool, err := deps.Lookup(trimmed)
		if err != nil {
			return nil, err
		}
		seen[trimmed] = true
		out = append(out, tool)
	}
	return out, nil
}

// requireRoot ensures the process is privileged, re-executing the whole command
// through sudo when it is not.
func requireRoot(action string) error {
	if os.Geteuid() == 0 {
		return nil
	}
	sudo, err := exec.LookPath("sudo")
	if err != nil {
		return fmt.Errorf("%s requires root and sudo is not available", action)
	}
	exe := executablePath()
	if exe == "" {
		exe = os.Args[0]
	}
	log.Printf("deps: requesting sudo for %s", action)
	cmd := exec.Command(sudo, append([]string{exe}, os.Args[1:]...)...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil {
		return err
	}
	os.Exit(0)
	return nil
}

// isValidListenAddr accepts "", ":443", "0.0.0.0:443", "127.0.0.1:443", or
// "[::]:443". Host is optional; port is required.
func isValidListenAddr(addr string) bool {
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	if port == "" {
		return false
	}
	value, err := strconv.Atoi(port)
	return err == nil && value > 0 && value <= 65535
}

func runtimeArch() string {
	switch goruntime.GOARCH {
	case "amd64":
		return "amd64"
	case "arm64":
		return "arm64"
	default:
		return ""
	}
}

func normalizeServiceMode(mode string, allowAll bool) (string, error) {
	mode = strings.ToLower(strings.TrimSpace(mode))
	if mode == "" || mode == "auto" {
		if allowAll {
			return "all", nil
		}
		return detectServiceMode(), nil
	}
	if allowAll && mode == "all" {
		return mode, nil
	}
	switch mode {
	case "systemd", "init.d", "none":
		return mode, nil
	default:
		return "", fmt.Errorf("unsupported service mode: %s", mode)
	}
}

func normalizeUnitName(value, fallback string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return fallback
	}
	var b strings.Builder
	for _, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' || r == '.' {
			b.WriteRune(r)
		}
	}
	normalized := strings.Trim(b.String(), ".-_")
	if normalized == "" {
		return fallback
	}
	return normalized
}

func detectServiceMode() string {
	if commandExists("systemctl") && fileExists("/run/systemd/system") {
		return "systemd"
	}
	if commandExists("rc-update") || commandExists("rc-service") {
		return "init.d"
	}
	return "none"
}

func installSeedConfig(configFile string) (config.Config, error) {
	if strings.TrimSpace(configFile) == "" {
		return config.Config{}, nil
	}
	return config.Load(config.LoadOptions{File: configFile})
}

func validateServiceUser(serviceUser string) error {
	if serviceUser == "" || serviceUser == "root" {
		return nil
	}
	if _, err := user.Lookup(serviceUser); err != nil {
		return fmt.Errorf("service user %q is unavailable; use --user root or an existing account: %w", serviceUser, err)
	}
	return nil
}

func ensureInstallOwnership(installDir, dataDir, serviceUser string) error {
	if serviceUser == "" || serviceUser == "root" {
		return nil
	}
	account, err := user.Lookup(serviceUser)
	if err != nil {
		return fmt.Errorf("lookup service user %s: %w", serviceUser, err)
	}
	uid, err := strconv.Atoi(account.Uid)
	if err != nil {
		return fmt.Errorf("parse uid for %s: %w", serviceUser, err)
	}
	gid, err := strconv.Atoi(account.Gid)
	if err != nil {
		return fmt.Errorf("parse gid for %s: %w", serviceUser, err)
	}
	for _, path := range []string{installDir, dataDir, filepath.Join(installDir, "agent.json"), filepath.Join(installDir, "bootstrap-input.json")} {
		if !fileExists(path) {
			continue
		}
		if err := os.Chown(path, uid, gid); err != nil {
			return fmt.Errorf("chown %s: %w", path, err)
		}
	}
	return nil
}

// probeURL issues a GET and returns an error on a network failure or a non-2xx
// status. Used by doctor's controller connectivity checks.
func probeURL(rawURL, bearer string, timeout time.Duration) error {
	req, err := http.NewRequest(http.MethodGet, rawURL, nil)
	if err != nil {
		return err
	}
	if bearer != "" {
		req.Header.Set("authorization", "Bearer "+bearer)
	}
	client := &http.Client{Timeout: timeout}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	if resp.StatusCode >= 300 {
		return fmt.Errorf("HTTP %s", resp.Status)
	}
	return nil
}

// checkControllerURL reads the controller from agent.json (best-effort).
func checkControllerURL(configPath string) string {
	if configPath == "" {
		return ""
	}
	if record := readRawConfig(configPath); record != nil {
		if controller, ok := record["controller"].(string); ok {
			return controller
		}
	}
	return ""
}

func commandExists(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func runCommand(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	output, err := cmd.CombinedOutput()
	if err == nil {
		return nil
	}
	trimmed := strings.TrimSpace(string(output))
	if trimmed == "" {
		return fmt.Errorf("%s %s: %w", name, strings.Join(args, " "), err)
	}
	return fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, trimmed)
}

func writeJSONFile(path string, value any) error {
	body, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	body = append(body, '\n')
	return atomicfile.Write(path, body, 0o600)
}

func refreshPublicIPs(ctx context.Context, cfg *config.Config, state *publicIPState) {
	if cfg == nil || state == nil {
		return
	}
	state.applyOverrides(cfg)
	override4, override6 := state.localOverrides()
	if ipv4 := detectPublicIPIfUnconfigured(ctx, override4, "https://api4.ipify.org?format=text"); ipv4 != "" {
		cfg.PublicIPv4 = ipv4
	}
	if ipv6 := detectPublicIPIfUnconfigured(ctx, override6, "https://api6.ipify.org?format=text"); ipv6 != "" {
		cfg.PublicIPv6 = ipv6
	}
	state.set(cfg.PublicIPv4, cfg.PublicIPv6)
}

func detectPublicIPIfUnconfigured(ctx context.Context, override, endpoint string) string {
	if strings.TrimSpace(override) != "" {
		return ""
	}
	return detectPublicIP(ctx, endpoint)
}

func detectPublicIP(ctx context.Context, endpoint string) string {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return ""
	}
	resp, err := publicIPClient.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return ""
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return ""
	}
	ip := strings.TrimSpace(string(body))
	if net.ParseIP(ip) == nil {
		return ""
	}
	return ip
}
