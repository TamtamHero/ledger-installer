package main

import (
	"strings"
	"time"

	cli "github.com/jawher/mow.cli"
	log "github.com/xlab/suplog"
)

var (
	envName = app.String(cli.StringOpt{
		Name:   "env",
		Desc:   "Application environment",
		EnvVar: "APP_ENV",
		Value:  "local",
	})

	appLogLevel = app.String(cli.StringOpt{
		Name:   "L log-level",
		Desc:   "Available levels: error, warn, info, debug.",
		EnvVar: "APP_LOG_LEVEL",
		Value:  "info",
	})

	appInstallerPath = app.String(cli.StringOpt{
		Name:   "I installer",
		Desc:   "Path to a Python program implemeting installer.",
		EnvVar: "APP_INSTALLER_PATH",
		Value:  "app/ledgerInstaller.py",
	})

	appArtifactsPath = app.String(cli.StringOpt{
		Name:   "A artifacts",
		Desc:   "Path to Ledger artifacts prefix dir.",
		EnvVar: "APP_ARTIFACTS_PATH",
		Value:  "example/artifacts",
	})

	appSignKeyHex = app.String(cli.StringOpt{
		Name:   "S sign-key",
		Desc:   "Provide an app signing private key.",
		EnvVar: "APP_SIGN_KEY",
		Value:  "",
	})

	appRootKeyHex = app.String(cli.StringOpt{
		Name:   "R root-key",
		Desc:   "Provide a private key to establish SCP secure connection.",
		EnvVar: "APP_ROOT_KEY",
		Value:  "",
	})

	bugsnagKey = app.String(cli.StringOpt{
		Name:   "bugsnag-key",
		Desc:   "Bugsnag API key for error reporing",
		EnvVar: "APP_BUGSNAG_KEY",
		Value:  "",
	})

	httpListenAddr = app.String(cli.StringOpt{
		Name:   "http-listen-addr",
		Desc:   "HTTP server listening address",
		EnvVar: "HTTP_LISTEN_ADDR",
		Value:  "localhost:8080",
	})
)

// StatsD configuration.
var (
	statsdPrefix = app.String(cli.StringOpt{
		Name:   "statsd-prefix",
		Desc:   "Specify StatsD compatible metrics prefix.",
		EnvVar: "STATSD_PREFIX",
		Value:  "kusd.api",
	})
	statsdAddr = app.String(cli.StringOpt{
		Name:   "statsd-addr",
		Desc:   "UDP address of a StatsD compatible metrics aggregator.",
		EnvVar: "STATSD_ADDR",
		Value:  "localhost:8125",
	})
	statsdStuckDur = app.String(cli.StringOpt{
		Name:   "statsd-stuck-func",
		Desc:   "Sets a duration to consider a function to be stuck (e.g. in deadlock).",
		EnvVar: "STATSD_STUCK_DUR",
		Value:  "30m",
	})
	statsdMocking = app.String(cli.StringOpt{
		Name:   "statsd-mocking",
		Desc:   "If enabled replaces statsd client with a mock one that simply logs values.",
		EnvVar: "STATSD_MOCKING",
		Value:  "false",
	})
	statsdDisabled = app.String(cli.StringOpt{
		Name:   "statsd-disabled",
		Desc:   "Force disabling statsd reporting completely.",
		EnvVar: "STATSD_DISABLED",
		Value:  "true",
	})
)

func toBool(s string) bool {
	switch strings.ToLower(s) {
	case "true", "1", "t", "yes":
		return true
	default:
		return false
	}
}

func duration(s string, defaults time.Duration) time.Duration {
	dur, err := time.ParseDuration(s)
	if err != nil {
		dur = defaults
	}
	return dur
}

func checkStatsdPrefix(s string) string {
	if !strings.HasSuffix(s, ".") {
		return s + "."
	}
	return s
}

func logLevel(s string) log.Level {
	switch s {
	case "1", "error":
		return log.ErrorLevel
	case "2", "warn":
		return log.WarnLevel
	case "3", "info":
		return log.InfoLevel
	case "4", "debug":
		return log.DebugLevel
	default:
		return log.FatalLevel
	}
}
