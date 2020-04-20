package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path"
	"path/filepath"
	"strconv"

	bugsnag "github.com/bugsnag/bugsnag-go"
	"github.com/pkg/errors"
	"github.com/xlab/invoker"
	log "github.com/xlab/suplog"

	"github.com/kompose-app/ledger-installer/crypto"
)

type ArtifactLoader interface {
	Load(appName, appVersion string) (ArtifactPayload, error)
}

type ArtifactPayload interface {
	Info() ArtifactSpec
	Install(ctx context.Context, apduIn <-chan string, apduOut chan<- string) error
}

var (
	ErrNotFound  = errors.New("artifact not found")
	ErrManifest  = errors.New("artifact manifest is not correct")
	ErrNoPayload = errors.New("artifact payload missing")
	ErrTimeout   = errors.New("loader timeout")
	ErrInternal  = errors.New("loader internal error")
)

type ArtifactSpec struct {
	Name          string `json:"name"`
	Version       string `json:"version"`
	Icon          string `json:"icon"`
	TargetID      string `json:"targetId"`
	TargetVersion string `json:"targetVersion"`
	AppSignature  string `json:"signature"`
	Flags         string `json:"flags"`

	DerivationPath struct {
		Curves []Curve  `json:"curves"`
		Paths  []string `json:"paths"`
	} `json:"derivationPath"`

	Dependencies []string `json:"deps"`
	Binary       string   `json:"binary"`
	DataSize     int      `json:"dataSize"`
}

type Curve string

const (
	CurveSecp256k1  Curve = "secp256k1"
	CurvePrime256r1 Curve = "prime256r1"
	CurveEd25519    Curve = "ed25519"
)

func NewArtifactLoader(
	installerBin, artifactsPath string,
	signKey, rootKey *ecdsa.PrivateKey,
) (ArtifactLoader, error) {
	workDir, _ := os.Getwd()

	loader := &artifactLoader{
		installerBin:  installerBin,
		artifactsPath: artifactsPath,
		workDir:       workDir,
		signKey:       signKey,
		rootKey:       rootKey,
	}

	return loader, nil
}

type artifactLoader struct {
	installerBin  string
	artifactsPath string
	workDir       string
	signKey       *ecdsa.PrivateKey
	rootKey       *ecdsa.PrivateKey
}

func (a *artifactLoader) Load(appName, appVersion string) (ArtifactPayload, error) {
	appPrefix := path.Join(a.artifactsPath, appName)
	if info, err := os.Stat(appPrefix); err != nil {
		_ = bugsnag.Notify(err)
		return nil, ErrNotFound
	} else if !info.IsDir() {
		_ = bugsnag.Notify(errors.Errorf("not a dir: %s", appPrefix))
		return nil, ErrNotFound
	}

	appVersionPath := path.Join(appPrefix, appVersion)
	if _, err := os.Stat(appPrefix); err != nil {
		_ = bugsnag.Notify(err)
		return nil, errors.Errorf("could not find app version: %s", appVersion)
	}

	var spec ArtifactSpec

	manifest, err := ioutil.ReadFile(filepath.Join(appVersionPath, "manifest.json"))
	if err != nil {
		_ = bugsnag.Notify(err)
		return nil, ErrManifest
	} else if err = json.Unmarshal(manifest, &spec); err != nil {
		_ = bugsnag.Notify(err)
		return nil, ErrManifest
	}

	payload := &artifactPayload{
		loader:         a,
		appName:        appName,
		appVersion:     appVersion,
		appVersionPath: appVersionPath,

		logger: log.WithFields(log.Fields{
			"app": appName,
			"ver": appVersion,
		}),

		spec:    spec,
		invoker: invoker.NewInvoker(a.installerBin, a.workDir),
	}

	return payload, nil
}

type artifactPayload struct {
	loader         *artifactLoader
	appName        string
	appVersion     string
	appVersionPath string

	spec    ArtifactSpec
	logger  log.Logger
	invoker invoker.Invoker
}

func (a *artifactPayload) Info() ArtifactSpec {
	return a.spec
}

func (a *artifactPayload) Install(ctx context.Context, apduIn <-chan string, apduOut chan<- string) error {
	defer close(apduOut)

	loggerFn := a.msgLogger(a.spec.Name, a.spec.Version)

	stdOut := invoker.NewWatchedSafeBuffer(ctx, bufferToChan(apduOut), nil)
	stdErr := invoker.NewWatchedSafeBuffer(ctx, loggerFn, nil)

	out := a.invoker.RunWithIO(ctx, chanReader(apduIn), stdOut, stdErr, a.Args()...)
	defer func() {
		go invoker.DrainOut(out)
	}()

	select {
	case <-ctx.Done():
		return ErrTimeout
	case result, ok := <-out:
		if !ok {
			return ErrTimeout
		}

		defer result.Discard()

		if !result.Success {
			if result.Error != nil {
				err := errors.Wrap(result.Error, "failed to invoke installer")
				_ = bugsnag.Notify(err, a.MetaData())
				return ErrInternal
			}

			if len(result.StdErr()) > 0 {
				err := errors.New(string(result.StdErr()))
				err = errors.Wrap(result.Error, "installer crashed")
				_ = bugsnag.Notify(err, a.MetaData())
				return ErrInternal
			}

			err := errors.New("installer crashed")
			_ = bugsnag.Notify(err, a.MetaData())
			return ErrInternal
		}

		return nil
	}
}

func chanReader(chanIn <-chan string) io.Reader {
	return &chanReaderAdapter{
		chanIn: chanIn,
		buf:    new(bytes.Buffer),
	}
}

type chanReaderAdapter struct {
	chanIn <-chan string
	buf    *bytes.Buffer
}

func (c *chanReaderAdapter) Read(p []byte) (n int, err error) {
	if c.buf.Len() > 0 {
		return c.buf.Read(p)
	}

	select {
	case str, ok := <-c.chanIn:
		if !ok {
			return 0, io.EOF
		}
		c.buf.WriteString(str)
	}

	return c.buf.Read(p)
}

func bufferToChan(apduOut chan<- string) func(msg []byte) (stop bool) {
	return func(msg []byte) (stop bool) {
		fmt.Println("I see", string(msg), "in stdout!")
		apduOut <- string(msg)
		return
	}
}

func (a *artifactPayload) msgLogger(appName, appVersion string) func(msg []byte) (stop bool) {
	return func(msg []byte) (stop bool) {
		fmt.Print(string(msg))

		a.logger.WithFields(log.Fields{
			"module": "ledgerInstaller.py",
		}).Infoln(string(msg))

		return
	}
}

func (a *artifactPayload) MetaData() bugsnag.MetaData {
	metaData := make(bugsnag.MetaData)

	metaData.Add("Payload", "appName", a.appName)
	metaData.Add("Payload", "appVersion", a.appVersion)
	metaData.Add("Payload", "appVersionPath", a.appVersionPath)
	metaData.Add("Env", "installerBin", a.loader.installerBin)
	metaData.Add("Env", "artifactsPath", a.loader.artifactsPath)
	metaData.Add("Env", "workDir", a.loader.workDir)
	metaData.AddStruct("Artifact", a.spec)

	return metaData
}

func (a *artifactPayload) Args() []string {
	args := []string{
		"--delete", "--tlv",
		"--targetId", a.spec.TargetID,
		"--targetVersion", a.spec.TargetVersion,
		"--fileName", filepath.Join(a.appVersionPath, "bin/app.hex"),
		"--appName", a.spec.Name,
		"--appVersion", a.spec.Version,
		"--dataSize", strconv.Itoa(a.spec.DataSize),
		"--icon", a.spec.Icon,
		"--appFlags", a.spec.Flags,
	}

	for _, curve := range a.spec.DerivationPath.Curves {
		args = append(args, "--curve", string(curve))
	}

	for _, path := range a.spec.DerivationPath.Paths {
		args = append(args, "--path", path)
	}

	for _, dep := range a.spec.Dependencies {
		args = append(args, "--dep", dep)
	}

	// if a.loader.signKey != nil {
	// 	keyHex := hex.EncodeToString(crypto.FromECDSA(a.loader.signKey))
	// 	args = append(args, "--signPrivateKey", keyHex)
	// }

	if a.loader.rootKey != nil {
		keyHex := hex.EncodeToString(crypto.FromECDSA(a.loader.rootKey))
		args = append(args, "--rootPrivateKey", keyHex)
	}

	log.Println("FULL ARGS:", args)

	return args
}
