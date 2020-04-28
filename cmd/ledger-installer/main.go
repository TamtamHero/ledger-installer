package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"encoding/hex"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/bugsnag/bugsnag-go"
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
	cli "github.com/jawher/mow.cli"
	"github.com/pkg/errors"
	"github.com/xlab/closer"
	log "github.com/xlab/suplog"

	"github.com/kompose-app/ledger-installer/crypto"
)

var app = cli.App("ledger-installer", "Ledger Apps Installer Server")

func main() {
	app.Before = prepareApp
	app.Action = runApp
	_ = app.Run(os.Args)
}

func prepareApp() {
	log.DefaultLogger.SetLevel(logLevel(*appLogLevel))

	if *envName == "prod" {
		gin.SetMode(gin.ReleaseMode)
	}

	bugsnag.Configure(bugsnag.Configuration{
		APIKey:       *bugsnagKey,
		ReleaseStage: *envName,
		NotifyReleaseStages: []string{
			"dev", "prod",
		},
		ProjectPackages: []string{
			"github.com/kompose-app/ledger-installer*",
		},
		PanicHandler: func() {},
	})
}

func runApp() {
	defer closer.Close()

	signKey, rootKey, _ := loadOrGeneratePrivateKeys()

	loader, err := NewArtifactLoader(*appInstallerPath, *appArtifactsPath, signKey, rootKey)
	if err != nil {
		_ = bugsnag.Notify(err)
		err = errors.Wrap(err, "failed to init artifact loader")
		log.Fatalln(err)
	}

	r := gin.Default()

	r.Use(cors.New(cors.Config{
		AllowOrigins:  []string{"*"},
		AllowMethods:  []string{"GET", "POST"},
		AllowHeaders:  []string{"Origin", "Accept", "Content-Type", "Content-Length", "Accept-Encoding", "X-CSRF-Token"},
		ExposeHeaders: []string{"Content-Type", "Content-Length"},
		MaxAge:        12 * time.Hour,
	}))

	r.GET("/api/v1/appInfo/:name/:version", func(c *gin.Context) {
		appName := c.Param("name")
		if len(appName) == 0 {
			c.AbortWithError(400, errors.New("missing app name parameter"))
			return
		} else if !validateAppName(appName) {
			c.AbortWithError(400, errors.New("incorrect name, expected [a-zA-Z0-9_-]+"))
			return
		}

		appVersion := c.Param("version")
		if len(appVersion) == 0 {
			appVersion = "latest"
		} else if !validateAppVersion(appName) {
			c.AbortWithError(400, errors.New("incorrect version, expected [a-zA-Z0-9_-.]+ or semver"))
			return
		}

		payload, err := loader.Load(appName, appVersion)
		if err != nil {
			if err == ErrNotFound || err == ErrManifest || err == ErrNoPayload {
				c.AbortWithError(404, err)
				return
			}
		}

		c.JSON(200, payload.Info())
	})

	r.POST("/api/v1/appInstall/:name/:version", func(c *gin.Context) {
		appName := c.Param("name")
		if len(appName) == 0 {
			c.AbortWithError(400, errors.New("missing app name parameter"))
		} else if !validateAppName(appName) {
			c.AbortWithError(400, errors.New("incorrect name, expected [a-zA-Z0-9_-]+"))
			return
		}

		appVersion := c.Param("version")
		if len(appVersion) == 0 {
			appVersion = "latest"
		} else if !validateAppVersion(appName) {
			c.AbortWithError(400, errors.New("incorrect version, expected [a-zA-Z0-9_-.]+ or semver"))
			return
		}

		payload, err := loader.Load(appName, appVersion)
		if err != nil {
			if err == ErrNotFound || err == ErrManifest || err == ErrNoPayload {
				c.AbortWithError(404, err)
				return
			}
		}

		apduIn, apduOut := make(chan string), make(chan string)
		go wrapBodyToChannels(c.Copy(), c.Writer, c.Request.Body, apduIn, apduOut)

		if err := payload.Install(c.Copy(), apduIn, apduOut); err != nil {
			c.AbortWithError(500, ErrInternal)
			return
		}

		c.Status(200)
	})

	r.GET("/apiws/v1/appInstall/:name/:version", func(c *gin.Context) {
		appName := c.Param("name")
		if len(appName) == 0 {
			c.AbortWithError(400, errors.New("missing app name parameter"))
		} else if !validateAppName(appName) {
			c.AbortWithError(400, errors.New("incorrect name, expected [a-zA-Z0-9_-]+"))
			return
		}

		appVersion := c.Param("version")
		if len(appVersion) == 0 {
			appVersion = "latest"
		} else if !validateAppVersion(appName) {
			c.AbortWithError(400, errors.New("incorrect version, expected [a-zA-Z0-9_-.]+ or semver"))
			return
		}

		payload, err := loader.Load(appName, appVersion)
		if err != nil {
			if err == ErrNotFound || err == ErrManifest || err == ErrNoPayload {
				c.AbortWithError(404, err)
				return
			}
		}

		wshandler(c.Copy(), c.Writer, c.Request, payload)
	})

	r.Run()
}

func wshandler(ctx context.Context, w http.ResponseWriter, r *http.Request, payload ArtifactPayload) error {
	var wsupgrader = websocket.Upgrader{
		ReadBufferSize:  1024,
		WriteBufferSize: 1024,
		CheckOrigin: func(r *http.Request) bool {
			return true
		},
	}

	ws, err := wsupgrader.Upgrade(w, r, nil)
	if err != nil {
		err = errors.Wrap(err, "failed to perform Websocket upgrade")
		_ = bugsnag.Notify(err)
		return err
	}

	apduIn, apduOut := make(chan string), make(chan string)

	commCtx, cancelFn := context.WithCancel(ctx)
	defer cancelFn()

	go wrapWebsocketToChannels(commCtx, ws, apduIn, apduOut)

	_ = payload.Install(ctx, apduIn, apduOut)

	return nil
}

const (
	// Time allowed to write a message to the peer.
	writeWait = 10 * time.Second

	// Maximum message size allowed from peer.
	maxMessageSize = 256 * 2

	// Time allowed to read the next pong message from the peer.
	pongWait = 60 * time.Second

	// Send pings to peer with this period. Must be less than pongWait.
	pingPeriod = (pongWait * 9) / 10

	// Time to wait before force close on connection.
	closeGracePeriod = 10 * time.Second
)

func pingWebsocket(ctx context.Context, ws *websocket.Conn) {
	ticker := time.NewTicker(pingPeriod)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			if err := ws.WriteControl(websocket.PingMessage, []byte{}, time.Now().Add(writeWait)); err != nil {
				log.WithError(err).Warningln("websocket ping error")
			}
		case <-ctx.Done():
			return
		}
	}
}

func internalErrorWebsocket(ws *websocket.Conn, err error) {
	ws.WriteMessage(websocket.TextMessage, []byte("Internal server error. "+err.Error()))
}

func wrapWebsocketToChannels(
	ctx context.Context,
	ws *websocket.Conn,
	apduIn chan<- string,
	apduOut <-chan string,
) {
	ws.SetReadLimit(maxMessageSize)
	ws.SetReadDeadline(time.Now().Add(pongWait))
	ws.SetPongHandler(func(string) error {
		ws.SetReadDeadline(time.Now().Add(pongWait))
		return nil
	})

	pingCtx, pingCancelFn := context.WithCancel(ctx)
	go pingWebsocket(pingCtx, ws)

	closeFn := func() {
		pingCancelFn()
		ws.SetWriteDeadline(time.Now().Add(writeWait))
		ws.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""))
		time.Sleep(closeGracePeriod)
		ws.Close()
	}

	go func() {
		for {
			select {
			case <-ctx.Done():
				closeFn()
				return
			case apdu, ok := <-apduOut:
				if !ok {
					closeFn()
					return
				}

				log.Println("<=", apdu)

				ws.SetWriteDeadline(time.Now().Add(writeWait))
				if err := ws.WriteMessage(websocket.TextMessage, []byte(apdu)); err != nil {
					err = errors.Wrap(err, "websocket write deadline")
					_ = bugsnag.Notify(err)
					pingCancelFn()
					ws.Close()
					return
				}
			}
		}
	}()

	go func() {
		for {
			select {
			case <-ctx.Done():
				close(apduIn)
				return
			default:
				_, data, err := ws.ReadMessage()
				if err != nil {
					log.Errorln(err)
					close(apduIn)
					return
				} else if len(data) == 0 {
					time.Sleep(500 * time.Millisecond)
					continue
				}

				apdu := string(data)
				log.Println("=>", apdu)

				apduIn <- apdu + "\n"
			}
		}
	}()
}

func wrapBodyToChannels(
	ctx context.Context,
	wr gin.ResponseWriter,
	r io.ReadCloser,
	apduIn chan<- string,
	apduOut <-chan string,
) {
	for {
		select {
		case <-ctx.Done():
			close(apduIn)
			r.Close()
			return
		case apdu, ok := <-apduOut:
			if !ok {
				close(apduIn)
				r.Close()
				return
			}

			log.Println("<=", apdu)

			_, _ = wr.Write(append([]byte(apdu), '\n'))
			wr.Flush()
		default:
			const maxBufSize = 256 * 2
			buf := bytes.NewBuffer(make([]byte, maxBufSize))
			n, _ := io.CopyN(buf, r, maxBufSize)

			if n == maxBufSize {
				// discard the rest in case of possible overflow
				_, _ = io.Copy(ioutil.Discard, r)
			} else if n == 0 {
				time.Sleep(500 * time.Millisecond)
				continue
			}

			apdu := string(buf.Bytes()[:n])
			log.Println("=>", apdu)

			apduIn <- apdu
		}
	}
}

func loadOrGeneratePrivateKeys() (signKey, rootKey *ecdsa.PrivateKey, err error) {
	if len(*appSignKeyHex) == 0 {
		if signKey, err = crypto.GenerateKey(); err != nil {
			_ = bugsnag.Notify(err)
			log.WithError(err).Fatalln("no private key for app signing, failed to generate one")
			return
		}

		log.WithFields(log.Fields{
			"priv": hex.EncodeToString(crypto.FromECDSA(signKey)),
			"pub":  hex.EncodeToString(crypto.FromECDSAPub(&signKey.PublicKey)),
		}).Infoln("generated app signing privkey")
	} else {
		if signKey, err = crypto.HexToECDSA(*appSignKeyHex); err != nil {
			_ = bugsnag.Notify(err)
			log.WithError(err).Fatalln("failed to load app signing private key")
			return
		}

		log.WithFields(log.Fields{
			"pub": hex.EncodeToString(crypto.FromECDSAPub(&signKey.PublicKey)),
		}).Infoln("loaded app signing key")
	}

	if len(*appRootKeyHex) == 0 {
		if rootKey, err = crypto.GenerateKey(); err != nil {
			_ = bugsnag.Notify(err)
			log.WithError(err).Fatalln("no private key for SCP encryption, failed to generate one")
			return
		}

		log.WithFields(log.Fields{
			"priv": hex.EncodeToString(crypto.FromECDSA(rootKey)),
			"pub":  hex.EncodeToString(crypto.FromECDSAPub(&rootKey.PublicKey)),
		}).Infoln("generated root SCP privkey")
	} else {
		if rootKey, err = crypto.HexToECDSA(*appRootKeyHex); err != nil {
			_ = bugsnag.Notify(err)
			log.WithError(err).Fatalln("failed to load root SCP private key")
			return
		}

		log.WithFields(log.Fields{
			"pub": hex.EncodeToString(crypto.FromECDSAPub(&rootKey.PublicKey)),
		}).Infoln("loaded root SCP key")
	}

	return signKey, rootKey, nil
}

var appNameRx = regexp.MustCompile(`[a-zA-Z0-9_\-]+`)

func validateAppName(name string) bool {
	if name == "." || strings.Contains(name, "..") {
		return false
	}

	return appNameRx.MatchString(name)
}

var appVersionRx = regexp.MustCompile(`[a-zA-Z0-9_.\-]+`)

func validateAppVersion(version string) bool {
	if version == "." || strings.Contains(version, "..") {
		return false
	}

	return appVersionRx.MatchString(version)
}
