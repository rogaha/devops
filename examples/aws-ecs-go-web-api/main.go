package main

import (
	"crypto/tls"
	"encoding/json"
	"expvar"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/ec2metadata"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/go-redis/redis"
	"github.com/jmoiron/sqlx"
	"github.com/kelseyhightower/envconfig"
	_ "github.com/lib/pq"
	"github.com/pkg/errors"
	"gitlab.com/geeks-accelerator/oss/devops/pkg/devdeploy"
	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
)

// build is the git version of this program. It is set using build flags in the makefile.
var build = "develop"

// service is the name of the program used for logging, tracing, etc.
var service = "WEB_API"

func main() {

	// =========================================================================
	// Logging
	log.SetFlags(log.LstdFlags | log.Lmicroseconds | log.Lshortfile)
	log.SetPrefix(service + " : ")
	log := log.New(os.Stdout, log.Prefix(), log.Flags())

	// Print the build version for our logs. Also expose it under /debug/vars.
	expvar.NewString("build").Set(build)
	log.Printf("main : Started : Service Initializing version %q", build)
	defer log.Println("main : Completed")

	// =========================================================================
	// Configuration
	// Use environment variables to configure service. Used defined envconfig value for the key or prefix the key with
	// the service name, ie. WEB_API_AWS_AWS_ACCESS_KEY_ID or AWS_ACCESS_KEY_ID
	var cfg struct {
		Env     string `default:"dev" envconfig:"ENV"`
		Service struct {
			Name        string   `default:"web-api" envconfig:"SERVICE_NAME"`
			Project     string   `default:"" envconfig:"PROJECT_NAME"`
			BaseUrl     string   `default:"" envconfig:"BASE_URL"  example:"http://api.example.saasstartupkit.com"`
			HostNames   []string `envconfig:"HOST_NAMES" example:"alternative-subdomain.example.saasstartupkit.com"`
			Host        string   `default:"0.0.0.0:4000" envconfig:"HOST"`
			EnableHTTPS bool     `default:"false" envconfig:"ENABLE_HTTPS"`
			HTTPSHost   string   `default:"" envconfig:"HTTPS_HOST"`
			StaticFiles struct {
				Dir               string `default:"./static" envconfig:"STATIC_DIR"`
				S3Enabled         bool   `envconfig:"S3_ENABLED"`
				S3Prefix          string `default:"public/web_app/static" envconfig:"S3_PREFIX"`
				CloudFrontEnabled bool   `envconfig:"CLOUDFRONT_ENABLED"`
			}
		}
		Redis struct {
			Host        string        `default:":6379" envconfig:"HOST"`
			DB          int           `default:"1" envconfig:"DB"`
			DialTimeout time.Duration `default:"5s" envconfig:"DIAL_TIMEOUT"`
		}
		DB struct {
			Host       string `default:"127.0.0.1:5433" envconfig:"HOST"`
			User       string `default:"postgres" envconfig:"USERNAME"`
			Pass       string `default:"postgres" envconfig:"PASSWORD" json:"-"` // don't print
			Database   string `default:"shared" envconfig:"DATABASE"`
			Driver     string `default:"postgres" envconfig:"DRIVER"`
			Timezone   string `default:"utc" envconfig:"TIMEZONE"`
			DisableTLS bool   `default:"true" envconfig:"DISABLE_TLS"`
		}
		Aws struct {
			AccessKeyID                string `envconfig:"AWS_ACCESS_KEY_ID"`
			SecretAccessKey            string `envconfig:"AWS_SECRET_ACCESS_KEY" json:"-"` // don't print
			Region                     string `default:"us-west-2" envconfig:"AWS_DEFAULT_REGION"`
			S3BucketPrivate            string `envconfig:"S3_BUCKET_PRIVATE"`
			S3BucketPublic             string `envconfig:"S3_BUCKET_PUBLIC"`
			SecretsManagerConfigPrefix string `default:"" envconfig:"SECRETS_MANAGER_CONFIG_PREFIX"`

			// Get an AWS session from an implicit source if no explicit
			// configuration is provided. This is useful for taking advantage of
			// EC2/ECS instance roles.
			UseRole bool `envconfig:"AWS_USE_ROLE"`
		}
		BuildInfo struct {
			CiCommitRefName  string `envconfig:"CI_COMMIT_REF_NAME"`
			CiCommitShortSha string `envconfig:"CI_COMMIT_SHORT_SHA"`
			CiCommitSha      string `envconfig:"CI_COMMIT_SHA"`
			CiCommitTag      string `envconfig:"CI_COMMIT_TAG"`
			CiJobId          string `envconfig:"CI_JOB_ID"`
			CiJobUrl         string `envconfig:"CI_JOB_URL"`
			CiPipelineId     string `envconfig:"CI_PIPELINE_ID"`
			CiPipelineUrl    string `envconfig:"CI_PIPELINE_URL"`
		}
	}

	// For additional details refer to https://github.com/kelseyhightower/envconfig
	if err := envconfig.Process(service, &cfg); err != nil {
		log.Fatalf("main : Parsing Config : %+v", err)
	}

	// AWS access keys are required, if roles are enabled, remove any placeholders.
	if cfg.Aws.UseRole {
		cfg.Aws.AccessKeyID = ""
		cfg.Aws.SecretAccessKey = ""

		// Get an AWS session from an implicit source if no explicit
		// configuration is provided. This is useful for taking advantage of
		// EC2/ECS instance roles.
		if cfg.Aws.Region == "" {
			sess := session.Must(session.NewSession())
			md := ec2metadata.New(sess)

			var err error
			cfg.Aws.Region, err = md.Region()
			if err != nil {
				log.Fatalf("main : Load region of ecs metadata : %+v", err)
			}
		}
	}

	// Set the default AWS Secrets Manager prefix used for name to store config files that will be persisted across
	// deployments and distributed to each instance of the service running.
	if cfg.Aws.SecretsManagerConfigPrefix == "" {
		var pts []string
		if cfg.Service.Project != "" {
			pts = append(pts, cfg.Service.Project)
		}
		pts = append(pts, cfg.Env)

		cfg.Aws.SecretsManagerConfigPrefix = filepath.Join(pts...)
	}

	// Print the config for our logs. It's important to any credentials in the config
	// that could expose a security risk are excluded from being json encoded by
	// applying the tag `json:"-"` to the struct var.
	{
		cfgJSON, err := json.MarshalIndent(cfg, "", "    ")
		if err != nil {
			log.Fatalf("main : Marshalling Config to JSON : %+v", err)
		}
		log.Printf("main : Config : %v\n", string(cfgJSON))
	}

	// =========================================================================
	// Init AWS Session
	var awsSession *session.Session
	if cfg.Aws.UseRole {
		// Get an AWS session from an implicit source if no explicit
		// configuration is provided. This is useful for taking advantage of
		// EC2/ECS instance roles.
		awsSession = session.Must(session.NewSession())
		if cfg.Aws.Region != "" {
			awsSession.Config.WithRegion(cfg.Aws.Region)
		}

		log.Printf("main : AWS : Using role.\n")

	} else if cfg.Aws.AccessKeyID != "" {
		creds := credentials.NewStaticCredentials(cfg.Aws.AccessKeyID, cfg.Aws.SecretAccessKey, "")
		awsSession = session.New(&aws.Config{Region: aws.String(cfg.Aws.Region), Credentials: creds})

		log.Printf("main : AWS : Using static credentials\n")
	}

	// =========================================================================
	// Start Database
	var dbUrl url.URL
	{
		// Query parameters.
		var q url.Values = make(map[string][]string)

		// Handle SSL Mode
		if cfg.DB.DisableTLS {
			q.Set("sslmode", "disable")
		} else {
			q.Set("sslmode", "require")
		}

		q.Set("timezone", cfg.DB.Timezone)

		// Construct url.
		dbUrl = url.URL{
			Scheme:   cfg.DB.Driver,
			User:     url.UserPassword(cfg.DB.User, cfg.DB.Pass),
			Host:     cfg.DB.Host,
			Path:     cfg.DB.Database,
			RawQuery: q.Encode(),
		}
	}

	masterDb, err := sqlx.Open(cfg.DB.Driver, dbUrl.String())
	if err != nil {
		log.Fatalf("main : Register DB : %s : %+v", cfg.DB.Driver, err)
	}
	defer masterDb.Close()

	// =========================================================================
	// Start Redis if enabled
	var redisClient *redis.Client
	if cfg.Redis.Host != "-" {
		log.Println("main : Started : Initialize Redis")
		redisClient = redis.NewClient(&redis.Options{
			Addr:        cfg.Redis.Host,
			DB:          cfg.Redis.DB,
			DialTimeout: cfg.Redis.DialTimeout,
		})
		defer redisClient.Close()

		if err := redisClient.Ping().Err(); err != nil {
			log.Fatalf("main : Ping Redis : %+v", err)
		}
	}

	// =========================================================================
	// URL Formatter

	// s3UrlFormatter is a help function used by to convert an relative static file path to publicly available URL.
	var staticUrlFormatter func(string) string
	if cfg.Service.StaticFiles.S3Enabled || cfg.Service.StaticFiles.CloudFrontEnabled {
		s3UrlFormatter, err := devdeploy.S3UrlFormatter(awsSession, cfg.Aws.S3BucketPublic, cfg.Service.StaticFiles.S3Prefix, cfg.Service.StaticFiles.CloudFrontEnabled)
		if err != nil {
			log.Fatalf("main : S3UrlFormatter failed : %+v", err)
		}

		staticUrlFormatter = func(p string) string {
			// When the path starts with a forward slash its referencing a local file,
			// make sure the static file prefix is included
			if strings.HasPrefix(p, "/") || !strings.HasPrefix(p, "://") {
				p = filepath.Join(cfg.Service.StaticFiles.S3Prefix, p)
			}
			return s3UrlFormatter(p)
		}
	} else {
		staticUrlFormatter = func(p string) string {
			return p
		}
	}

	// =========================================================================
	// Main Handler
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {

		// Serve the file from the local file system.
		if strings.TrimPrefix(r.RequestURI, "/") != "" {
			fp := filepath.Join(cfg.Service.StaticFiles.Dir, r.RequestURI)
			http.ServeFile(w, r, fp)
			return
		}

		w.Header().Set("Content-Type", "text/html")

		fmt.Fprintf(w, "Welcome to the example web API!\n<br/>")

		if err := testDbConn(masterDb); err != nil {
			fmt.Fprintf(w, "Database connection: %s\n<br/>", err)
		} else {
			fmt.Fprintf(w, "Database connection: ok\n<br/>")
		}

		if redisClient != nil {
			if err := testRedisConn(redisClient); err != nil {
				fmt.Fprintf(w, "Redis connection: %s\n<br/>", err)
			} else {
				fmt.Fprintf(w, "Redis connection: ok\n<br/>")
			}
		}

		fmt.Fprintf(w, "CI_COMMIT_REF_NAME: %s\n<br/>", os.Getenv("CI_COMMIT_REF_NAME"))
		fmt.Fprintf(w, "CI_COMMIT_SHORT_SHA: %s\n<br/>", os.Getenv("CI_COMMIT_SHORT_SHA"))
		fmt.Fprintf(w, "CI_COMMIT_SHA: %s\n<br/>", os.Getenv("CI_COMMIT_SHA"))
		fmt.Fprintf(w, "CI_COMMIT_TAG: %s\n<br/>", os.Getenv("CI_COMMIT_TAG"))
		fmt.Fprintf(w, "CI_JOB_ID: <a href=\"%s\">%s</a>\n<br/>", os.Getenv("CI_JOB_URL"), os.Getenv("CI_JOB_ID"))
		fmt.Fprintf(w, "CI_PIPELINE_ID: <a href=\"%s\">%s</a>\n<br/>", os.Getenv("CI_PIPELINE_URL"), os.Getenv("CI_PIPELINE_ID"))

		fmt.Fprintf(w, "<img src=\"%s\">", staticUrlFormatter("dancing_gopher1.gif"))
		fmt.Fprintf(w, "<img src=\"%s\">", staticUrlFormatter("dancing_gopher2.gif"))
	})

	// =========================================================================
	// ECS Task registration for services that don't use an AWS Elastic Load Balancer.
	err = devdeploy.EcsServiceTaskInit(log, awsSession)
	if err != nil {
		log.Fatalf("main : Ecs Service Task init : %+v", err)
	}

	// =========================================================================
	// Start APP Service

	// Make a channel to listen for an interrupt or terminate signal from the OS.
	// Use a buffered channel because the signal package requires it.
	shutdown := make(chan os.Signal, 1)
	signal.Notify(shutdown, os.Interrupt, syscall.SIGTERM)

	// Make a channel to listen for errors coming from the listener. Use a
	// buffered channel so the goroutine can exit if we don't collect this error.
	serverErrors := make(chan error, 1)

	go func() {
		log.Printf("main : API Listening %s", cfg.Service.Host)
		serverErrors <- http.ListenAndServe(cfg.Service.Host, nil)
	}()

	// Start the HTTPS service listening for requests with an SSL Cert auto generated with Let's Encrypt.
	if cfg.Service.HTTPSHost != "" {

		// Determine the primary host by parsing host from the base app URL.
		baseSiteUrl, err := url.Parse(cfg.Service.BaseUrl)
		if err != nil {
			log.Fatalf("main : Parse service base URL : %s : %+v", cfg.Service.BaseUrl, err)
		}

		// Drop any ports from the base app URL.
		var primaryHostname string
		if strings.Contains(baseSiteUrl.Host, ":") {
			primaryHostname, _, err = net.SplitHostPort(baseSiteUrl.Host)
			if err != nil {
				log.Fatalf("main : SplitHostPort : %s : %+v", baseSiteUrl.Host, err)
			}
		} else {
			primaryHostname = baseSiteUrl.Host
		}

		// Generate a unique list of hostnames.
		var hosts = []string{primaryHostname}
		for _, h := range cfg.Service.HostNames {
			h = strings.TrimSpace(h)
			if h != "" && h != primaryHostname {
				hosts = append(hosts, h)
			}
		}

		// Enable autocert to store certs via Secret Manager.
		secretPrefix := filepath.Join(cfg.Aws.SecretsManagerConfigPrefix, "autocert")

		// Local file cache to reduce requests hitting Secret Manager.
		localCache := autocert.DirCache(os.TempDir())

		cache, err := devdeploy.NewSecretManagerAutocertCache(log, awsSession, secretPrefix, localCache)
		if err != nil {
			log.Fatalf("main : HTTPS : %+v", err)
		}

		m := &autocert.Manager{
			Prompt:     autocert.AcceptTOS,
			HostPolicy: autocert.HostWhitelist(hosts...),
			Cache:      cache,
		}
		tLSConfig := &tls.Config{GetCertificate: m.GetCertificate}

		tLSConfig.NextProtos = append(tLSConfig.NextProtos, acme.ALPNProto)
		tLSConfig.NextProtos = append(tLSConfig.NextProtos, "h2")

		go func() {
			log.Printf("main : API Listening %s with SSL cert for hosts %s", cfg.Service.HTTPSHost, strings.Join(hosts, ", "))

			srv := &http.Server{
				Addr:         cfg.Service.HTTPSHost,
				Handler:      http.DefaultServeMux,
				TLSConfig:    tLSConfig,
				TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler), 0),
			}

			serverErrors <- srv.ListenAndServeTLS("", "")
		}()
	}

	// =========================================================================
	// Shutdown

	// Blocking main and waiting for shutdown.
	select {
	case err := <-serverErrors:
		log.Fatalf("main : Error starting server: %+v", err)

	case sig := <-shutdown:
		log.Printf("main : %v : Start shutdown..", sig)

		// Ensure the public IP address for the task is removed from Route53.
		// TODO: this function needs to remove the current IP of the instance, and terminate RDS + Elastic cache
		err = devdeploy.EcsServiceTaskTaskShutdown(log, awsSession)
		if err != nil {
			log.Fatalf("main : Ecs Service Task shutdown : %+v", err)
		}

		// Log the status of this shutdown.
		switch {
		case sig == syscall.SIGSTOP:
			log.Fatal("main : Integrity issue caused shutdown")
		case err != nil:
			log.Fatalf("main : Could not stop server gracefully : %+v", err)
		}
	}
}

// testDbConn ensures this service can access the database instance.
func testDbConn(db *sqlx.DB) error {
	// check
	_, err := db.Exec("SELECT 1")
	if err != nil {
		return errors.Wrap(err, "Database query failed.")
	}

	return nil
}

// testRedisConn ensures this service can access the Redis cache instance.
func testRedisConn(r *redis.Client) error {
	err := r.Ping().Err()
	if err != nil {
		return errors.Wrap(err, "Redis ping failed.")
	}

	return err
}
