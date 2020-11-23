/*
Obtains Google Analytics RealTime API metrics, and presents them to
prometheus for scraping.
*/
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"golang.org/x/oauth2/jwt"
	"google.golang.org/api/analytics/v3"
	"gopkg.in/yaml.v2"
)

var (
	credsfile = "./config/ga_creds.json"
	conffile  = "./config/conf.yaml"
	promGauge = make(map[string]prometheus.Gauge)
	config    = new(conf)
)

// metricdef defines a single metric to return from the GA API
type metricdef struct {
	Label string  `yaml:"label"`
	Metric string `yaml:"metric"`
	Filter string `yaml:"filter"`
}

// conf defines configuration parameters
type conf struct {
	Interval int         `yaml:"interval"`
	Metrics  []metricdef `yaml:"metrics"`
	ViewID   string      `yaml:"viewid"`
	PromPort string      `yaml:"port"`
}

func init() {
	config.getConf(conffile)

	// All metrics are registered as Prometheus Gauge
	for _, metric := range config.Metrics {
		promGauge[metric.Label] = prometheus.NewGauge(prometheus.GaugeOpts{
			Name:        fmt.Sprintf("ga_%s", metric.Label),
			Help:        fmt.Sprintf("Google Analytics %s", metric.Label),
			ConstLabels: map[string]string{"job": "googleAnalytics"},
		})

		prometheus.MustRegister(promGauge[metric.Label])
	}
}

func main() {
	creds := getCreds(credsfile)

	// JSON web token configuration
	jwtc := jwt.Config{
		Email:        creds["client_email"],
		PrivateKey:   []byte(creds["private_key"]),
		PrivateKeyID: creds["private_key_id"],
		Scopes:       []string{analytics.AnalyticsReadonlyScope},
		TokenURL:     creds["token_uri"],
		// Expires:      time.Duration(1) * time.Hour, // Expire in 1 hour
	}

	httpClient := jwtc.Client(context.Background())
	as, err := analytics.New(httpClient)
	if err != nil {
		panic(err)
	}

	// Authenticated RealTime Google Analytics API service
	rts := analytics.NewDataRealtimeService(as)

	// Expose the registered metrics via HTTP.
	http.Handle("/metrics", promhttp.Handler())
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`<html>
			<head><title>Google Analytics Exporter</title></head>
			<body>
			<h1>Google Analytics Exporter</h1>
			<p><a href="/metrics">Metrics</a></p>
			</body>
			</html>`))
	})
	go http.ListenAndServe(fmt.Sprintf(":%s", config.PromPort), nil)

	for {
		for _, metric := range config.Metrics {
			// Go routine per metric
			go func(metric metricdef) {
				val := getMetric(rts, metric)
				// Gauge value to float64
				valf, _ := strconv.ParseFloat(val, 64)
				promGauge[metric.Label].Set(valf)
			}(metric)
		}
		time.Sleep(time.Second * time.Duration(config.Interval))
	}
}

// getMetric queries GA RealTime API for a specific metric.
func getMetric(rts *analytics.DataRealtimeService, metric metricdef) string {
	getc := rts.Get(config.ViewID, metric.Metric)
	if metric.Filter != "" {
		getc = getc.Filters(metric.Filter)
	}

	m, err := getc.Do()
	if err != nil {
		panic(err)
	}

	return m.Rows[0][0]
}

// conf.getConf reads yaml configuration file
func (c *conf) getConf(filename string) {
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		panic(err)
	}
	if err = yaml.Unmarshal(data, &c); err != nil {
		panic(err)
	}
}

// https://console.developers.google.com/apis/credentials
// 'Service account keys' creds formated file is expected.
// NOTE: the email from the creds has to be added to the Analytics permissions
func getCreds(filename string) (r map[string]string) {
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		panic(err)
	}
	if err = json.Unmarshal(data, &r); err != nil {
		panic(err)
	}

	return r
}
