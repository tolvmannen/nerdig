package main

import (
	"crypto/tls"
	"os"

	//"encoding/hex"
	"fmt"
	"log"
	"net/http"

	//"strconv"
	"strings"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-contrib/static"
	"github.com/gin-gonic/gin"
	"gopkg.in/yaml.v3"
	//"github.com/miekg/dns"
)

const (
	ContentTypeBinary = "application/octet-stream"
	ContentTypeForm   = "application/x-www-form-urlencoded"
	ContentTypeJSON   = "application/json"
	ContentTypeHTML   = "text/html; charset=utf-8"
	ContentTypeText   = "text/plain; charset=utf-8"
)

type httpconf struct {
	TLS              string   `yaml:"TLS" json:"TLS"`
	Address          string   `yaml:"Address" json:"Address"`
	Port             string   `yaml:"Port" json:"Port"`
	Certfile         string   `yaml:"Certfile" json:"Certfile"`
	Keyfile          string   `yaml:"Keyfile" json:"Keyfile"`
	AllowOrigins     []string `yaml:"AllowOrigins" json:"AllowOrigins"`
	AllowMethods     []string `yaml:"AllowMethods" json:"AllowMethods"`
	AllowHeaders     []string `yaml:"AllowHeaders" json:"AllowHeaders"`
	ExposeHeaders    []string `yaml:"ExposeHeaders" json:"ExposeHeaders"`
	AllowCredentials bool     `yaml:"AllowCredentials" json:"AllowCredentials"`
	LogLevel         int      `yaml:"LogLevel" json:"LogLevel"`
}

func main() {

	// http conf
	cf, err := os.ReadFile("conf.yaml")
	if err != nil {
		fmt.Printf("ReadFile error: %v\n", err)
	}
	var hc httpconf
	yaml.Unmarshal(cf, &hc)
	if err != nil {
		fmt.Printf("YAML error: %v\n", err)
	}

	// Create a Gin router
	router := gin.Default()

	//router.Static("/script", "./script")
	router.Use(static.Serve("/", static.LocalFile("html", false)))

	// Fix issues with browsers diallowing POSTing (No 'Access-Control-Allow-Origin' header is present on the requested resource)
	router.Use(cors.New(cors.Config{
		AllowAllOrigins:  false,
		AllowOrigins:     hc.AllowOrigins,
		AllowMethods:     hc.AllowMethods,
		AllowHeaders:     hc.AllowHeaders,
		ExposeHeaders:    hc.ExposeHeaders,
		AllowCredentials: hc.AllowCredentials,
		MaxAge:           12 * time.Hour,
	}))

	// Create Endpoint for testing
	router.POST("/echo", func(c *gin.Context) {
		var jsonInput map[string]interface{}
		if err := c.ShouldBindJSON(&jsonInput); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, jsonInput)
	})
	/*
		router.POST("/dig/json", func(c *gin.Context) {
			var query Query
			if err := c.ShouldBindJSON(&query); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
				return
			}
			out := dig(query)
			c.JSON(http.StatusOK, out)
		})

	*/
	router.POST("/dig/webclient", func(c *gin.Context) {
		var wq WebQuery
		if err := c.ShouldBindJSON(&wq); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		//fmt.Printf("WQ: %#v\n", wq)

		query := wq.Parse()

		//fmt.Printf("Q: %#v\n", query)
		out := dig(query)

		//fmt.Printf("\n\n%+v\n\n", out)

		outstr := out.ToHTML()

		outstr += query.ToCLI()

		c.Data(http.StatusOK, ContentTypeHTML, []byte(outstr))
	})

	router.GET("/dig/info/*name", func(c *gin.Context) {
		// trim any leading slash (applies when no 'name' is provided)
		name := strings.TrimLeft(c.Param("name"), "/")
		outstr := ""
		mdfile, err := os.ReadFile("mdfiles/" + name + ".md")
		if err != nil {
			outstr = "<p>Could not open file: " + name + ".md (" + err.Error() + "</p>"
		} else {
			outstr = string(mdToHTML(mdfile))
		}
		c.Data(http.StatusOK, ContentTypeHTML, []byte(outstr))

	})

	switch hc.TLS {
	case "auto":
		fmt.Println("Auto TLS not yet implemented")
	case "local":
		// Load Certificates
		cer, err := tls.LoadX509KeyPair(hc.Certfile, hc.Keyfile)
		if err != nil {
			log.Println(err)
			return
		}

		config := &tls.Config{Certificates: []tls.Certificate{cer}}

		server := &http.Server{
			Addr:      hc.Address + ":" + hc.Port,
			TLSConfig: config,
			Handler:   router,
		}

		// Start the HTTPS server
		log.Fatal(server.ListenAndServeTLS("", ""))
	default:
		server := &http.Server{
			Addr:    hc.Address + ":" + hc.Port,
			Handler: router,
		}
		log.Fatal(server.ListenAndServe())

	}
}

// Notes

/*

NumField and Field - https://github.com/miekg/dns/blob/master/format.go

Type(rr.TypeCovered).String() - https://github.com/miekg/dns/blob/master/types.go#L900

*/
