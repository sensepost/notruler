package main

import (
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"strings"

	"github.com/howeyc/gopass"
	"github.com/sensepost/notruler/autodiscover"
	"github.com/sensepost/ruler/mapi"
	"github.com/sensepost/ruler/utils"
	"github.com/urfave/cli"
)

//globals
var config utils.Session
var autodiscURL string

func exit(err error) {
	//we had an error
	if err != nil {
		utils.Error.Println(err)
	}

	//let's disconnect from the MAPI session
	exitcode, err := mapi.Disconnect()
	if err != nil {
		utils.Error.Println(err)
	}
	os.Exit(exitcode)
}

//ReadYml reads the supplied config file, Unmarshals the data into the global config struct.
func readMailboxes(path string) (outputs []string, err error) {

	data, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	for _, line := range strings.Split(string(data), "\n") {
		if line != "" {
			outputs = append(outputs, line)
		}
	}
	return outputs, err
}

//Function to connect to the Exchange server
func connect(c *cli.Context, mailbox string) error {
	var err error
	config.Email = mailbox
	//add supplied cookie to the cookie jar
	if c.GlobalString("cookie") != "" {
		//split into cookies and then into name : value
		cookies := strings.Split(c.GlobalString("cookie"), ";")
		var cookieJarTmp []*http.Cookie
		var cdomain string
		//split and get the domain from the email
		if eparts := strings.Split(mailbox, "@"); len(eparts) == 2 {
			cdomain = eparts[1]
		} else {
			return fmt.Errorf("[x] Invalid email address")
		}

		for _, v := range cookies {
			cookie := strings.Split(v, "=")
			c := &http.Cookie{
				Name:   cookie[0],
				Value:  cookie[1],
				Path:   "/",
				Domain: cdomain,
			}
			cookieJarTmp = append(cookieJarTmp, c)
		}
		u, _ := url.Parse(fmt.Sprintf("https://%s/", cdomain))
		config.CookieJar.SetCookies(u, cookieJarTmp)
	}

	config.CookieJar, _ = cookiejar.New(nil)

	//add supplied cookie to the cookie jar
	if c.GlobalString("cookie") != "" {
		//split into cookies and then into name : value
		cookies := strings.Split(c.GlobalString("cookie"), ";")
		var cookieJarTmp []*http.Cookie
		var cdomain string
		//split and get the domain from the email
		if eparts := strings.Split(mailbox, "@"); len(eparts) == 2 {
			cdomain = eparts[1]
		} else {
			return fmt.Errorf("Invalid email address")
		}

		for _, v := range cookies {
			cookie := strings.Split(v, "=")
			c := &http.Cookie{
				Name:   cookie[0],
				Value:  cookie[1],
				Path:   "/",
				Domain: cdomain,
			}
			cookieJarTmp = append(cookieJarTmp, c)
		}
		u, _ := url.Parse(fmt.Sprintf("https://%s/", cdomain))
		config.CookieJar.SetCookies(u, cookieJarTmp)
	}

	if autodiscURL == "" {
		autodiscURL = c.GlobalString("url")
	}

	if c.GlobalBool("o365") == true {
		autodiscURL = "https://autodiscover-s.outlook.com/autodiscover/autodiscover.xml"
	}

	autodiscover.SessionConfig = &config

	var resp *utils.AutodiscoverResp
	var rawAutodiscover string

	var mapiURL, abkURL, userDN string

	//try connect to MAPI/HTTP first -- this is faster and the code-base is more stable
	//unless of course the global "RPC" flag has been set, which specifies we should just use
	//RPC/HTTP from the get-go
	if c.GlobalString("config") != "" {
		var yamlConfig utils.YamlConfig
		if yamlConfig, err = utils.ReadYml(c.GlobalString("config")); err != nil {
			utils.Error.Println("Invalid Config file.")
			return err
		}

		//set all fields from yamlConfig into config (this overrides cmdline options)
		if yamlConfig.Username != "" {
			config.User = yamlConfig.Username
		}
		if yamlConfig.Password != "" {
			config.Pass = yamlConfig.Password
		}
		if yamlConfig.Email != "" {
			config.Email = yamlConfig.Email
		}
		if yamlConfig.Hash != "" {
			if config.NTHash, err = hex.DecodeString(yamlConfig.Hash); err != nil {
				return fmt.Errorf("Invalid hash provided. Hex decode failed")
			}
		}

		if config.User == "" && config.Email == "" {
			return fmt.Errorf("Missing username and/or email argument. Use --domain (if needed), --username and --email or the --config")
		}

		if config.Pass == "" {
			fmt.Printf("Password: ")
			var pass []byte
			pass, err = gopass.GetPasswd()
			if err != nil {
				// Handle gopass.ErrInterrupted or getch() read error
				return fmt.Errorf("Password or hash required. Supply NTLM hash with --hash")
			}
			config.Pass = string(pass)
		}

		if yamlConfig.RPC == true {
			//create RPC URL
			config.RPCURL = fmt.Sprintf("%s?%s:6001", yamlConfig.RPCURL, yamlConfig.Mailbox)
			config.RPCEncrypt = yamlConfig.RPCEncrypt
			config.RPCNtlm = yamlConfig.Ntlm
		} else {
			mapiURL = fmt.Sprintf("%s?MailboxId=%s", yamlConfig.MapiURL, yamlConfig.Mailbox)
		}
		userDN = yamlConfig.UserDN

	} else if !c.GlobalBool("rpc") {

		if config.User == "" && config.Email == "" {
			return fmt.Errorf("Missing username and/or email argument. Use --domain (if needed), --username and --email or the --config")
		}

		if c.GlobalBool("nocache") == false { //unless user specified nocache, check cache for existing autodiscover
			resp = autodiscover.CheckCache(mailbox)
		}
		if resp == nil {
			resp, rawAutodiscover, autodiscURL, err = autodiscover.GetMapiHTTP(mailbox, autodiscURL, resp)
			if err != nil {
				return err
			}
		}
		mapiURL = mapi.ExtractMapiURL(resp)
		abkURL = mapi.ExtractMapiAddressBookURL(resp)
		userDN = resp.Response.User.LegacyDN

		if mapiURL == "" { //try RPC
			resp, rawAutodiscover, config.RPCURL, config.RPCMailbox, config.RPCNtlm, autodiscURL, err = autodiscover.GetRPCHTTP(mailbox, autodiscURL, resp)
			if err != nil {
				exit(err)
			}
			if resp.Response.User.LegacyDN == "" {
				return fmt.Errorf("Both MAPI/HTTP and RPC/HTTP failed. Are the credentials valid? \n%s", resp.Response.Error)
			}

			if c.GlobalBool("nocache") == false {
				autodiscover.CreateCache(mailbox, rawAutodiscover) //store the autodiscover for future use
			}
		} else {

			utils.Trace.Println("MAPI URL found: ", mapiURL)

			//mapi.Init(&config, userDN, mapiURL, abkURL, mapi.HTTP)
			if c.GlobalBool("nocache") == false {
				autodiscover.CreateCache(mailbox, rawAutodiscover) //store the autodiscover for future use
			}
		}

	} else {

		if config.User == "" && config.Email == "" {
			return fmt.Errorf("Missing username and/or email argument. Use --domain (if needed), --username and --email or the --config")
		}

		utils.Trace.Println("RPC/HTTP forced, trying RPC/HTTP")
		if c.GlobalBool("nocache") == false { //unless user specified nocache, check cache for existing autodiscover
			resp = autodiscover.CheckCache(mailbox)
		}

		resp, rawAutodiscover, config.RPCURL, config.RPCMailbox, config.RPCNtlm, autodiscURL, err = autodiscover.GetRPCHTTP(mailbox, autodiscURL, resp)
		if err != nil {
			return err
		}

		userDN = resp.Response.User.LegacyDN

		if c.GlobalBool("nocache") == false {
			autodiscover.CreateCache(mailbox, rawAutodiscover) //store the autodiscover for future use
		}
	}

	if config.RPCURL != "" {
		mapi.Init(&config, userDN, "", "", mapi.RPC)
	} else {
		mapi.Init(&config, userDN, mapiURL, abkURL, mapi.HTTP)
	}

	//now we should do the login
	logon, err := mapi.Authenticate()

	if err != nil {
		return err
	} else if logon.MailboxGUID != nil {

		utils.Trace.Println("And we are authenticated")
		utils.Trace.Println("Openning the Inbox")

		propertyTags := make([]mapi.PropertyTag, 2)
		propertyTags[0] = mapi.PidTagDisplayName
		propertyTags[1] = mapi.PidTagSubfolders
		mapi.GetFolder(mapi.INBOX, propertyTags) //Open Inbox
	}
	return nil
}

func printRules() error {
	cols := make([]mapi.PropertyTag, 3)
	cols[0] = mapi.PidTagRuleID
	cols[1] = mapi.PidTagRuleName
	cols[2] = mapi.PidTagRuleActions

	rows, er := mapi.FetchRules(cols)

	if er != nil {
		return er
	}

	if rows.RowCount > 0 {
		utils.Info.Printf("Found %d rules\n", rows.RowCount)
		maxwidth := 30

		for k := 0; k < int(rows.RowCount); k++ {
			if len(string(rows.RowData[k][1].ValueArray)) > maxwidth {
				maxwidth = len(string(rows.RowData[k][1].ValueArray))
			}
		}
		maxwidth -= 10

		for k := 0; k < int(rows.RowCount); k++ {

			rd := mapi.RuleAction{}
			rd.Unmarshal(rows.RowData[k][2].ValueArray)
			if rd.ActionType == 0x05 {
				utils.Info.Printf("Found client-side rule: name [%s], id [%x], trigger [%s]\n", string(utils.FromUnicode(rows.RowData[k][1].ValueArray)), rows.RowData[k][0].ValueArray, string(utils.FromUnicode(rd.ActionData.Trigger)))
				for _, v := range rd.ActionData.Conditions {
					if v.Tag[1] == 0x49 {
						utils.Warning.Printf("Executes an application! %s\n", string(utils.FromUnicode(v.Value)))
						break
					}
				}

			}
		}

	} else {
		utils.Info.Printf("No Rules Found\n")
	}
	return nil
}

func main() {

	app := cli.NewApp()

	app.Name = "notruler"
	app.Usage = "A tool to check for abused Exchange Services"
	app.Version = "0.0.1"
	app.Author = "Etienne Stalmans <etienne@sensepost.com>, @_staaldraad"
	app.Description = `
A tool by @_staaldraad from @sensepost for Exchange Admins to check for abused Exchange Services.`

	app.Flags = []cli.Flag{
		cli.StringFlag{
			Name:  "domain,d",
			Value: "",
			Usage: "A domain for the user (optional in most cases. Otherwise allows: domain\\username)",
		},
		cli.BoolFlag{
			Name:  "o365",
			Usage: "We know the target is on Office365, so authenticate directly against that.",
		},
		cli.StringFlag{
			Name:  "username,u",
			Value: "",
			Usage: "A valid username for the Exchange Admin",
		},
		cli.StringFlag{
			Name:  "password,p",
			Value: "",
			Usage: "A valid password for the Exchange Admin",
		},
		cli.StringFlag{
			Name:  "mailbox,m",
			Value: "",
			Usage: "The target mailbox account email address",
		},
		cli.StringFlag{
			Name:  "mailboxes,mm",
			Value: "",
			Usage: "The file path to a list of mailboxes to check",
		},
		cli.StringFlag{
			Name:  "config",
			Value: "",
			Usage: "The path to a config file to use",
		},
		cli.StringFlag{
			Name:  "url",
			Value: "",
			Usage: "If you know the Autodiscover URL or the autodiscover service is failing. Requires full URI, https://autodisc.d.com/autodiscover/autodiscover.xml",
		},
		cli.StringFlag{
			Name:  "proxy",
			Value: "",
			Usage: "If you need to use an upstream proxy. Works with https://user:pass@ip:port or https://ip:port",
		},
		cli.BoolFlag{
			Name:  "insecure,k",
			Usage: "Ignore server SSL certificate errors",
		},
		cli.BoolFlag{
			Name:  "noencrypt",
			Usage: "Don't use encryption the RPC level - some environments require this",
		},
		cli.BoolFlag{
			Name:  "basic,b",
			Usage: "Force Basic authentication",
		},
		cli.BoolFlag{
			Name:  "nocache",
			Usage: "Don't use the cached autodiscover record",
		},
		cli.BoolFlag{
			Name:  "rpc",
			Usage: "Force RPC/HTTP rather than MAPI/HTTP",
		},
		cli.BoolFlag{
			Name:  "verbose",
			Usage: "Be verbose and show some of thei inner workings",
		},
		cli.BoolFlag{
			Name:  "debug",
			Usage: "Be print debug info",
		},
	}

	app.Before = func(c *cli.Context) error {
		if c.Bool("verbose") == true && c.Bool("debug") == false {
			utils.Init(os.Stdout, os.Stdout, os.Stdout, os.Stderr)
		} else if c.Bool("verbose") == false && c.Bool("debug") == true {
			utils.Init(ioutil.Discard, os.Stdout, os.Stdout, os.Stderr)
		} else if c.Bool("debug") == true {
			utils.Init(os.Stdout, os.Stdout, os.Stdout, os.Stderr)
		} else {
			utils.Init(ioutil.Discard, os.Stdout, os.Stdout, os.Stderr)
		}

		//if no password or hash was supplied, read from stdin
		if c.GlobalString("password") == "" {
			fmt.Printf("Password: ")
			var pass []byte
			pass, err := gopass.GetPasswd()
			if err != nil {
				// Handle gopass.ErrInterrupted or getch() read error
				utils.Error.Println("Password required.")
				cli.OsExiter(1)
			}
			config.Pass = string(pass)
		} else {
			config.Pass = c.GlobalString("password")
		}
		//setup our autodiscover service
		config.Domain = c.GlobalString("domain")
		config.User = c.GlobalString("username")
		config.Basic = c.GlobalBool("basic")
		config.Insecure = c.GlobalBool("insecure")
		config.Verbose = c.GlobalBool("verbose")
		config.Admin = true
		config.RPCEncrypt = !c.GlobalBool("noencrypt")
		config.CookieJar, _ = cookiejar.New(nil)
		config.Proxy = c.GlobalString("proxy")
		config.Email = c.GlobalString("mailbox")

		return nil
	}

	app.Commands = []cli.Command{
		{
			Name:    "check",
			Aliases: []string{"c"},
			Usage:   "Check if the credentials work and we can interact with the mailbox[s]",
			Action: func(c *cli.Context) error {
				var mailboxes []string

				if config.Email != "" {
					mailboxes = append(mailboxes, config.Email)
				}

				if c.GlobalString("mailboxes") != "" {
					//read mailbox file
					mailboxes, _ = readMailboxes(c.GlobalString("mailboxes"))
				}

				for _, mailbox := range mailboxes {
					err := connect(c, mailbox)
					if err != nil {
						utils.Error.Printf("Looks like %s failed: %s\n", mailbox, err)
					} else {
						utils.Info.Printf("Looks like we are good to go for %s!\n", mailbox)
					}
				}
				return nil
			},
		},
		{
			Name:    "rules",
			Aliases: []string{"r"},
			Usage:   "Reviews all rules and tries to find Execute rules that have a remote path.",
			Action: func(c *cli.Context) error {
				var mailboxes []string

				if config.Email != "" {
					mailboxes = append(mailboxes, config.Email)
				}

				if c.GlobalString("mailboxes") != "" {
					//read mailbox file
					mailboxes, _ = readMailboxes(c.GlobalString("mailboxes"))
				}

				for _, mailbox := range mailboxes {
					err := connect(c, mailbox)
					if err != nil {
						utils.Error.Printf("Looks like %s failed: %s\n", mailbox, err)
					} else {
						utils.Info.Printf("Checking [%s]\n", mailbox)
						printRules()
					}
				}
				mapi.Disconnect()
				return nil
			},
		},
	}

	app.Action = func(c *cli.Context) error {
		cli.ShowAppHelp(c)
		return nil
	}

	app.Run(os.Args)

}
