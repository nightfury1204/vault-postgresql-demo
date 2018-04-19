package main

import (
	_ "github.com/hashicorp/vault/api"
	"os"
	"github.com/hashicorp/vault/api"
	"log"
	"errors"
	"io/ioutil"
	"github.com/hashicorp/vault/helper/jsonutil"
	"fmt"
)

var (
	vaultAddr = os.Getenv("VAULT_ADDR")
	vaultToken = os.Getenv("VAULT_TOKEN")
	username = os.Getenv("PG_USER")
	password = os.Getenv("PG_PASS")
)

const (
	rolesName = "postgres-role"
	policyName = "postgres-policy"
	ttl = "3600"
)

func main()  {
	err := validate()
	if err!=nil {
		log.Fatal(err)
	}

	client, err := api.NewClient(api.DefaultConfig())
	if err!=nil {
		log.Fatal(err)
	}

	client.SetAddress(vaultAddr)
	client.SetToken(vaultToken)

	// assumed that vault database is enabled


	/*{
		"plugin_name": "postgresql-database-plugin",
		"allowed_roles": "readonly",
		"connection_url": "postgresql://{{username}}:{{password}}@localhost:5432/postgres",
		"max_open_connections": 5,
		"max_connection_lifetime": "5s",
		"username": "username",
		"password": "password"
	}*/
	config := struct {
		Plugin_name string `json:"plugin_name"`
		Allowed_roles string `json:"allowed_roles"`
		Connection_url string `json:"connection_url"`
		Max_open_connections int `json:"max_open_connections"`
		Max_connection_lifetime string `json:"max_connection_lifetime"`
		Username string `json:"username"`
		Password string `json:"password"`
	}{
		"postgresql-database-plugin",
		rolesName,
		"postgresql://{{username}}:{{password}}@localhost:5432/postgres?sslmode=disable",
		5,
		"5s",
		username,
		password,
	}

	req := client.NewRequest("POST","/v1/database/config/postgres")
	req.SetJSONBody(config)

	resp, err := client.RawRequest(req)
	if err!=nil {
		log.Fatal(err)
	}
	printLog(resp, "/v1/database/config/postgres")

	/*{
		"db_name": "mysql",
		"creation_statements": ["CREATE USER '{{name}}'@'%' IDENTIFIED BY '{{password}}'", "GRANT SELECT ON *.* TO '{{name}}'@'%'"],
		"default_ttl": "1h",
		"max_ttl": "24h"
	}*/

	roles := struct {
		Db_name string `json:"db_name"`
		Creation_statements []string `json:"creation_statements"`
		Default_ttl string `json:"default_ttl"`
		Max_ttl string `json:"max_ttl"`
	}{
		"postgres",
		 []string{"CREATE ROLE \"{{name}}\" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}';"," GRANT SELECT ON ALL TABLES IN SCHEMA public TO \"{{name}}\";"},
        "15s",
        "24h",
	}

	req = client.NewRequest("POST","/v1/database/roles/"+rolesName)
	req.SetJSONBody(roles)

	resp, err = client.RawRequest(req)
	if err!=nil {
		log.Fatal(err)
	}
	printLog(resp, "/v1/database/roles/"+rolesName)


	// creating policy
	postgresPolicy :=`
path "database/creds/postgres-role" {
  capabilities = ["read"]
}
path "sys/leases/renew" {
  capabilities = ["create"]
}
path "sys/leases/revoke" {
  capabilities = ["update"]
}
`

	err = client.Sys().PutPolicy(policyName, postgresPolicy)
	if err != nil {
		log.Fatal("unable to create policy",err)
	}

	// generating token
	tokenReq := &api.TokenCreateRequest{
		Policies: []string{policyName},
		DisplayName: "read-postgres",
		NoParent:    true,
		Period:      ttl,
		TTL:         ttl,
		Renewable: pointerBoool(true),
	}
	secret, err := client.Auth().Token().Create(tokenReq)
	if err != nil {
		log.Fatal("unable to create token", err)
	}
	log.Println("----------------token---------------")
	log.Println(secret)
	log.Println(secret.Auth.ClientToken)
	log.Println("------------------------------------")


	// generating credentials
	client.SetToken(secret.Auth.ClientToken)

	req = client.NewRequest("GET","/v1/database/creds/"+rolesName)
	resp, err = client.RawRequest(req)
	if err!=nil {
		log.Fatal("unable to create credential for database.",err)
	}
	//printLog(resp, "/v1/database/creds/"+rolesName)

	cred := api.Secret{}

	defer resp.Body.Close()
	jsonutil.DecodeJSONFromReader(resp.Body, &cred)
	fmt.Println("lease_id: ",cred.LeaseID)
	fmt.Println()
	fmt.Println("username: ",cred.Data["username"])
	fmt.Println("password: ",cred.Data["password"])
}

func validate() error {
	if len(vaultAddr)==0 {
		return errors.New("vault address is empty")
	}

	if len(vaultToken)==0 {
		return errors.New("vault token is empty")
	}

	if len(username)==0 {
		return errors.New("postgres username is empty")
	}

	if len(password)==0 {
		return errors.New("postgres password is empty")
	}
	return nil
}

func printLog(resp *api.Response, path string)  {
	// return
	log.Println("-----------"+path+"----------------")
	defer resp.Body.Close()
	data, err := ioutil.ReadAll(resp.Body)
	if err!=nil {
		log.Fatal(err)
	}
	log.Println(string(data))
	log.Println("--------------------------------------------------------")
}

func pointerBoool(u bool) *bool {
	return &u
}