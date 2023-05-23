package main

import (
	"crypto/sha256"
	"path/filepath"
	"time"

	"github.com/marcellop71/mosaic/abe"
	"github.com/marcellop71/mosaic/abe/log"
	"github.com/marcellop71/mosaic/service"
)

func timer(name string) func() {
	start := time.Now()
	return func() {
		log.Info("%s took %v\n", name, time.Since(start))
	}
}

func GlobalSetup(config service.Config, org string, lib string) {
	defer timer("GlobalSetup")()
	// lib表示使用的加密算法库
	service.SetupOrg(org, lib, config.Arithmetic.Curve, config.Arithmetic.Seed)
	log.Info("set up organization %s on curve %s", org, config.Arithmetic.Curve)
}

func AuthSetup(auths []string, org string) {
	defer timer("AuthSetup")()
	//对org组织下的每个authority生成公私钥
	for _, auth := range auths {
		service.SetupAuth(auth, org)
	}
	log.Info("set up authorities %s on organization %s", auths, org)
}

func KeyGen(user string, attrs []string) {
	defer timer("KeyGen")()
	//给当前的user生成具有attrs属性的key
	for _, attr := range attrs {
		service.SetupUserkey(user, attr)
	}
	log.Info("user %s asking for keys for attributes %s", user, attrs)
}

func Encrypt(policy string, secretJson string, org string) string {
	defer timer("Encrypt")()
	// ecnrypting
	authpubsJson := abe.AuthPubsOfPolicyJson(policy)
	authpubsJson = service.FetchAuthPubs(authpubsJson)
	//将policy写入到密文中
	secret_enc := abe.EncryptJson(secretJson, policy, authpubsJson)
	return secret_enc
}

func Decrypt(user string, secret_enc string) string {
	defer timer("Decrypt")()
	// decrypting
	//获取密文中的policy,为什么要从中获取policy呢？
	policy := abe.PolicyOfCiphertextJson(secret_enc)
	userattrsJson := service.FetchUserAttrs(user)
	userattrsJson = abe.SelectUserAttrsJson(user, policy, userattrsJson)
	userattrsJson = service.FetchUserkeys(userattrsJson)
	secret_dec := abe.DecryptJson(secret_enc, userattrsJson)
	return secret_dec
}

// 编译miracl库，并运行当前程序
// go run -tags=miracl examples/ex_JsonAPI_linear_constraints_noz3.go
func main() {
	log.Init("Info")

	filename, err := filepath.Abs("./examples/config.yaml")
	if err != nil {
		log.Panic("%s", err)
	}
	//读取本地配置文件
	config := service.ReadConfig(filename).Config
	//初始化storage
	service.InitAbeService(config, nil)

	org := config.Example.Org
	lib := config.Example.Lib
	GlobalSetup(config, org, lib)

	auths := config.Example.Auths
	AuthSetup(auths, org)

	user := config.Example.User
	attrs := config.Example.Attrs
	KeyGen(user, attrs)

	// policies := []string{
	// 	"(E@auth1 == 5) /\\ B@auth0",                      //true
	// 	"(E@auth1 > 1) /\\ B@auth0",                       //tru
	// 	"(E@auth1 > 1) /\\ (E@auth1 < 1)",                 //false
	// 	"((E@auth1 >= 4) /\\ (E@auth1 <= 6)) \\/ A@auth0", //true
	// 	"(E@auth1 == 4) /\\ B@auth0",                      //false
	// }

	policy := config.Example.Policy
	log.Info("----------------")
	log.Info("policy: %s", policy)

	// 随机生成secret
	secretJson := service.NewRandomSecret(org)
	secret := abe.NewPointOfJsonStr(secretJson).GetP()
	secret_hash := sha256.Sum256([]byte(secret))
	// log.Info("secret hash: %s", abe.Encode(string(secret_hash[:])))

	secret_enc := Encrypt(policy, secretJson, org)
	secret_dec := Decrypt(user, secret_enc)
	secret_dec_hash := sha256.Sum256([]byte(secret_dec))

	if abe.Encode(string(secret_dec_hash[:])) == abe.Encode(string(secret_hash[:])) {
		log.Info("secret correctly reconstructed")
	} else {
		log.Info("secret not correctly reconstructed")
	}

}
