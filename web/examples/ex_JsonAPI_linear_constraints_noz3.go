package main

import (
	"crypto/sha256"
	"path/filepath"

	"github.com/marcellop71/mosaic/abe"
	"github.com/marcellop71/mosaic/abe/log"
	"github.com/marcellop71/mosaic/service"
)

func main() {
	log.Init("Debug")

	filename, err := filepath.Abs("./examples/config.yaml")
	if err != nil {
		log.Panic("%s", err)
	}
	//读取本地配置文件
	config := service.ReadConfig(filename).Config
	log.Info("hi")
	
	//初始化storage
	service.InitAbeService(config, nil)

	// lib表示使用的加密算法库
	lib := "miracl"
	org := "org0"
	service.SetupOrg(org, lib, config.Arithmetic.Curve, config.Arithmetic.Seed)
	log.Info("set up organization %s on curve %s", org, config.Arithmetic.Curve)

	//对org组织下的每个authority生成公私钥
	auths := []string{"auth0", "auth1"}
	for _, auth := range auths {
		service.SetupAuth(auth, org)
	}
	log.Info("set up authorities %s on organization %s", auths, org)

	//给当前的user生成具有attrs属性的key
	user := "marcello.paris@gmail.com"
	attrs := []string{"A@auth0", "B@auth0", "E=5@auth1"}
	for _, attr := range attrs {
		service.SetupUserkey(user, attr)
	}
	log.Info("user %s asking for keys for attributes %s", user, attrs)

	policies := []string{
		"(E@auth1 == 5) /\\ B@auth0",                      //true
		"(E@auth1 > 1) /\\ B@auth0",                       //true
		"(E@auth1 > 1) /\\ (E@auth1 < 1)",                 //false
		"((E@auth1 >= 4) /\\ (E@auth1 <= 6)) \\/ A@auth0", //true
		"(E@auth1 == 4) /\\ B@auth0",                      //false
	}

	for _, policy := range policies {
		log.Info("----------------")
		log.Info("policy: %s", policy)
		// ecnrypting
		secretJson := service.NewRandomSecret(org)
		secret := abe.NewPointOfJsonStr(secretJson).GetP()
		secret_hash := sha256.Sum256([]byte(secret))
		log.Info("secret hash: %s", abe.Encode(string(secret_hash[:])))

		//化简policy
		// policy = abe.RewritePolicy(policy)
		authpubsJson := abe.AuthPubsOfPolicyJson(policy)
		authpubsJson = service.FetchAuthPubs(authpubsJson)
		//将policy写入到密文中
		secret_enc := abe.EncryptJson(secretJson, policy, authpubsJson)

		// decrypting
		//获取密文中的policy,为什么要从中获取policy呢？
		// policy = abe.PolicyOfCiphertextJson(secret_enc)
		userattrsJson := service.FetchUserAttrs(user)
		userattrsJson = abe.SelectUserAttrsJson(user, policy, userattrsJson)
		userattrsJson = service.FetchUserkeys(userattrsJson)
		secret_dec := abe.DecryptJson(secret_enc, userattrsJson)
		secret_dec_hash := sha256.Sum256([]byte(secret_dec))

		if abe.Encode(string(secret_dec_hash[:])) == abe.Encode(string(secret_hash[:])) {
			log.Info("secret correctly reconstructed")
		} else {
			log.Info("secret not correctly reconstructed")
		}
	}
}
