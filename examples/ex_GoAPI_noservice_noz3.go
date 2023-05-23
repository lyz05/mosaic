package main

import (
	"github.com/marcellop71/mosaic/abe"
	"github.com/marcellop71/mosaic/abe/log"
)

func main() {
	log.Init("Info")

	seed := "abcdef"
	// 生成一条新的曲线
	curve := abe.NewCurve()
	curve.SetSeed(seed).InitRng()
	// 在G1，G2上随机生成新的点和Pair对。
	org := abe.NewRandomOrg(curve)
	// 生成随机密钥，包含公钥和私钥
	authkeys := abe.NewRandomAuth(org)
	user := "marcello.paris@gmail.com"

	policies := []string{
		"A@auth0",             //true
		"A@auth0 /\\ B@auth0", //true
		"A@auth0 /\\ A@auth0", //true
		"A@auth0 /\\ (B@auth0 /\\ (C@auth0 \\/ D@auth0))",                           //false
		"A@auth0 /\\ ((D@auth0 \\/ (B@auth0 /\\ C@auth0)) \\/ A@auth0)",             //true
		"(A@auth0 \\/ C@auth0) /\\ (D@auth0 \\/ (B@auth0 /\\ C@auth0))",             //false
		"(/\\ A@auth0 (\\/ A@auth0 D@auth0 (/\\ B@auth0 C@auth0)))",                 //最简化形势?
		"(A@auth0 /\\ B@auth0) \\/ (A@auth0 /\\ C@auth0) \\/ (B@auth0 /\\ C@auth0)", //true
		"A@auth0 /\\ B@auth0 /\\ C@auth0",                                           //false
	}

	for _, policy := range policies {
		log.Info("----------------")
		log.Info("policy: %s", policy)

		// ecnrypting
		secret := abe.NewRandomSecret(org)
		//化简policy
		// policy = abe.RewritePolicy(policy)
		authpubs := abe.AuthPubsOfPolicy(policy)
		for attr, _ := range authpubs.AuthPub {
			authpubs.AuthPub[attr] = authkeys.AuthPub
		}
		//访问结构为policy，产生密文CT
		ct := abe.Encrypt(secret, policy, authpubs)

		// decrypting
		userattrs_A := abe.NewRandomUserkey(user, "A@auth0", authkeys.AuthPrv)
		userattrs_B := abe.NewRandomUserkey(user, "B@auth0", authkeys.AuthPrv)
		userattrs := userattrs_A.Add(userattrs_B)
		userattrs.SelectUserAttrs(user, policy)

		//包含访问结构的密文CT
		secret_dec := abe.Decrypt(ct, userattrs)

		//验证解密结果是否正确
		if abe.SecretHash(secret) == abe.SecretHash(secret_dec) {
			log.Info("secret correctly reconstructed")
		} else {
			log.Info("secret not correctly reconstructed")
		}
	}
}
