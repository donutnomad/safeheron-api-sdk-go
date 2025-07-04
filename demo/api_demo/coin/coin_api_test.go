package coin_api_demo

import (
	"fmt"
	"os"
	"testing"

	"github.com/donutnomad/safeheron-api-sdk-go/safeheron"
	"github.com/donutnomad/safeheron-api-sdk-go/safeheron/api"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

var coinApi api.CoinApi

func TestDemo(t *testing.T) {

	var res api.CoinResponse
	if err := coinApi.ListCoin(&res); err != nil {
		panic(fmt.Errorf("failed to create wallet account, %w", err))
	}
	//assert.Nil(t, err)
	//assert.Greater(t, len(res.Content), 0)

	for _, coin := range res {
		log.Infof("coinKey: %s, coinName: %s", coin.CoinKey, coin.CoinName)
	}
	//log.Infof("result: %t", res.Result)
}

func setup() {
	viper.SetConfigFile("config.yaml")

	if err := viper.ReadInConfig(); err != nil {
		panic(fmt.Errorf("Error reading config file, %w", err))
	}

	sc := safeheron.Client{Config: safeheron.ApiConfig{
		BaseUrl:               viper.GetString("baseUrl"),
		ApiKey:                viper.GetString("apiKey"),
		RsaPrivateKey:         viper.GetString("privateKeyPemFile"),
		SafeheronRsaPublicKey: viper.GetString("safeheronPublicKeyPemFile"),
		RequestTimeout:        viper.GetInt64("requestTimeout"),
		LoadFromFile:          true,
	}}

	coinApi = api.CoinApi{Client: sc}
}

func teardown() {
}

func TestMain(m *testing.M) {
	setup()
	code := m.Run()
	teardown()
	os.Exit(code)
}
