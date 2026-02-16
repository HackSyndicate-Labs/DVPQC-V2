package config

type Config struct {
	Env string
}

func LoadConfig() Config {
	return Config{
		Env: "prod",
	}
}
