package config

type Config struct {
	MongoURI  string
	JWTSecret string
}

func Load(path string) (*Config, error) {
	return &Config{
		MongoURI:  "mongodb://localhost:27017/ai-cdn",
		JWTSecret: "",
	}, nil
}
