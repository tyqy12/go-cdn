package config

type Config struct {
	GostConfigPath string
}

func Load(path string) (*Config, error) {
	return &Config{GostConfigPath: "/etc/ai-cdn/gost.yml"}, nil
}
