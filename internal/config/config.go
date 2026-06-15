package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

type HTTPService struct {
	Name     string `yaml:"name"`
	Listen   string `yaml:"listen"`
	Upstream string `yaml:"upstream"`
	Headers  map[string]string `yaml:"headers"`
}

type MySQLService struct {
	Listen   string `yaml:"listen"`
	Upstream string `yaml:"upstream"`
	User     string `yaml:"user"`
	Password string `yaml:"password"`
	Database string `yaml:"database"`
}

type RedisService struct {
	Listen   string `yaml:"listen"`
	Upstream string `yaml:"upstream"`
	Password string `yaml:"password"`
}

type Config struct {
	HTTP  []HTTPService  `yaml:"http"`
	MySQL []MySQLService `yaml:"mysql"`
	Redis []RedisService `yaml:"redis"`
}

var searchPaths = []string{
	os.Getenv("HOME") + "/.config/credential-gateway/config.yaml",
	"/etc/credential-gateway/config.yaml",
}

func Load(path string) (*Config, error) {
	if path == "" {
		for _, p := range searchPaths {
			if _, err := os.Stat(p); err == nil {
				path = p
				break
			}
		}
	}
	if path == "" {
		return nil, fmt.Errorf("no config file found (searched %v)", searchPaths)
	}
	if err := checkPermissions(path); err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config %s: %w", path, err)
	}
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse config %s: %w", path, err)
	}
	return &cfg, nil
}

// checkPermissions rejects configs readable by group or world.
func checkPermissions(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("stat config %s: %w", path, err)
	}
	mode := info.Mode().Perm()
	if mode&0o044 != 0 {
		return fmt.Errorf("config file %s has unsafe permissions %04o (must not be group- or world-readable)", path, mode)
	}
	return nil
}
