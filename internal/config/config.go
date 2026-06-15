package config

import (
	"bytes"
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

type HTTPService struct {
	Name     string            `yaml:"name"`
	Listen   string            `yaml:"listen"`
	Upstream string            `yaml:"upstream"`
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
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	var cfg Config
	if err := dec.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("parse config %s: %w", path, err)
	}
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config %s: %w", path, err)
	}
	return &cfg, nil
}

// Validate checks required fields and rejects duplicate listen addresses.
func (c *Config) Validate() error {
	seen := make(map[string]string)

	for i, h := range c.HTTP {
		label := fmt.Sprintf("http[%d]", i)
		if h.Listen == "" {
			return fmt.Errorf("%s: missing required field 'listen'", label)
		}
		if h.Upstream == "" {
			return fmt.Errorf("%s: missing required field 'upstream'", label)
		}
		if len(h.Headers) == 0 {
			return fmt.Errorf("%s: missing required field 'headers' (at least one credential header required)", label)
		}
		if prev, dup := seen[h.Listen]; dup {
			return fmt.Errorf("%s: duplicate listen address %q (already used by %s)", label, h.Listen, prev)
		}
		seen[h.Listen] = label
	}

	for i, m := range c.MySQL {
		label := fmt.Sprintf("mysql[%d]", i)
		if m.Listen == "" {
			return fmt.Errorf("%s: missing required field 'listen'", label)
		}
		if m.Upstream == "" {
			return fmt.Errorf("%s: missing required field 'upstream'", label)
		}
		if m.User == "" {
			return fmt.Errorf("%s: missing required field 'user'", label)
		}
		if m.Password == "" {
			return fmt.Errorf("%s: missing required field 'password'", label)
		}
		if prev, dup := seen[m.Listen]; dup {
			return fmt.Errorf("%s: duplicate listen address %q (already used by %s)", label, m.Listen, prev)
		}
		seen[m.Listen] = label
	}

	for i, r := range c.Redis {
		label := fmt.Sprintf("redis[%d]", i)
		if r.Listen == "" {
			return fmt.Errorf("%s: missing required field 'listen'", label)
		}
		if r.Upstream == "" {
			return fmt.Errorf("%s: missing required field 'upstream'", label)
		}
		if prev, dup := seen[r.Listen]; dup {
			return fmt.Errorf("%s: duplicate listen address %q (already used by %s)", label, r.Listen, prev)
		}
		seen[r.Listen] = label
	}

	if len(c.HTTP)+len(c.MySQL)+len(c.Redis) == 0 {
		return fmt.Errorf("config defines no listeners")
	}

	return nil
}

// checkPermissions rejects configs readable by group or world.
func checkPermissions(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("stat config %s: %w", path, err)
	}
	mode := info.Mode().Perm()
	if mode&0o077 != 0 {
		return fmt.Errorf("config file %s has unsafe permissions %04o (must be 0600 or stricter)", path, mode)
	}
	return nil
}
