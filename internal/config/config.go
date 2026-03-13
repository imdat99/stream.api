package config

import (
	"strings"

	"github.com/spf13/viper"
)

type Config struct {
	Server   ServerConfig
	Database DatabaseConfig
	Redis    RedisConfig
	JWT      JWTConfig
	Google   GoogleConfig
	Frontend FrontendConfig
	CORS     CORSConfig
	Email    EmailConfig
	AWS      AWSConfig
	Render   RenderConfig
	Internal InternalAuthConfig
}

type ServerConfig struct {
	Port     string `mapstructure:"port"`
	GRPCPort string `mapstructure:"grpc_port"`
	Mode     string `mapstructure:"mode"` // e.g., "debug", "release"
}

type RenderConfig struct {
	AgentSecret   string `mapstructure:"agent_secret"`
	EnableMetrics bool   `mapstructure:"enable_metrics"`
	EnableTracing bool   `mapstructure:"enable_tracing"`
	OTLPEndpoint  string `mapstructure:"otlp_endpoint"`
	ServiceName   string `mapstructure:"service_name"`
}

type InternalAuthConfig struct {
	Marker string `mapstructure:"marker"`
}

type DatabaseConfig struct {
	DSN string
}

type RedisConfig struct {
	Addr     string
	Password string
	DB       int
}

type JWTConfig struct {
	Secret string
}

type GoogleConfig struct {
	ClientID       string `mapstructure:"client_id"`
	ClientSecret   string `mapstructure:"client_secret"`
	RedirectURL    string `mapstructure:"redirect_url"`
	StateTTLMinute int    `mapstructure:"state_ttl_minutes"`
}

type FrontendConfig struct {
	BaseURL                string `mapstructure:"base_url"`
	GoogleAuthFinalizePath string `mapstructure:"google_auth_finalize_path"`
}

type CORSConfig struct {
	AllowOrigins []string `mapstructure:"allow_origins"`
}

type EmailConfig struct {
	From string
	// Add SMTP settings here later
}

type AWSConfig struct {
	Region         string
	Bucket         string
	AccessKey      string
	SecretKey      string
	Endpoint       string // Optional: for MinIO or other S3 compatible
	ForcePathStyle bool
}

func LoadConfig() (*Config, error) {
	v := viper.New()

	// Set defaults
	v.SetDefault("server.port", "8080")
	v.SetDefault("server.grpc_port", "9000")
	v.SetDefault("server.mode", "debug")
	v.SetDefault("redis.db", 0)
	v.SetDefault("render.enable_metrics", true)
	v.SetDefault("render.enable_tracing", false)
	v.SetDefault("render.service_name", "stream-api-render")
	v.SetDefault("google.state_ttl_minutes", 10)
	v.SetDefault("frontend.google_auth_finalize_path", "/auth/google/finalize")
	v.SetDefault("internal.marker", "")
	v.SetDefault("cors.allow_origins", []string{"http://localhost:5173", "http://localhost:8080", "http://localhost:8081"})

	// Environment variable settings
	v.SetEnvPrefix("APP")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()

	// Config file settings (optional)
	v.SetConfigName("config")
	v.SetConfigType("yaml")
	v.AddConfigPath(".")
	v.AddConfigPath("./config")

	if err := v.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return nil, err
		}
		// Config file not found is fine, we rely on env vars or defaults
	}

	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, err
	}

	return &cfg, nil
}
