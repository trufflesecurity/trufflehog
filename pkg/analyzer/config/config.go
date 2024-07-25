package config

// TODO: separate CLI configuration from analysis configuration.
type Config struct {
	LoggingEnabled bool
	LogFile        string
	ShowAll        bool
}
