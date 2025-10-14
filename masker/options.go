package masker

type Pattern struct {
	Name     string
	Regex    string
	MaskFunc func(string) string
}

type Config struct {
	Patterns []Pattern
}

type Option func(*Config)

func WithPatterns(patterns []Pattern) Option {
	return func(c *Config) {
		c.Patterns = patterns
	}
}

func WithCustomPattern(name, regex string, maskFunc func(string) string) Option {
	return func(c *Config) {
		c.Patterns = append(c.Patterns, Pattern{
			Name:     name,
			Regex:    regex,
			MaskFunc: maskFunc,
		})
	}
}

func DefaultConfig() Config {
	return Config{
		Patterns: DefaultPatterns(),
	}
}
