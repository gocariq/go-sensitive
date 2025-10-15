package masker

import (
	"encoding/json"
	"regexp"
	"strings"
	"sync"
)

type Masker interface {
	Mask(data interface{}) interface{}
	MaskInterface(data interface{}) interface{}
}

type DefaultMasker struct {
	patterns []Pattern
	cache    *regexp.Regexp
	mu       sync.RWMutex
	compiled bool
}

func NewWithOpts(opts ...Option) Masker {

	var config Config
	if len(opts) == 0 {
		config = DefaultConfig()
	} else {
		config = Config{}
	}

	for _, opt := range opts {
		opt(&config)
	}

	masker := &DefaultMasker{
		patterns: config.Patterns,
	}
	masker.compilePatterns()

	return masker
}

func New() Masker {

	config := DefaultConfig()
	masker := &DefaultMasker{
		patterns: config.Patterns,
	}
	masker.compilePatterns()

	return masker
}

func (dm *DefaultMasker) compilePatterns() {
	dm.mu.Lock()
	defer dm.mu.Unlock()

	if len(dm.patterns) > 0 {
		var regexParts []string
		for _, pattern := range dm.patterns {
			if pattern.Regex != "" {
				regexParts = append(regexParts, pattern.Regex)
			}
		}
		if len(regexParts) > 0 {
			combinedRegex := strings.Join(regexParts, "|")
			dm.cache = regexp.MustCompile(combinedRegex)
			dm.compiled = true
		}
	}
}

func (dm *DefaultMasker) Mask(data interface{}) interface{} {
	return dm.processValue(data)
}

func (dm *DefaultMasker) MaskInterface(data interface{}) interface{} {
	return dm.processInterface(data)
}

func (dm *DefaultMasker) processValue(value interface{}) interface{} {
	switch v := value.(type) {
	case string:
		return dm.maskString(v)
	case map[string]interface{}:
		return dm.processMap(v)
	case []interface{}:
		return dm.processSlice(v)
	case []map[string]interface{}:
		return dm.processMapSlice(v)
	case map[interface{}]interface{}:
		return dm.processInterfaceMap(v)
	default:
		return v
	}
}

func (dm *DefaultMasker) processMap(m map[string]interface{}) map[string]interface{} {
	result := make(map[string]interface{})
	for key, value := range m {
		result[key] = dm.processValue(value)
	}
	return result
}

func (dm *DefaultMasker) processInterfaceMap(m map[interface{}]interface{}) map[interface{}]interface{} {
	result := make(map[interface{}]interface{})
	for key, value := range m {
		result[key] = dm.processValue(value)
	}
	return result
}

func (dm *DefaultMasker) processSlice(s []interface{}) []interface{} {
	result := make([]interface{}, len(s))
	for i, item := range s {
		result[i] = dm.processValue(item)
	}
	return result
}

func (dm *DefaultMasker) processMapSlice(s []map[string]interface{}) []map[string]interface{} {
	result := make([]map[string]interface{}, len(s))
	for i, item := range s {
		result[i] = dm.processMap(item)
	}
	return result
}

func (dm *DefaultMasker) maskString(s string) string {
	if !dm.compiled {
		return s
	}

	dm.mu.RLock()
	defer dm.mu.RUnlock()

	return dm.cache.ReplaceAllStringFunc(s, func(match string) string {
		for _, pattern := range dm.patterns {
			if pattern.MaskFunc != nil {
				compiledPattern := regexp.MustCompile(pattern.Regex)
				if compiledPattern.MatchString(match) {
					return pattern.MaskFunc(match)
				}
			}
		}
		return match
	})
}

func (dm *DefaultMasker) processInterface(v interface{}) map[string]interface{} {
	data, _ := StructToMap(v)

	result := make(map[string]interface{})
	for key, value := range data {
		result[key] = dm.processValue(value)
	}
	return result
}

func StructToMap(obj interface{}) (map[string]interface{}, error) {
	data, err := json.Marshal(obj)
	if err != nil {
		return nil, err
	}

	var result map[string]interface{}
	err = json.Unmarshal(data, &result)
	if err != nil {
		return nil, err
	}

	return result, nil
}

func MaskData(data interface{}, opts ...Option) interface{} {
	masker := NewWithOpts(opts...)
	return masker.Mask(data)
}

func MaskDataInterface(data interface{}, opts ...Option) interface{} {
	masker := NewWithOpts(opts...)
	return masker.MaskInterface(data)
}

func MaskString(data string, opts ...Option) string {
	masker := NewWithOpts(opts...)
	result := masker.Mask(data)
	if str, ok := result.(string); ok {
		return str
	}
	return data
}
