// Package metrics provides vendor-neutral metrics collection and export.
// Supports Prometheus text format (compatible with Grafana, Datadog, New Relic, etc.)
package metrics

import (
	"fmt"
	"sync"
	"time"
)

// Counter represents a monotonically increasing counter
type Counter struct {
	mu    sync.RWMutex
	value float64
}

// Inc increments the counter by 1
func (c *Counter) Inc() {
	c.Add(1)
}

// Add adds the given value to the counter
func (c *Counter) Add(delta float64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.value += delta
}

// Value returns the current counter value
func (c *Counter) Value() float64 {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.value
}

// Gauge represents a value that can go up and down
type Gauge struct {
	mu    sync.RWMutex
	value float64
}

// Set sets the gauge to the given value
func (g *Gauge) Set(value float64) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.value = value
}

// Inc increments the gauge by 1
func (g *Gauge) Inc() {
	g.Add(1)
}

// Dec decrements the gauge by 1
func (g *Gauge) Dec() {
	g.Add(-1)
}

// Add adds the given value to the gauge
func (g *Gauge) Add(delta float64) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.value += delta
}

// Value returns the current gauge value
func (g *Gauge) Value() float64 {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.value
}

// Histogram tracks distribution of values
type Histogram struct {
	mu     sync.RWMutex
	sum    float64
	count  uint64
	values []float64
}

// Observe adds a single observation to the histogram
func (h *Histogram) Observe(value float64) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.sum += value
	h.count++
	h.values = append(h.values, value)
}

// Sum returns the sum of all observations
func (h *Histogram) Sum() float64 {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.sum
}

// Count returns the count of observations
func (h *Histogram) Count() uint64 {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.count
}

// Registry holds all metrics
type Registry struct {
	mu         sync.RWMutex
	counters   map[string]*Counter
	gauges     map[string]*Gauge
	histograms map[string]*Histogram
	labels     map[string]map[string]string
}

// NewRegistry creates a new metrics registry
func NewRegistry() *Registry {
	return &Registry{
		counters:   make(map[string]*Counter),
		gauges:     make(map[string]*Gauge),
		histograms: make(map[string]*Histogram),
		labels:     make(map[string]map[string]string),
	}
}

// Counter gets or creates a counter
func (r *Registry) Counter(name string, labels map[string]string) *Counter {
	key := r.makeKey(name, labels)
	r.mu.Lock()
	defer r.mu.Unlock()

	if c, ok := r.counters[key]; ok {
		return c
	}

	c := &Counter{}
	r.counters[key] = c
	r.labels[key] = labels
	return c
}

// Gauge gets or creates a gauge
func (r *Registry) Gauge(name string, labels map[string]string) *Gauge {
	key := r.makeKey(name, labels)
	r.mu.Lock()
	defer r.mu.Unlock()

	if g, ok := r.gauges[key]; ok {
		return g
	}

	g := &Gauge{}
	r.gauges[key] = g
	r.labels[key] = labels
	return g
}

// Histogram gets or creates a histogram
func (r *Registry) Histogram(name string, labels map[string]string) *Histogram {
	key := r.makeKey(name, labels)
	r.mu.Lock()
	defer r.mu.Unlock()

	if h, ok := r.histograms[key]; ok {
		return h
	}

	h := &Histogram{values: make([]float64, 0)}
	r.histograms[key] = h
	r.labels[key] = labels
	return h
}

// makeKey creates a unique key for a metric with labels
func (r *Registry) makeKey(name string, labels map[string]string) string {
	if len(labels) == 0 {
		return name
	}
	key := name
	for k, v := range labels {
		key += fmt.Sprintf("_%s_%s", k, v)
	}
	return key
}

// ExportPrometheus exports metrics in Prometheus text format
func (r *Registry) ExportPrometheus() string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var output string
	timestamp := time.Now().UnixMilli()

	// Export counters
	for key, counter := range r.counters {
		name, labelStr := r.formatMetric(key)
		output += fmt.Sprintf("# TYPE %s counter\n", name)
		output += fmt.Sprintf("%s%s %.2f %d\n", name, labelStr, counter.Value(), timestamp)
	}

	// Export gauges
	for key, gauge := range r.gauges {
		name, labelStr := r.formatMetric(key)
		output += fmt.Sprintf("# TYPE %s gauge\n", name)
		output += fmt.Sprintf("%s%s %.2f %d\n", name, labelStr, gauge.Value(), timestamp)
	}

	// Export histograms
	for key, hist := range r.histograms {
		name, labelStr := r.formatMetric(key)
		output += fmt.Sprintf("# TYPE %s histogram\n", name)
		output += fmt.Sprintf("%s_sum%s %.2f %d\n", name, labelStr, hist.Sum(), timestamp)
		output += fmt.Sprintf("%s_count%s %d %d\n", name, labelStr, hist.Count(), timestamp)
	}

	return output
}

// formatMetric extracts metric name and formats labels for Prometheus
func (r *Registry) formatMetric(key string) (string, string) {
	labels := r.labels[key]
	if len(labels) == 0 {
		return key, ""
	}

	// Extract base name (before first label)
	name := key
	for k := range labels {
		idx := len(name) - len(k) - len(labels[k]) - 2
		if idx > 0 {
			name = name[:idx]
		}
		break
	}

	// Format labels: {key1="value1",key2="value2"}
	labelStr := "{"
	first := true
	for k, v := range labels {
		if !first {
			labelStr += ","
		}
		labelStr += fmt.Sprintf(`%s="%s"`, k, v)
		first = false
	}
	labelStr += "}"

	return name, labelStr
}

// Global registry
var defaultRegistry = NewRegistry()

// GetRegistry returns the default global registry
func GetRegistry() *Registry {
	return defaultRegistry
}
