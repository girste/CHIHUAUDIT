package metrics

import (
	"strings"
	"testing"
)

func TestCounter(t *testing.T) {
	c := &Counter{}

	// Test initial value
	if got := c.Value(); got != 0 {
		t.Errorf("Counter.Value() = %v, want 0", got)
	}

	// Test Inc
	c.Inc()
	if got := c.Value(); got != 1 {
		t.Errorf("Counter.Value() after Inc() = %v, want 1", got)
	}

	// Test Add
	c.Add(5.5)
	if got := c.Value(); got != 6.5 {
		t.Errorf("Counter.Value() after Add(5.5) = %v, want 6.5", got)
	}
}

func TestGauge(t *testing.T) {
	g := &Gauge{}

	// Test Set
	g.Set(10.5)
	if got := g.Value(); got != 10.5 {
		t.Errorf("Gauge.Value() = %v, want 10.5", got)
	}

	// Test Inc
	g.Inc()
	if got := g.Value(); got != 11.5 {
		t.Errorf("Gauge.Value() after Inc() = %v, want 11.5", got)
	}

	// Test Dec
	g.Dec()
	if got := g.Value(); got != 10.5 {
		t.Errorf("Gauge.Value() after Dec() = %v, want 10.5", got)
	}

	// Test Add with negative
	g.Add(-5.5)
	if got := g.Value(); got != 5.0 {
		t.Errorf("Gauge.Value() after Add(-5.5) = %v, want 5.0", got)
	}
}

func TestHistogram(t *testing.T) {
	h := &Histogram{values: make([]float64, 0)}

	// Test initial state
	if got := h.Sum(); got != 0 {
		t.Errorf("Histogram.Sum() = %v, want 0", got)
	}
	if got := h.Count(); got != 0 {
		t.Errorf("Histogram.Count() = %v, want 0", got)
	}

	// Test observations
	h.Observe(1.5)
	h.Observe(2.5)
	h.Observe(3.0)

	if got := h.Sum(); got != 7.0 {
		t.Errorf("Histogram.Sum() = %v, want 7.0", got)
	}
	if got := h.Count(); got != 3 {
		t.Errorf("Histogram.Count() = %v, want 3", got)
	}
}

func TestRegistry(t *testing.T) {
	reg := NewRegistry()

	t.Run("Counter creation and reuse", func(t *testing.T) {
		labels := map[string]string{"method": "GET"}
		c1 := reg.Counter("http_requests", labels)
		c1.Add(10)

		c2 := reg.Counter("http_requests", labels)
		if c1 != c2 {
			t.Error("Registry should return same counter for same name+labels")
		}
		if c2.Value() != 10 {
			t.Errorf("Counter value = %v, want 10", c2.Value())
		}
	})

	t.Run("Gauge creation", func(t *testing.T) {
		g := reg.Gauge("memory_usage", nil)
		g.Set(256.5)
		if g.Value() != 256.5 {
			t.Errorf("Gauge value = %v, want 256.5", g.Value())
		}
	})

	t.Run("Histogram creation", func(t *testing.T) {
		h := reg.Histogram("request_duration", map[string]string{"endpoint": "/api"})
		h.Observe(0.5)
		h.Observe(1.5)
		if h.Count() != 2 {
			t.Errorf("Histogram count = %v, want 2", h.Count())
		}
	})
}

func TestExportPrometheus(t *testing.T) {
	reg := NewRegistry()

	// Add some metrics
	reg.Counter("test_counter", map[string]string{"label": "value"}).Add(42)
	reg.Gauge("test_gauge", nil).Set(123.45)
	h := reg.Histogram("test_histogram", nil)
	h.Observe(1.0)
	h.Observe(2.0)

	output := reg.ExportPrometheus()

	// Verify output contains expected patterns
	tests := []struct {
		name    string
		pattern string
	}{
		{"counter type", "# TYPE test_counter counter"},
		{"counter value", "test_counter"},
		{"gauge type", "# TYPE test_gauge gauge"},
		{"gauge value", "123.45"},
		{"histogram type", "# TYPE test_histogram histogram"},
		{"histogram sum", "test_histogram_sum"},
		{"histogram count", "test_histogram_count"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if !strings.Contains(output, tt.pattern) {
				t.Errorf("ExportPrometheus() output missing %q", tt.pattern)
			}
		})
	}
}

func TestMakeKey(t *testing.T) {
	reg := NewRegistry()

	tests := []struct {
		name   string
		metric string
		labels map[string]string
		want   string
	}{
		{
			name:   "no labels",
			metric: "test_metric",
			labels: nil,
			want:   "test_metric",
		},
		{
			name:   "with labels",
			metric: "http_requests",
			labels: map[string]string{"method": "GET", "status": "200"},
			// Key includes metric + all label pairs (order may vary)
			want: "http_requests",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := reg.makeKey(tt.metric, tt.labels)
			if tt.labels == nil {
				if got != tt.want {
					t.Errorf("makeKey() = %v, want %v", got, tt.want)
				}
			} else {
				// With labels, just verify it starts with metric name
				if !strings.HasPrefix(got, tt.metric) {
					t.Errorf("makeKey() = %v, want prefix %v", got, tt.metric)
				}
			}
		})
	}
}

func TestGetRegistry(t *testing.T) {
	reg1 := GetRegistry()
	reg2 := GetRegistry()

	if reg1 != reg2 {
		t.Error("GetRegistry() should return same instance (singleton)")
	}

	// Verify it's functional
	reg1.Counter("test", nil).Inc()
	if reg2.Counter("test", nil).Value() != 1 {
		t.Error("Global registry not shared correctly")
	}
}

func TestConcurrentAccess(t *testing.T) {
	reg := NewRegistry()
	counter := reg.Counter("concurrent_test", nil)

	// Test concurrent increments
	done := make(chan bool)
	for i := 0; i < 100; i++ {
		go func() {
			counter.Inc()
			done <- true
		}()
	}

	for i := 0; i < 100; i++ {
		<-done
	}

	if counter.Value() != 100 {
		t.Errorf("Counter value = %v, want 100 (concurrent safety issue)", counter.Value())
	}
}
