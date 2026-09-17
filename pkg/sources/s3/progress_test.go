package s3

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestScanProgress_Percent(t *testing.T) {
	tests := []struct {
		name      string
		setup     func(p *scanProgress)
		wantValue int64
	}{
		{
			name:      "nothing counted",
			setup:     func(p *scanProgress) {},
			wantValue: 0,
		},
		{
			name: "listing in flight",
			setup: func(p *scanProgress) {
				p.listingsInFlight.Add(1)
				p.addTotal(10, 1000)
				p.addDone(5, 500)
			},
			wantValue: 0,
		},
		{
			name: "count failed",
			setup: func(p *scanProgress) {
				p.countFailed.Store(true)
				p.addTotal(10, 1000)
				p.addDone(5, 500)
			},
			wantValue: 0,
		},
		{
			name: "partial rounds down",
			setup: func(p *scanProgress) {
				p.addTotal(3, 3000)
				p.addDone(1, 1999)
			},
			wantValue: 66,
		},
		{
			name: "all done caps at 99",
			setup: func(p *scanProgress) {
				p.addTotal(10, 1000)
				p.addDone(10, 1000)
			},
			wantValue: 99,
		},
		{
			name: "done exceeds total caps at 99",
			setup: func(p *scanProgress) {
				p.addTotal(10, 1000)
				p.addDone(12, 1200)
			},
			wantValue: 99,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var p scanProgress
			tt.setup(&p)
			assert.Equal(t, tt.wantValue, p.percent())
		})
	}
}
