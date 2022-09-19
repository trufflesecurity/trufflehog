package sources

import (
	"sync"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"google.golang.org/protobuf/testing/protocmp"
)

func TestCounter_IncTotal(t *testing.T) {
	tests := []struct {
		name string
		want int
	}{
		{
			name: "increment total 50 times",
			want: 50,
		},
		{
			name: "increment total 0 times",
		},
		{
			name: "increment total 1 times",
			want: 1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &Counter{}

			var wg sync.WaitGroup
			wg.Add(tt.want)
			for i := 0; i < tt.want; i++ {
				go func(c *Counter) {
					defer wg.Done()
					c.IncTotal()
				}(c)
			}

			wg.Wait()
			if got := c.totalCnt; int(got) != tt.want {
				t.Errorf("Counter.IncTotal() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCounter_IncSuccess(t *testing.T) {
	tests := []struct {
		name string
		want int
	}{
		{
			name: "increment total 50 times",
			want: 50,
		},
		{
			name: "increment total 0 times",
		},
		{
			name: "increment total 1 times",
			want: 1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &Counter{}

			var wg sync.WaitGroup
			wg.Add(tt.want)
			for i := 0; i < tt.want; i++ {
				go func(c *Counter) {
					defer wg.Done()
					c.IncSuccess()
				}(c)
			}

			wg.Wait()
			if got := c.Get(); int(got) != tt.want {
				t.Errorf("Counter.IncTotal() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestProgress_Update(t *testing.T) {
	tests := []struct {
		name, msg, encodeResumeInfo string
		counter                     uint32
		scope, routines, want       int
	}{
		{
			name:     "update progress, no counter",
			scope:    100,
			routines: 10,
			want:     10,
		},
		{
			name:     "update progress, counter 5",
			scope:    100,
			routines: 10,
			counter:  5,
			want:     15,
		},
		{
			name:     "update progress, counter 50",
			scope:    100,
			routines: 10,
			counter:  50,
			want:     60,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &Progress{}
			p.Counter.successCnt = tt.counter

			var wg sync.WaitGroup
			wg.Add(tt.routines)
			for i := 0; i < tt.routines; i++ {
				p.Counter.IncSuccess()
				go func(p *Progress) {
					defer wg.Done()
					p.Update(tt.scope, tt.msg, tt.encodeResumeInfo)
				}(p)
			}

			wg.Wait()
			if got := p.PercentComplete; int(got) != tt.want {
				t.Errorf("Progress.Update(%v, %v, %v): got %v, want %v", tt.scope, tt.msg, tt.encodeResumeInfo, got, tt.want)
			}
		})
	}
}

func TestProgress_Complete(t *testing.T) {
	tests := []struct {
		name,
		msg string
		curProgress, wantProgress *Progress
	}{
		{
			name: "complete progress",
			msg:  "completed scanning thinger",
			curProgress: &Progress{
				PercentComplete:   42,
				Message:           "scanning thinger",
				EncodedResumeInfo: "resume info",
				SectionsRemaining: 12,
				SectionsCompleted: 2,
			},
			wantProgress: &Progress{
				PercentComplete:   100,
				Message:           "completed scanning thinger",
				EncodedResumeInfo: "",
				SectionsRemaining: 0,
				SectionsCompleted: 14,
			},
		},
		{
			name: "complete progress with no message",
			curProgress: &Progress{
				PercentComplete:   80,
				Message:           "scanning thinger2",
				EncodedResumeInfo: "resume info2",
				SectionsRemaining: 2,
				SectionsCompleted: 42,
			},
			wantProgress: &Progress{
				PercentComplete:   100,
				EncodedResumeInfo: "",
				SectionsRemaining: 0,
				SectionsCompleted: 44,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.curProgress.Counter.successCnt = uint32(tt.wantProgress.SectionsCompleted)
			tt.curProgress.Complete(tt.msg)

			ignoreOpts := cmpopts.IgnoreFields(Progress{}, "mut", "Counter")
			if !cmp.Equal(tt.curProgress, tt.wantProgress, protocmp.Transform(), ignoreOpts) {
				t.Errorf("Progress.Complete(%v): got %v, want %v", tt.msg, tt.curProgress, tt.wantProgress)
			}
		})
	}
}
