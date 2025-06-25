package sources

import (
	"errors"
	"fmt"
	"sync"
	"testing"
)

var testError = fmt.Errorf("simulated failure")

func TestNewScanErrors(t *testing.T) {
	testCases := []struct {
		name     string
		projects int
		want     *ScanErrors
	}{
		{
			name:     "no projects",
			projects: 0,
			want: &ScanErrors{
				errors: make([]error, 0),
			},
		},
		{
			name:     "one project",
			projects: 1,
			want: &ScanErrors{
				errors: make([]error, 0, 1),
			},
		},
		{
			name:     "fifty projects",
			projects: 50,
			want: &ScanErrors{
				errors: make([]error, 0, 50),
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got := NewScanErrors()

			if !errors.Is(got.Errors(), tc.want.Errors()) {
				t.Errorf("got %+v, want %+v", got, tc.want)
			}
		})
	}
}

func TestScanErrorsAdd(t *testing.T) {
	testCases := []struct {
		name        string
		concurrency int
		wantErr     int
	}{
		{
			name:        "no concurrency, no errors",
			concurrency: 1,
			wantErr:     0,
		},
		{
			name:        "no concurrency, one error",
			concurrency: 1,
			wantErr:     1,
		},
		{
			name:        "concurrency, 100 errors",
			concurrency: 10,
			wantErr:     100,
		},
		{
			name:        "concurrency, 1000 errors",
			concurrency: 10,
			wantErr:     1000,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			se := NewScanErrors()

			var wg sync.WaitGroup
			for i := 0; i < tc.concurrency; i++ {
				wg.Add(1)
				go func() {
					for j := 0; j < tc.wantErr/tc.concurrency; j++ {
						se.Add(testError)
					}
					wg.Done()
				}()
			}
			wg.Wait()

			if se.Count() != uint64(tc.wantErr) {
				t.Errorf("got %d, want %d", se.Count(), tc.wantErr)
			}
		})
	}
}

func TestScanErrorsCount(t *testing.T) {
	testCases := []struct {
		name        string
		concurrency int
		wantErrCnt  int
	}{
		{
			name:        "no concurrency, no errors",
			concurrency: 1,
			wantErrCnt:  0,
		},
		{
			name:        "no concurrency, one error",
			concurrency: 1,
			wantErrCnt:  1,
		},
		{
			name:        "concurrency, 100 errors",
			concurrency: 10,
			wantErrCnt:  100,
		},
		{
			name:        "concurrency, 2048 errors",
			concurrency: 8,
			wantErrCnt:  2048,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			se := NewScanErrors()

			var wg sync.WaitGroup
			for i := 0; i < tc.concurrency; i++ {
				wg.Add(1)
				go func() {
					for j := 0; j < tc.wantErrCnt/tc.concurrency; j++ {
						se.Add(testError)
					}
					wg.Done()
				}()
			}
			wg.Wait()

			if se.Count() != uint64(tc.wantErrCnt) {
				t.Errorf("got %d, want %d", se.Count(), tc.wantErrCnt)
			}
		})
	}
}

func TestScanErrorsString(t *testing.T) {
	se := NewScanErrors()
	se.Add(testError)
	want := `["` + testError.Error() + `"]`
	if got := fmt.Sprintf("%v", se); got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}
