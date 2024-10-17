package channelmetrics

import "time"

// noopCollector is a default implementation of the MetricsCollector interface
// for internal package use only.
type noopCollector struct{}

func (noopCollector) RecordProduceDuration(duration time.Duration) {}
func (noopCollector) RecordConsumeDuration(duration time.Duration) {}
func (noopCollector) RecordChannelLen(size int)                    {}
func (noopCollector) RecordChannelCap(capacity int)                {}
