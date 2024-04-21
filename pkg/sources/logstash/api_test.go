package logstash

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSource_GetShardListPreference(t *testing.T) {
	index := Index{Name: "index1", PrimaryShards: []int{1, 4, 3}, DocumentCount: 20}
	index2 := Index{Name: "index2", PrimaryShards: []int{1}, DocumentCount: 10}
	index3 := Index{Name: "index3", PrimaryShards: []int{}, DocumentCount: 0}

	assert.Equal(t, "_shards:1,4,3", getShardListPreference(&index))
	assert.Equal(t, "_shards:1", getShardListPreference(&index2))
	assert.Equal(t, "", getShardListPreference(&index3))
}
