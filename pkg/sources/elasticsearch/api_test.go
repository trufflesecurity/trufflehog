package elasticsearch

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSource_GetShardListPreference(t *testing.T) {
	index := Index{name: "index1", primaryShards: []int{1, 4, 3}, documentCount: 20}
	index2 := Index{name: "index2", primaryShards: []int{1}, documentCount: 10}
	index3 := Index{name: "index3", primaryShards: []int{}, documentCount: 0}

	assert.Equal(t, "_shards:1,4,3", getShardListPreference(index.primaryShards))
	assert.Equal(t, "_shards:1", getShardListPreference(index2.primaryShards))
	assert.Equal(t, "", getShardListPreference(index3.primaryShards))
}
