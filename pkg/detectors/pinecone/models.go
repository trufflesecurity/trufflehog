package pinecone

type listIndexesResponse struct {
	Indexes []indexInfo `json:"indexes"`
}

type indexInfo struct {
	Name string    `json:"name"`
	Host string    `json:"host"`
	Spec indexSpec `json:"spec"`
}

type indexSpec struct {
	Serverless *serverlessSpec `json:"serverless,omitempty"`
}

type serverlessSpec struct {
	Cloud  string `json:"cloud"`
	Region string `json:"region"`
}
