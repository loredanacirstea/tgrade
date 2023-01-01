package types

const (
	// needs to be same name as ethermint's evm module
	// if we use the ethermint's keeper for queries
	ModuleName = "ewasm"

	StoreKey = ModuleName

	RouterKey = ModuleName

	QuerierRoute = ModuleName

	// TransientKey is the key to access the Ewasm transient store, that is reset
	// during the Commit phase.
	TransientKey = "transient_" + ModuleName
)

// // prefix bytes for the ewasm persistent store
// const (
// 	prefixTodo = iota + 1
// )

// // KVStore key prefixes
// var (
// 	KeyPrefixTodo = []byte{prefixTodo}
// )
