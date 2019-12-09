package nftables

import (
	"github.com/sbezverk/nftableslib"
)

// InitNFTables initializes connection to netfilter and instantiates nftables table interface
func InitNFTables() (nftableslib.TablesInterface, error ) {
	conn := nftableslib.InitConn()
	ti := nftableslib.InitNFTables(conn)

	return ti, nil
}