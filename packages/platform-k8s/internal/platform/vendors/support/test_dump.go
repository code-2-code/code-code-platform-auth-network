package support

import (
	"fmt"
	"encoding/json"
)

func Dump() {
	sets := StartupExternalAccessSets()
	b, _ := json.MarshalIndent(sets, "", "  ")
	fmt.Println(string(b))
}
