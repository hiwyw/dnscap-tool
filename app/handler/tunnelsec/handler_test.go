package tunnelsec

import (
	"log"
	"testing"

	"github.com/zdnscloud/g53"
)

func TestExistEncoding(t *testing.T) {
	sn, _ := g53.NameFromString("www.gslb.x9/01o3Sfk0Xn4bGKU46u6USnyfReF1F61bhL239wIA=.")
	log.Printf("subdomain label count==>%d", sn.LabelCount())
	log.Printf("www.gslb.a==>%v", existEncoding(sn, 8))
}
