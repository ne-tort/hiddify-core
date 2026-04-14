package mieru

import (
	"fmt"
)

func beginAndEndPortFromPortRange(portRange string) (int, int, error) {
	var begin, end int

	_, err := fmt.Sscanf(portRange, "%d-%d", &begin, &end)
	return begin, end, err

}
