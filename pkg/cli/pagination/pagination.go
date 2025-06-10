package pagination

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"time"
)

func Paginate(limit int, f func(offset int) (int, bool, error)) error {
	offset := 0
	for {
		start := time.Now()
		total, hasNext, err := f(offset)
		if err != nil {
			return err
		}
		numFetched := offset + limit
		if numFetched > total {
			numFetched = total
		}
		fmt.Printf("Fetched %d of total '%d' in %f seconds.\n", numFetched, total, time.Since(start).Seconds())

		// Check if there is another page
		if !hasNext {
			fmt.Printf("No more pages available.\n")
			break
		}

		// Ask user for input to continue paginate
		fmt.Println("Press 'n' for next page, 'q' to quit:")
		reader := bufio.NewReader(os.Stdin)
		input, _ := reader.ReadString('\n')
		input = strings.TrimSpace(input)

		if input == "q" {
			break
		} else if input == "n" {
			offset += limit
		} else {
			fmt.Println("Invalid input. Use 'n' for next page or 'q' to quit.")
		}
	}
	return nil
}
