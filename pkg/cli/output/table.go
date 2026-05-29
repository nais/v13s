package output

import (
	"github.com/fatih/color"
	"github.com/rodaine/table"
)

var (
	HeaderFmt = color.New(color.FgGreen, color.Underline).SprintfFunc()
	ColumnFmt = color.New(color.FgYellow).SprintfFunc()
)

// Table is a thin wrapper around rodaine/table that applies the standard
// green-header / yellow-first-column formatting used across all CLI commands.
type Table struct {
	headers []any
	rows    [][]string
}

func New(headers ...any) *Table {
	return &Table{headers: headers}
}

func (t *Table) AddRow(row ...string) {
	t.rows = append(t.rows, row)
}

func (t *Table) Print() {
	tbl := table.New(t.headers...)
	tbl.WithHeaderFormatter(HeaderFmt).WithFirstColumnFormatter(ColumnFmt)
	tbl.SetRows(t.rows)
	tbl.Print()
}
