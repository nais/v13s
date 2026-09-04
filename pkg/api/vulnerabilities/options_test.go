package vulnerabilities

import "testing"

func TestPriorityFilterAcceptsMultiplePriorities(t *testing.T) {
	filter := GetFilter(
		PriorityFilter(Priority_PRIORITY_HIGH, Priority_PRIORITY_ELEVATED),
	)

	if len(filter.GetPriorities()) != 2 {
		t.Fatalf("expected 2 priorities, got %d", len(filter.GetPriorities()))
	}
	if filter.GetPriorities()[0] != Priority_PRIORITY_HIGH || filter.GetPriorities()[1] != Priority_PRIORITY_ELEVATED {
		t.Fatalf("unexpected priorities: %#v", filter.GetPriorities())
	}
}

func TestPriorityFilterSinglePriorityUsesExactSetField(t *testing.T) {
	filter := GetFilter(
		PriorityFilter(Priority_PRIORITY_HIGH),
	)

	if len(filter.GetPriorities()) != 1 || filter.GetPriorities()[0] != Priority_PRIORITY_HIGH {
		t.Fatalf("expected exact priority set [HIGH], got %#v", filter.GetPriorities())
	}
}
