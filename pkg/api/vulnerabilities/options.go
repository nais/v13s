package vulnerabilities

import (
	"time"

	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/timestamppb"
)

var _ Option = (*funcOption)(nil)

type Option interface {
	Apply(*Options)
}

type OrderByField string

type WorkLoadType string

const (
	WorkloadTypeApp WorkLoadType = "app"
	WorkloadTypeJob WorkLoadType = "job"
)

const (
	OrderByAffectedWorkloads OrderByField = "affected_workloads"
	OrderByCluster           OrderByField = "cluster"
	OrderByCreatedAt         OrderByField = "created_at"
	OrderByCritical          OrderByField = "critical"
	OrderByCveId             OrderByField = "cve_id"
	OrderByCvssScore         OrderByField = "cvss_score"
	OrderByHigh              OrderByField = "high"
	OrderByLow               OrderByField = "low"
	OrderByMedium            OrderByField = "medium"
	OrderByNamespace         OrderByField = "namespace"
	OrderByPackage           OrderByField = "package"
	OrderByReason            OrderByField = "reason"
	OrderByRiskScore         OrderByField = "risk_score"
	OrderBySeverity          OrderByField = "severity"
	OrderBySeveritySince     OrderByField = "severity_since"
	OrderBySuppressed        OrderByField = "suppressed"
	OrderByUnassigned        OrderByField = "unassigned"
	OrderByUpdatedAt         OrderByField = "updated_at"
	OrderByWorkload          OrderByField = "workload"
)

// Map of valid fields
var validOrderByFields = map[OrderByField]struct{}{
	OrderByAffectedWorkloads: {},
	OrderByCluster:           {},
	OrderByCreatedAt:         {},
	OrderByCritical:          {},
	OrderByCveId:             {},
	OrderByCvssScore:         {},
	OrderByHigh:              {},
	OrderByLow:               {},
	OrderByMedium:            {},
	OrderByNamespace:         {},
	OrderByPackage:           {},
	OrderByReason:            {},
	OrderByRiskScore:         {},
	OrderBySeverity:          {},
	OrderBySeveritySince:     {},
	OrderBySuppressed:        {},
	OrderByUnassigned:        {},
	OrderByUpdatedAt:         {},
	OrderByWorkload:          {},
}

// String method for OrderByField
func (o OrderByField) String() string {
	return string(o)
}

// IsValid method using a map for efficient lookup
func (o OrderByField) IsValid() bool {
	_, exists := validOrderByFields[o]
	return exists
}

const DefaultLimit = 50

type Options struct {
	CallOptions       []grpc.CallOption
	Filter            *Filter
	IncludeSuppressed bool
	IncludeUnresolved bool
	Limit             int32
	Offset            int32
	OrderBy           *OrderBy
	Since             *timestamppb.Timestamp
	SinceType         *SinceType
	Severity          *Severity
	ExcludeNamespaces []string
	ExcludeClusters   []string
}

type VulnerabilityFilter struct {
	CveIds    []string
	CvssScore *float64
}

type funcOption struct {
	f func(options *Options)
}

func newFuncOption(f func(o *Options)) *funcOption {
	return &funcOption{
		f: f,
	}
}

func (fo *funcOption) Apply(o *Options) {
	fo.f(o)
}

func GetOptions(opts ...Option) *Options {
	return applyOptions(opts...)
}

func GetFilter(opts ...Option) *Filter {
	return applyOptions(opts...).Filter
}

func GetCallOptions(opts ...Option) []grpc.CallOption {
	return applyOptions(opts...).CallOptions
}

func GetIncludeSuppressed(opts ...Option) bool {
	return applyOptions(opts...).IncludeSuppressed
}

func GetLimit(opts ...Option) int32 {
	return applyOptions(opts...).Limit
}

func GetOffset(opts ...Option) int32 {
	return applyOptions(opts...).Offset
}

func GetOrderBy(opts ...Option) *OrderBy {
	return applyOptions(opts...).OrderBy
}

func GetSince(opts ...Option) *timestamppb.Timestamp {
	return applyOptions(opts...).Since
}

func GetIncludedUnresolved(opts ...Option) bool { return applyOptions(opts...).IncludeUnresolved }

// TODO: document the Options
func CallOptions(opts ...grpc.CallOption) Option {
	return newFuncOption(func(o *Options) {
		o.CallOptions = opts
	})
}

// TODO: document the Options
func ClusterFilter(name string) Option {
	return newFuncOption(func(o *Options) {
		if o.Filter == nil {
			o.Filter = &Filter{}
		}
		o.Filter.Cluster = &name
	})
}

// TODO: document the Options
func NamespaceFilter(name string) Option {
	return newFuncOption(func(o *Options) {
		if o.Filter == nil {
			o.Filter = &Filter{}
		}
		o.Filter.Namespace = &name
	})
}

// TODO: document the Options
func WorkloadTypeFilter(name string) Option {
	return newFuncOption(func(o *Options) {
		if o.Filter == nil {
			o.Filter = &Filter{}
		}
		o.Filter.WorkloadType = &name
	})
}

func WorkloadFilter(name string) Option {
	return newFuncOption(func(o *Options) {
		if o.Filter == nil {
			o.Filter = &Filter{}
		}
		o.Filter.Workload = &name
	})
}

func ImageFilter(name, tag string) Option {
	return newFuncOption(func(o *Options) {
		if o.Filter == nil {
			o.Filter = &Filter{}
		}
		o.Filter.ImageName = &name
		o.Filter.ImageTag = &tag
	})
}

func IncludeSuppressed() Option {
	return newFuncOption(func(o *Options) {
		o.IncludeSuppressed = true
	})
}

func Limit(limit int32) Option {
	return newFuncOption(func(o *Options) {
		o.Limit = limit
	})
}

func Offset(offset int32) Option {
	return newFuncOption(func(o *Options) {
		o.Offset = offset
	})
}

func Order(field OrderByField, direction Direction) Option {
	return newFuncOption(func(o *Options) {
		o.OrderBy = &OrderBy{
			Field:     string(field),
			Direction: direction,
		}
	})
}

func Since(t time.Time) Option {
	return newFuncOption(func(o *Options) {
		o.Since = timestamppb.New(t)
	})
}

func SinceTypeFilter(sinceType SinceType) Option {
	return newFuncOption(func(o *Options) {
		o.SinceType = &sinceType
	})
}

func IncludeUnresolved() Option {
	return newFuncOption(func(o *Options) {
		o.IncludeUnresolved = true
	})
}

func SeverityFilter(sev Severity) Option {
	return newFuncOption(func(o *Options) {
		o.Severity = &sev
	})
}

func ExcludeNamespacesFilter(namespace ...string) Option {
	return newFuncOption(func(o *Options) {
		o.ExcludeNamespaces = append(o.ExcludeNamespaces, namespace...)
	})
}

func ExcludeClustersFilter(cluster ...string) Option {
	return newFuncOption(func(o *Options) {
		o.ExcludeClusters = append(o.ExcludeClusters, cluster...)
	})
}

func applyOptions(opts ...Option) *Options {
	o := &Options{}
	for _, opt := range opts {
		opt.Apply(o)
	}
	if o.Filter == nil {
		o.Filter = &Filter{}
	}
	if o.Limit == 0 {
		o.Limit = DefaultLimit
	}

	// If single-namespace include is set, exclude list is irrelevant
	if o.Filter.Namespace != nil {
		o.ExcludeNamespaces = nil
	}

	if o.Filter.Cluster != nil {
		o.ExcludeClusters = nil
	}

	return o
}

func (f *Filter) FuzzyWorkloadType() *string {
	if f.WorkloadType == nil {
		return nil
	}
	app := string(WorkloadTypeApp)
	job := string(WorkloadTypeJob)

	switch *f.WorkloadType {
	case "app", "APP", "application", "Application", "APPLICATION":
		return &app
	case "job", "Job", "JOB", "Naisjob", "NAISJOB", "NaisJob":
		return &job
	}
	return f.WorkloadType
}

func (f *Filter) GetWorkloadTypes() []string {
	wTypes := []string{"app", "job"}
	if f.GetWorkloadType() != "" {
		wTypes = []string{*f.FuzzyWorkloadType()}
	}
	return wTypes
}
