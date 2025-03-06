package vulnerabilities

import (
	"google.golang.org/grpc"
)

var _ Option = (*funcOption)(nil)

type Option interface {
	apply(*options)
}

type OrderByField string

const (
	OrderBySeverity   OrderByField = "severity"
	OrderByCluster    OrderByField = "cluster"
	OrderByNamespace  OrderByField = "namespace"
	OrderByWorkload   OrderByField = "workload"
	OrderByCritical   OrderByField = "critical"
	OrderByHigh       OrderByField = "high"
	OrderByMedium     OrderByField = "medium"
	OrderByLow        OrderByField = "low"
	OrderByUnassigned OrderByField = "unassigned"
	OrderByRiskScore  OrderByField = "risk_score"
)

func (o OrderByField) String() string {
	return string(o)
}

func (o OrderByField) IsValid() bool {
	switch o {
	case OrderBySeverity, OrderByCluster, OrderByNamespace, OrderByWorkload:
		return true
	}
	return false
}

const DefaultLimit = 50

type options struct {
	filter            *Filter
	callOptions       []grpc.CallOption
	includeSuppressed bool
	limit             int32
	offset            int32
	orderBy           *OrderBy
}

type funcOption struct {
	f func(options *options)
}

func newFuncOption(f func(o *options)) *funcOption {
	return &funcOption{
		f: f,
	}
}

func (fo *funcOption) apply(o *options) {
	fo.f(o)
}

// TODO: document the options
func CallOptions(opts ...grpc.CallOption) Option {
	return newFuncOption(func(o *options) {
		o.callOptions = opts
	})
}

// TODO: document the options
func ClusterFilter(name string) Option {
	return newFuncOption(func(o *options) {
		if o.filter == nil {
			o.filter = &Filter{}
		}
		o.filter.Cluster = &name
	})
}

// TODO: document the options
func NamespaceFilter(name string) Option {
	return newFuncOption(func(o *options) {
		if o.filter == nil {
			o.filter = &Filter{}
		}
		o.filter.Namespace = &name
	})
}

// TODO: document the options
func WorkloadTypeFilter(name string) Option {
	return newFuncOption(func(o *options) {
		if o.filter == nil {
			o.filter = &Filter{}
		}
		o.filter.WorkloadType = &name
	})
}

func WorkloadFilter(name string) Option {
	return newFuncOption(func(o *options) {
		if o.filter == nil {
			o.filter = &Filter{}
		}
		o.filter.Workload = &name
	})
}

func ImageFilter(name, tag string) Option {
	return newFuncOption(func(o *options) {
		if o.filter == nil {
			o.filter = &Filter{}
		}
		o.filter.ImageName = &name
		o.filter.ImageTag = &tag
	})
}

func IncludeSuppressed() Option {
	return newFuncOption(func(o *options) {
		o.includeSuppressed = true
	})
}

func Limit(limit int32) Option {
	return newFuncOption(func(o *options) {
		o.limit = limit
	})
}

func Offset(offset int32) Option {
	return newFuncOption(func(o *options) {
		o.offset = offset
	})
}

func Order(field OrderByField, direction Direction) Option {
	return newFuncOption(func(o *options) {
		o.orderBy = &OrderBy{
			Field:     string(field),
			Direction: direction,
		}
	})
}

func applyOptions(opts ...Option) *options {
	o := &options{}
	for _, opt := range opts {
		opt.apply(o)
	}
	if o.filter == nil {
		o.filter = &Filter{}
	}
	if o.limit == 0 {
		o.limit = DefaultLimit
	}
	return o
}
