package vulnerabilities

import "google.golang.org/grpc"

var _ Option = (*funcOption)(nil)

type Option interface {
	apply(*options)
}

type options struct {
	filter      *Filter
	callOptions []grpc.CallOption
	// pagination..
	// sorting..
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

func applyOptions(opts ...Option) *options {
	o := &options{}
	for _, opt := range opts {
		opt.apply(o)
	}
	return o
}