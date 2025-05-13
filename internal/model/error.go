package model

type RecoverableError struct {
	error
	Subsystem string
}

type UnrecoverableError struct {
	error
	Subsystem string
}

func ToRecoverableError(err error, subsystem string) RecoverableError {
	return RecoverableError{err, subsystem}
}

func ToUnrecoverableError(err error, subsystem string) UnrecoverableError {
	return UnrecoverableError{err, subsystem}
}
