package model

type RecoverableError struct {
	error
}

type UnrecoverableError struct {
	error
}

func ToRecoverableError(err error) RecoverableError {
	return RecoverableError{err}
}

func ToUnrecoverableError(err error) UnrecoverableError {
	return UnrecoverableError{err}
}
