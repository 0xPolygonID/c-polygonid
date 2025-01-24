package errsink

import (
	"context"
	"log/slog"
)

type Interface interface {
	Put(context.Context, error)
}

// Nop is an ErrorSink that does nothing. It does not require
// any initialization, so the zero value can be used.
type Nop struct{}

// NewNop returns a new NopErrorSink object. The constructor
// is provided for consistency.
func NewNop() Interface {
	return Nop{}
}

// Put for NopErrorSink does nothing.
func (Nop) Put(context.Context, error) {}

type SlogLogger interface {
	Log(context.Context, slog.Level, string, ...any)
}

type slogSink struct {
	logger SlogLogger
}

// NewSlog returns a new ErrorSink that logs errors using the provided slog.Logger
func NewSlog(l SlogLogger) Interface {
	return &slogSink{
		logger: l,
	}
}

func (s *slogSink) Put(ctx context.Context, v error) {
	s.logger.Log(ctx, slog.LevelError, v.Error())
}
