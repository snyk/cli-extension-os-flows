package cmdctx

import (
	"context"

	"github.com/rs/zerolog"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/ui"
	"github.com/snyk/go-application-framework/pkg/workflow"

	"github.com/snyk/cli-extension-os-flows/internal/errors"
	"github.com/snyk/cli-extension-os-flows/internal/instrumentation"
)

// CtxKey is the type of the keys inside the command context.
type CtxKey string

// This is the list of keys used by the command context.
const (
	IctxKey            CtxKey = "ictx"
	ConfigKey          CtxKey = "cfg"
	LoggerKey          CtxKey = "logger"
	ErrorFactoryKey    CtxKey = "errFactory"
	ProgressBarKey     CtxKey = "progressBar"
	InstrumentationKey CtxKey = "instrumentation"
)

// WithIctx adds an invocation context to the current context.
func WithIctx(ctx context.Context, ictx workflow.InvocationContext) context.Context {
	return context.WithValue(ctx, IctxKey, ictx)
}

// WithConfig adds a config to the current context.
func WithConfig(ctx context.Context, cfg configuration.Configuration) context.Context {
	return context.WithValue(ctx, ConfigKey, cfg)
}

// WithLogger adds a logger to the current context.
func WithLogger(ctx context.Context, logger *zerolog.Logger) context.Context {
	return context.WithValue(ctx, LoggerKey, logger)
}

// WithErrorFactory adds an error factory to the current context.
func WithErrorFactory(ctx context.Context, errFactory *errors.ErrorFactory) context.Context {
	return context.WithValue(ctx, ErrorFactoryKey, errFactory)
}

// WithProgressBar adds a progress bar to the current context.
func WithProgressBar(ctx context.Context, progressBar ui.ProgressBar) context.Context {
	return context.WithValue(ctx, ProgressBarKey, progressBar)
}

// WithInstrumentation adds instrumentation to the current context.
func WithInstrumentation(ctx context.Context, instrumentation instrumentation.Instrumentation) context.Context {
	return context.WithValue(ctx, InstrumentationKey, instrumentation)
}

// Ictx will retrieve the invocation context from the command context.
// It will return `nil` if the value wasn't set on the context.
func Ictx(ctx context.Context) workflow.InvocationContext {
	if ictx, ok := ctx.Value(IctxKey).(workflow.InvocationContext); ok {
		return ictx
	}
	return nil
}

// Config will retrieve the config from the command context.
// It will return `nil` if the value wasn't set on the context.
func Config(ctx context.Context) configuration.Configuration {
	if cfg, ok := ctx.Value(ConfigKey).(configuration.Configuration); ok {
		return cfg
	}
	return nil
}

// Logger will retrieve the logger from the command context.
// It will return `nil` if the value wasn't set on the context.
func Logger(ctx context.Context) *zerolog.Logger {
	if logger, ok := ctx.Value(LoggerKey).(*zerolog.Logger); ok {
		return logger
	}
	return nil
}

// ErrorFactory will retrieve the error factory from the command context.
// It will return `nil` if the value wasn't set on the context.
func ErrorFactory(ctx context.Context) *errors.ErrorFactory {
	if errFactory, ok := ctx.Value(ErrorFactoryKey).(*errors.ErrorFactory); ok {
		return errFactory
	}
	return nil
}

// ProgressBar will retrieve the progress bar from the command context.
// It will return `nil` if the value wasn't set on the context.
func ProgressBar(ctx context.Context) ui.ProgressBar {
	if progressBar, ok := ctx.Value(ProgressBarKey).(ui.ProgressBar); ok {
		return progressBar
	}
	return nil
}

// Instrumentation will retrieve the instrumentation from the command context.
// It will return `nil` if the value wasn't set on the context.
func Instrumentation(ctx context.Context) instrumentation.Instrumentation {
	if instrumentation, ok := ctx.Value(InstrumentationKey).(instrumentation.Instrumentation); ok {
		return instrumentation
	}
	return nil
}
