package gtoken

import (
	"context"
	"fmt"
	"github.com/gogf/gf/v2/frame/g"
)

const (
	LogLevelDebug   = "debug"
	LogLevelInfo    = "info"
	LogLevelWarning = "warning"
	LogLevelError   = "error"
)

func WriteLog(ctx context.Context, msg string, loglevel string) {
	text := fmt.Sprintf("%s%s", DefaultLogPrefix, msg)
	switch loglevel {
	case LogLevelDebug:
		g.Log().Debug(ctx, text)
	case LogLevelInfo:
		g.Log().Info(ctx, text)
	case LogLevelWarning:
		g.Log().Warning(ctx, text)
	case LogLevelError:
		g.Log().Error(ctx, text)
	default:
		g.Log().Info(ctx, text)
	}
}
