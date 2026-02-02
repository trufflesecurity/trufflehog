package log

import "go.uber.org/zap/zapcore"

type suppressCallerCore struct {
	zapcore.Core
}

func (c *suppressCallerCore) Write(ent zapcore.Entry, fields []zapcore.Field) error {
	ent.Caller = zapcore.EntryCaller{}
	ent.Stack = ""
	return c.Core.Write(ent, fields)
}
