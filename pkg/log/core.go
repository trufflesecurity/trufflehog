package log

import (
	"go.uber.org/zap/zapcore"
)

type levelFilterCore struct {
	core  zapcore.Core
	level zapcore.LevelEnabler
}

// NewLevelCore creates a core that can be used to independently control the
// level of an existing Core. This is essentially a filter that will only log
// if both the parent and the wrapper cores are enabled.
func NewLevelCore(core zapcore.Core, level zapcore.LevelEnabler) zapcore.Core {
	return &levelFilterCore{core, level}
}

func (c *levelFilterCore) Enabled(lvl zapcore.Level) bool {
	return c.level.Enabled(lvl)
}

func (c *levelFilterCore) With(fields []zapcore.Field) zapcore.Core {
	return &levelFilterCore{c.core.With(fields), c.level}
}

func (c *levelFilterCore) Check(ent zapcore.Entry, ce *zapcore.CheckedEntry) *zapcore.CheckedEntry {
	if !c.Enabled(ent.Level) {
		return ce
	}

	return c.core.Check(ent, ce)
}

func (c *levelFilterCore) Write(ent zapcore.Entry, fields []zapcore.Field) error {
	return c.core.Write(ent, fields)
}

func (c *levelFilterCore) Sync() error {
	return c.core.Sync()
}
