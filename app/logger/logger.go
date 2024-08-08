package logger

import (
	"github.com/natefinch/lumberjack"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var (
	l     *zap.SugaredLogger
	level zap.AtomicLevel
)

func init() {
	hook := lumberjack.Logger{
		Filename:   "dnscap-go.log",
		MaxSize:    50,
		MaxBackups: 10,
	}
	encoderConfig := zapcore.EncoderConfig{
		MessageKey:       "msg",
		LevelKey:         "level",
		TimeKey:          "time",
		NameKey:          "logger",
		CallerKey:        "caller",
		StacktraceKey:    "stacktrace",
		LineEnding:       zapcore.DefaultLineEnding,
		EncodeLevel:      zapcore.LowercaseLevelEncoder,
		EncodeTime:       zapcore.ISO8601TimeEncoder,
		EncodeDuration:   zapcore.SecondsDurationEncoder,
		EncodeCaller:     zapcore.ShortCallerEncoder,
		EncodeName:       zapcore.FullNameEncoder,
		ConsoleSeparator: "|",
	}

	atomicLevel := zap.NewAtomicLevel()
	atomicLevel.SetLevel(zap.InfoLevel)
	level = atomicLevel

	var writes = []zapcore.WriteSyncer{zapcore.AddSync(&hook)}
	core := zapcore.NewCore(
		zapcore.NewConsoleEncoder(encoderConfig),
		zapcore.NewMultiWriteSyncer(writes...),
		atomicLevel,
	)

	caller := zap.AddCaller()
	callSkip := zap.AddCallerSkip(1)
	stackTrace := zap.AddStacktrace(zapcore.PanicLevel)
	development := zap.Development()

	l = zap.New(core, caller, callSkip, stackTrace, development).Sugar()
}

func SetDebug() {
	level.SetLevel(zap.DebugLevel)
}

func Debug(args ...interface{}) {
	l.Debug(args...)
}

func Debugf(template string, args ...interface{}) {
	l.Debugf(template, args...)
}

func Info(args ...interface{}) {
	l.Info(args...)
}

func Infof(template string, args ...interface{}) {
	l.Infof(template, args...)
}

func Warn(args ...interface{}) {
	l.Warn(args...)
}

func Warnf(template string, args ...interface{}) {
	l.Warnf(template, args...)
}

func Error(args ...interface{}) {
	l.Error(args...)
}

func Errorf(template string, args ...interface{}) {
	l.Errorf(template, args...)
}

func Panic(args ...interface{}) {
	l.Panic(args...)
}

func Panicf(template string, args ...interface{}) {
	l.Panicf(template, args...)
}

func Fatal(args ...interface{}) {
	l.Fatal(args...)
}

func Fatalf(template string, args ...interface{}) {
	l.Fatalf(template, args...)
}
