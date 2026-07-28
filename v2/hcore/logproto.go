package hcore

import (
	"fmt"
	"os"
	"runtime/pprof"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func Log(level LogLevel, typ LogType, message ...any) {
	if level < static.logLevel {
		return
	}
	msg := fmt.Sprint(message...)

	static.logObserver.Publish(&LogMessage{
		Level:   level,
		Type:    typ,
		Time:    timestamppb.New(time.Now()),
		Message: msg,
	})
}

func (s *CoreService) LogListener(req *LogRequest, stream grpc.ServerStreamingServer[LogMessage]) error {
	logSub := static.logObserver.Subscribe(1)
	defer static.logObserver.Unsubscribe(logSub)

	for {
		select {
		case <-stream.Context().Done():
			return nil
		case info := <-logSub:
			if info.Level < req.Level {
				continue
			}
			stream.Send(info)
			// case <-time.After(500 * time.Millisecond):
		}
	}
}

func dumpGoroutinesToFile(path string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	return pprof.Lookup("goroutine").WriteTo(f, 2)
}
