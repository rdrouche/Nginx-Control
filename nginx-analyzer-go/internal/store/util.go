package store

import "time"

func nowMs() int64 { return time.Now().UnixMilli() }

func floorDiv1000(ms int64) int64 { return ms / 1000 }
