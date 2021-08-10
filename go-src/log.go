package main

import (
	"log"
)

func logError(format string, args ...interface{}) {
	if cfg.Verbose >= 1 {
		log.Printf("error: "+format, args...)
	}
}

func logPrint(format string, args ...interface{}) {
	if cfg.Verbose >= 2 {
		log.Printf(format, args...)
	}
}

func logDebug(format string, args ...interface{}) {
	if cfg.Verbose >= 3 {
		log.Printf("debug: "+format, args...)
	}
}

func logFatal(format string, args ...interface{}) {
	log.Fatalf("fatal: "+format, args...)
}
