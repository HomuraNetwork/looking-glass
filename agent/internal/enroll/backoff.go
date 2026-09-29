package enroll

import "time"

func Backoff(attempt int) time.Duration {
	if attempt <= 0 {
		return time.Second
	}
	if attempt > 8 {
		attempt = 8
	}
	delay := time.Second << attempt
	if delay > 5*time.Minute {
		return 5 * time.Minute
	}
	return delay
}
