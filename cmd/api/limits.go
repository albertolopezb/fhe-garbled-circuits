package main

import (
	"errors"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"
)

const evaluationsPerHour = 3

const evaluationSchema = `
CREATE TABLE IF NOT EXISTS proximity_evaluations (
    target_id INTEGER PRIMARY KEY,
    police_user_id INTEGER NOT NULL,
    suspect_user_id INTEGER NOT NULL,
    evaluated_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_proximity_pair_time
ON proximity_evaluations(police_user_id, suspect_user_id, evaluated_at);
`

var errEvaluationTargetMissing = errors.New("la asignación ya no está disponible")

var errAssignmentUsed = errors.New("esta asignación ya se evaluó")

type evaluationLimit struct {
	retryAt time.Time
}

func (e *evaluationLimit) Error() string {
	return "límite de tres evaluaciones por hora para esta persona"
}

func evaluationUsed(targetID int64) (bool, error) {
	var used bool
	err := db.QueryRow(`SELECT EXISTS(SELECT 1 FROM proximity_evaluations WHERE target_id=?)`, targetID).Scan(&used)
	return used, err
}

func recordEvaluation(s *session, now time.Time) error {
	cutoff := now.Add(-time.Hour).Unix()
	// SQLite serializes this single write statement across concurrent sessions.
	res, err := db.Exec(`INSERT INTO proximity_evaluations(target_id, police_user_id, suspect_user_id, evaluated_at)
		SELECT ?, ?, ?, ?
		WHERE EXISTS (SELECT 1 FROM case_targets WHERE id=? AND crypto_session_id=?)
		  AND (SELECT COUNT(*) FROM proximity_evaluations
		       WHERE police_user_id=? AND suspect_user_id=? AND evaluated_at>?) < ?
		ON CONFLICT(target_id) DO NOTHING`,
		s.TargetID, s.PoliceUserID, s.SuspectUserID, now.Unix(), s.TargetID, s.ID,
		s.PoliceUserID, s.SuspectUserID, cutoff, evaluationsPerHour)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil || n == 1 {
		return err
	}
	var active bool
	err = db.QueryRow(`SELECT EXISTS(SELECT 1 FROM case_targets WHERE id=? AND crypto_session_id=?)`, s.TargetID, s.ID).Scan(&active)
	if err != nil {
		return err
	}
	if !active {
		return errEvaluationTargetMissing
	}
	used, err := evaluationUsed(s.TargetID)
	if err != nil {
		return err
	}
	if used {
		return errAssignmentUsed
	}
	var retryAt int64
	err = db.QueryRow(`SELECT COALESCE(MIN(evaluated_at) + 3600, ?)
		FROM proximity_evaluations
		WHERE police_user_id=? AND suspect_user_id=? AND evaluated_at>?`,
		now.Unix()+1, s.PoliceUserID, s.SuspectUserID, cutoff).Scan(&retryAt)
	if err != nil {
		return err
	}
	return &evaluationLimit{retryAt: time.Unix(retryAt, 0)}
}

func writeRateLimit(w http.ResponseWriter, retryAt time.Time, message string) {
	seconds := max(1, int((time.Until(retryAt)+time.Second-1)/time.Second))
	w.Header().Set("Retry-After", strconv.Itoa(seconds))
	writeError(w, http.StatusTooManyRequests, errors.New(message))
}

type requestWindow struct {
	count int
	until time.Time
}

var requestLimits = struct {
	sync.Mutex
	windows map[string]requestWindow
	cleanup time.Time
}{windows: make(map[string]requestWindow)}

func allowRequest(w http.ResponseWriter, key string, limit int, duration time.Duration) bool {
	now := time.Now()
	requestLimits.Lock()
	if !now.Before(requestLimits.cleanup) {
		for key, window := range requestLimits.windows {
			if !now.Before(window.until) {
				delete(requestLimits.windows, key)
			}
		}
		requestLimits.cleanup = now.Add(time.Minute)
	}
	window := requestLimits.windows[key]
	if !now.Before(window.until) {
		window = requestWindow{until: now.Add(duration)}
	}
	if window.count >= limit {
		requestLimits.Unlock()
		writeRateLimit(w, window.until, "demasiadas solicitudes. Intenta de nuevo más tarde")
		return false
	}
	window.count++
	requestLimits.windows[key] = window
	requestLimits.Unlock()
	return true
}

func handleLimitedLogin(w http.ResponseWriter, r *http.Request) {
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		ip = r.RemoteAddr
	}
	if allowRequest(w, "login:"+ip, 20, time.Minute) {
		handleLogin(w, r)
	}
}
