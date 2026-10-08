package main

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/bcrypt"
)

type userRecord struct {
	ID          int64  `json:"id"`
	DisplayName string `json:"displayName"`
	Email       string `json:"email"`
	Role        string `json:"role"`
}

type targetRecord struct {
	ID             int64   `json:"id"`
	CaseID         int64   `json:"caseId"`
	CaseTitle      string  `json:"caseTitle"`
	Radius         int64   `json:"radius"`
	SuspectID      int64   `json:"suspectId"`
	SuspectName    string  `json:"suspectName"`
	SuspectEmail   string  `json:"suspectEmail"`
	PoliceID       int64   `json:"policeId"`
	PoliceName     string  `json:"policeName"`
	CryptoSession  string  `json:"cryptoSession"`
	Status         string  `json:"status"`
	Classification *string `json:"classification,omitempty"`
	CreatedAt      string  `json:"createdAt"`
}

type caseRecord struct {
	ID        int64          `json:"id"`
	Title     string         `json:"title"`
	Radius    int64          `json:"radius"`
	CreatedAt string         `json:"createdAt"`
	Targets   []targetRecord `json:"targets"`
}

var db *sql.DB

func initDatabase() error {
	path := os.Getenv("DB_PATH")
	if path == "" {
		path = "data/demo.db"
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}

	var err error
	db, err = sql.Open("sqlite3", path+"?_foreign_keys=on&_busy_timeout=5000")
	if err != nil {
		return err
	}
	if err := db.Ping(); err != nil {
		return err
	}

	schema := `
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    display_name TEXT NOT NULL,
    email TEXT NOT NULL UNIQUE COLLATE NOCASE,
    password_hash BLOB NOT NULL,
    role TEXT NOT NULL CHECK(role IN ('police','suspect')),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS auth_sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    token_hash TEXT NOT NULL UNIQUE,
    user_id INTEGER NOT NULL,
    expires_at TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS cases (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    police_user_id INTEGER NOT NULL,
    radius INTEGER NOT NULL CHECK(radius >= 0),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(police_user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS case_targets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id INTEGER NOT NULL,
    suspect_user_id INTEGER NOT NULL,
    crypto_session_id TEXT UNIQUE,
    status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','processing','complete')),
    classification TEXT NULL CHECK(classification IN ('DENTRO DEL RADIO','FUERA DEL RADIO','EXACTAMENTE EN EL LIMITE')),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(case_id, suspect_user_id),
    FOREIGN KEY(case_id) REFERENCES cases(id) ON DELETE CASCADE,
    FOREIGN KEY(suspect_user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_auth_sessions_token ON auth_sessions(token_hash);
CREATE INDEX IF NOT EXISTS idx_targets_case ON case_targets(case_id);
CREATE INDEX IF NOT EXISTS idx_targets_suspect ON case_targets(suspect_user_id);
`
	if _, err := db.Exec(schema); err != nil {
		return err
	}

	if err := seedDemoUsers(); err != nil {
		return err
	}
	return nil
}

func seedDemoUsers() error {
	seeds := []struct {
		name, email, password, role string
	}{
		{"Oficial Demo", "police@demo.local", "Police123!", "police"},
		{"Carlos Mendoza", "carlos@demo.local", "Demo1234!", "suspect"},
		{"Fernanda Santos", "fer@demo.local", "Demo1234!", "suspect"},
		{"Ximena Villarreal", "ximena@demo.local", "Demo1234!", "suspect"},
	}

	for _, s := range seeds {
		var exists int
		err := db.QueryRow(`SELECT COUNT(1) FROM users WHERE email = ?`, s.email).Scan(&exists)
		if err != nil {
			return err
		}
		if exists > 0 {
			continue
		}
		hash, err := bcrypt.GenerateFromPassword([]byte(s.password), bcrypt.DefaultCost)
		if err != nil {
			return err
		}
		if _, err := db.Exec(`INSERT INTO users(display_name,email,password_hash,role) VALUES(?,?,?,?)`, s.name, s.email, hash, s.role); err != nil {
			return err
		}
	}
	return nil
}

func normalizeEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}

func createSuspectUser(name, email, password string) (userRecord, error) {
	name = strings.TrimSpace(name)
	email = normalizeEmail(email)
	if len(name) < 2 {
		return userRecord{}, errors.New("nombre demasiado corto")
	}
	if !strings.Contains(email, "@") {
		return userRecord{}, errors.New("correo inválido")
	}
	if len(password) < 8 {
		return userRecord{}, errors.New("la contraseña debe tener al menos 8 caracteres")
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return userRecord{}, err
	}
	res, err := db.Exec(`INSERT INTO users(display_name,email,password_hash,role) VALUES(?,?,?,'suspect')`, name, email, hash)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "unique") {
			return userRecord{}, errors.New("ese correo ya está registrado")
		}
		return userRecord{}, err
	}
	id, _ := res.LastInsertId()
	return userRecord{ID: id, DisplayName: name, Email: email, Role: "suspect"}, nil
}

func authenticateUser(email, password string) (userRecord, error) {
	email = normalizeEmail(email)
	var u userRecord
	var hash []byte
	err := db.QueryRow(`SELECT id,display_name,email,role,password_hash FROM users WHERE email = ?`, email).
		Scan(&u.ID, &u.DisplayName, &u.Email, &u.Role, &hash)
	if err == sql.ErrNoRows {
		return userRecord{}, errors.New("correo o contraseña incorrectos")
	}
	if err != nil {
		return userRecord{}, err
	}
	if err := bcrypt.CompareHashAndPassword(hash, []byte(password)); err != nil {
		return userRecord{}, errors.New("correo o contraseña incorrectos")
	}
	return u, nil
}

func tokenHash(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func createAuthSession(userID int64, token string, expires time.Time) error {
	_, err := db.Exec(`INSERT INTO auth_sessions(token_hash,user_id,expires_at) VALUES(?,?,?)`, tokenHash(token), userID, expires.UTC().Format(time.RFC3339))
	return err
}

func deleteAuthSession(token string) {
	if token == "" {
		return
	}
	_, _ = db.Exec(`DELETE FROM auth_sessions WHERE token_hash = ?`, tokenHash(token))
}

func userFromToken(token string) (userRecord, error) {
	var u userRecord
	var expires string
	err := db.QueryRow(`
SELECT u.id,u.display_name,u.email,u.role,s.expires_at
FROM auth_sessions s
JOIN users u ON u.id=s.user_id
WHERE s.token_hash=?`, tokenHash(token)).Scan(&u.ID, &u.DisplayName, &u.Email, &u.Role, &expires)
	if err != nil {
		return userRecord{}, err
	}
	t, err := time.Parse(time.RFC3339, expires)
	if err != nil || time.Now().After(t) {
		deleteAuthSession(token)
		return userRecord{}, sql.ErrNoRows
	}
	return u, nil
}

func listSuspects() ([]userRecord, error) {
	rows, err := db.Query(`SELECT id,display_name,email,role FROM users WHERE role='suspect' ORDER BY display_name COLLATE NOCASE`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []userRecord
	for rows.Next() {
		var u userRecord
		if err := rows.Scan(&u.ID, &u.DisplayName, &u.Email, &u.Role); err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

func ensureSuspectIDs(ids []int64) error {
	if len(ids) == 0 {
		return errors.New("selecciona al menos una persona")
	}
	seen := map[int64]bool{}
	for _, id := range ids {
		if id <= 0 || seen[id] {
			return errors.New("lista de usuarios inválida")
		}
		seen[id] = true
		var role string
		if err := db.QueryRow(`SELECT role FROM users WHERE id=?`, id).Scan(&role); err != nil {
			return fmt.Errorf("usuario %d no existe", id)
		}
		if role != "suspect" {
			return fmt.Errorf("usuario %d no es sospechoso", id)
		}
	}
	return nil
}

func createCaseWithTargets(ctx context.Context, policeID int64, title string, radius int64, suspectIDs []int64) (int64, error) {
	title = strings.TrimSpace(title)
	if title == "" {
		return 0, errors.New("el caso necesita un título")
	}
	if radius < 0 {
		return 0, errors.New("radio inválido")
	}
	if err := ensureSuspectIDs(suspectIDs); err != nil {
		return 0, err
	}

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()

	res, err := tx.ExecContext(ctx, `INSERT INTO cases(title,police_user_id,radius) VALUES(?,?,?)`, title, policeID, radius)
	if err != nil {
		return 0, err
	}
	caseID, _ := res.LastInsertId()

	for _, suspectID := range suspectIDs {
		res, err := tx.ExecContext(ctx, `INSERT INTO case_targets(case_id,suspect_user_id,crypto_session_id) VALUES(?,?,NULL)`, caseID, suspectID)
		if err != nil {
			return 0, err
		}
		targetID, _ := res.LastInsertId()
		s, err := createSession(policeID, suspectID, targetID)
		if err != nil {
			return 0, err
		}
		if _, err := tx.ExecContext(ctx, `UPDATE case_targets SET crypto_session_id=? WHERE id=?`, s.ID, targetID); err != nil {
			return 0, err
		}
	}

	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return caseID, nil
}

func markTargetProcessing(targetID int64) {
	if targetID <= 0 {
		return
	}
	_, _ = db.Exec(`UPDATE case_targets SET status='processing' WHERE id=? AND status='pending'`, targetID)
}

func saveTargetResult(targetID int64, classification string) error {
	switch classification {
	case "DENTRO DEL RADIO", "FUERA DEL RADIO", "EXACTAMENTE EN EL LIMITE":
	default:
		return errors.New("clasificación inválida")
	}
	res, err := db.Exec(`UPDATE case_targets SET status='complete', classification=? WHERE id=?`, classification, targetID)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

func getTarget(targetID int64) (targetRecord, error) {
	var t targetRecord
	var classification sql.NullString
	err := db.QueryRow(`
SELECT ct.id,c.id,c.title,c.radius,
       su.id,su.display_name,su.email,
       pu.id,pu.display_name,
       ct.crypto_session_id,ct.status,ct.classification,ct.created_at
FROM case_targets ct
JOIN cases c ON c.id=ct.case_id
JOIN users su ON su.id=ct.suspect_user_id
JOIN users pu ON pu.id=c.police_user_id
WHERE ct.id=?`, targetID).Scan(
		&t.ID, &t.CaseID, &t.CaseTitle, &t.Radius,
		&t.SuspectID, &t.SuspectName, &t.SuspectEmail,
		&t.PoliceID, &t.PoliceName,
		&t.CryptoSession, &t.Status, &classification, &t.CreatedAt,
	)
	if err != nil {
		return targetRecord{}, err
	}
	if classification.Valid {
		t.Classification = &classification.String
	}
	return t, nil
}

func listCasesForPolice(policeID int64) ([]caseRecord, error) {
	rows, err := db.Query(`SELECT id,title,radius,created_at FROM cases WHERE police_user_id=? ORDER BY id DESC`, policeID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var cases []caseRecord
	for rows.Next() {
		var c caseRecord
		if err := rows.Scan(&c.ID, &c.Title, &c.Radius, &c.CreatedAt); err != nil {
			return nil, err
		}
		tRows, err := db.Query(`
SELECT ct.id,su.id,su.display_name,su.email,ct.crypto_session_id,ct.status,ct.classification,ct.created_at
FROM case_targets ct
JOIN users su ON su.id=ct.suspect_user_id
WHERE ct.case_id=?
ORDER BY su.display_name COLLATE NOCASE`, c.ID)
		if err != nil {
			return nil, err
		}
		for tRows.Next() {
			var t targetRecord
			var classification sql.NullString
			t.CaseID = c.ID
			t.CaseTitle = c.Title
			t.Radius = c.Radius
			t.PoliceID = policeID
			if err := tRows.Scan(&t.ID, &t.SuspectID, &t.SuspectName, &t.SuspectEmail, &t.CryptoSession, &t.Status, &classification, &t.CreatedAt); err != nil {
				tRows.Close()
				return nil, err
			}
			if classification.Valid {
				t.Classification = &classification.String
			}
			c.Targets = append(c.Targets, t)
		}
		tRows.Close()
		cases = append(cases, c)
	}
	return cases, rows.Err()
}

func listAssignmentsForSuspect(suspectID int64) ([]targetRecord, error) {
	rows, err := db.Query(`
SELECT ct.id,c.id,c.title,c.radius,
       su.id,su.display_name,su.email,
       pu.id,pu.display_name,
       ct.crypto_session_id,ct.status,ct.classification,ct.created_at
FROM case_targets ct
JOIN cases c ON c.id=ct.case_id
JOIN users su ON su.id=ct.suspect_user_id
JOIN users pu ON pu.id=c.police_user_id
WHERE ct.suspect_user_id=?
ORDER BY ct.id DESC`, suspectID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []targetRecord
	for rows.Next() {
		var t targetRecord
		var classification sql.NullString
		if err := rows.Scan(
			&t.ID, &t.CaseID, &t.CaseTitle, &t.Radius,
			&t.SuspectID, &t.SuspectName, &t.SuspectEmail,
			&t.PoliceID, &t.PoliceName,
			&t.CryptoSession, &t.Status, &classification, &t.CreatedAt,
		); err != nil {
			return nil, err
		}
		if classification.Valid {
			t.Classification = &classification.String
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

func updateTargetCryptoSession(targetID int64, sessionID string) error {
	_, err := db.Exec(`UPDATE case_targets SET crypto_session_id=?, status='pending', classification=NULL WHERE id=?`, sessionID, targetID)
	return err
}
