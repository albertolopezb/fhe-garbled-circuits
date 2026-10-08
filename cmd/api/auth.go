package main

import (
	"errors"
	"net/http"
	"strings"
	"time"
)

const authCookieName = "lattigo_demo_session"

type loginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type registerRequest struct {
	DisplayName string `json:"displayName"`
	Email       string `json:"email"`
	Password    string `json:"password"`
}

func setAuthCookie(w http.ResponseWriter, token string, expires time.Time) {
	http.SetCookie(w, &http.Cookie{
		Name:     authCookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Expires:  expires,
		MaxAge:   int(time.Until(expires).Seconds()),
	})
}

func clearAuthCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     authCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
		Expires:  time.Unix(0, 0),
	})
}

func currentUser(r *http.Request) (userRecord, string, error) {
	// Preferimos Bearer token para que cada pestaña pueda mantener una
	// identidad independiente en sessionStorage. Esto permite tener
	// Policía, Carlos, Fer y Ximena abiertos al mismo tiempo.
	auth := strings.TrimSpace(r.Header.Get("Authorization"))
	if strings.HasPrefix(strings.ToLower(auth), "bearer ") {
		token := strings.TrimSpace(auth[len("Bearer "):])
		if token != "" {
			u, err := userFromToken(token)
			if err != nil {
				return userRecord{}, token, errors.New("sesión expirada o inválida")
			}
			return u, token, nil
		}
	}

	// Fallback por compatibilidad con la primera versión basada en cookie.
	cookie, err := r.Cookie(authCookieName)
	if err != nil || cookie.Value == "" {
		return userRecord{}, "", errors.New("no autenticado")
	}
	u, err := userFromToken(cookie.Value)
	if err != nil {
		return userRecord{}, cookie.Value, errors.New("sesión expirada o inválida")
	}
	return u, cookie.Value, nil
}

func requireUser(w http.ResponseWriter, r *http.Request) (userRecord, bool) {
	u, _, err := currentUser(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, err)
		return userRecord{}, false
	}
	return u, true
}

func requireRole(w http.ResponseWriter, r *http.Request, role string) (userRecord, bool) {
	u, ok := requireUser(w, r)
	if !ok {
		return userRecord{}, false
	}
	if u.Role != role {
		writeError(w, http.StatusForbidden, errors.New("no tienes permisos para esta operación"))
		return userRecord{}, false
	}
	return u, true
}

func handleRegister(w http.ResponseWriter, r *http.Request) {
	var req registerRequest
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	u, err := createSuspectUser(req.DisplayName, req.Email, req.Password)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	token, err := randomToken(32)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	expires := time.Now().Add(24 * time.Hour)
	if err := createAuthSession(u.ID, token, expires); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	setAuthCookie(w, token, expires)
	writeJSON(w, http.StatusCreated, map[string]any{"ok": true, "user": u, "token": token, "expiresAt": expires.UTC().Format(time.RFC3339)})
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
	var req loginRequest
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	u, err := authenticateUser(req.Email, req.Password)
	if err != nil {
		writeError(w, http.StatusUnauthorized, err)
		return
	}
	token, err := randomToken(32)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	expires := time.Now().Add(24 * time.Hour)
	if err := createAuthSession(u.ID, token, expires); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	setAuthCookie(w, token, expires)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "user": u, "token": token, "expiresAt": expires.UTC().Format(time.RFC3339)})
}

func handleLogout(w http.ResponseWriter, r *http.Request) {
	_, token, _ := currentUser(r)
	deleteAuthSession(token)
	clearAuthCookie(w)
	writeJSON(w, http.StatusOK, messageResponse{OK: true, Message: "sesión cerrada"})
}

func handleMe(w http.ResponseWriter, r *http.Request) {
	u, ok := requireUser(w, r)
	if !ok {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "user": u})
}
