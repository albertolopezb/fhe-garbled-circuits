# E11 route audit (static, commit 2fd5a89, 2026-11-12T20:18:09)  ## Routes registered in cmd/api/main.go
- mux.HandleFunc("POST /api/auth/register", handleRegister)
- mux.HandleFunc("POST /api/auth/login", handleLimitedLogin)
- mux.HandleFunc("POST /api/auth/logout", handleLogout)
- mux.HandleFunc("GET /api/me", handleMe)
- mux.HandleFunc("GET /api/police/suspects", handlePoliceSuspects)
- mux.HandleFunc("GET /api/police/cases", handlePoliceCases)
- mux.HandleFunc("POST /api/police/cases", handleCreateCase)
- mux.HandleFunc("DELETE /api/police/cases/{caseID}", handleDeleteCase)
- mux.HandleFunc("GET /api/suspect/assignments", handleSuspectAssignments)
- mux.HandleFunc("GET /api/targets/{targetID}/context", handleTargetContext)
- mux.HandleFunc("POST /api/targets/{targetID}/result", handleTargetResult)
- mux.HandleFunc("GET /api/sessions/{id}", handleState)
- mux.HandleFunc("POST /api/sessions/{id}/reset", handleResetSession)
- mux.HandleFunc("POST /api/sessions/{id}/setup/share", handleSetupShare)
- mux.HandleFunc("GET /api/sessions/{id}/setup/artifacts", handleSetupArtifacts)
- mux.HandleFunc("POST /api/sessions/{id}/setup/r2", handleR2)
- mux.HandleFunc("POST /api/sessions/{id}/input", handleInput)
- mux.HandleFunc("GET /api/sessions/{id}/delta", handleDelta)
- mux.HandleFunc("POST /api/sessions/{id}/e2s", handleE2S)
- mux.HandleFunc("GET /api/sessions/{id}/e2s", handleE2SAgg)
- mux.HandleFunc("POST /api/sessions/{id}/gc/{name}", handleGCPut)
- mux.HandleFunc("GET /api/sessions/{id}/gc/{name}", handleGCGet)
- mux.Handle("/", http.FileServer(http.Dir(webDir)))

## JSON field names used by cmd/api (struct tags)
ageSeconds, agg, caseId, caseTitle, ckgShare, classification, cpk, createdAt, crsSeed, cryptoSession, ctDelta, ctX, ctY, data, deltaReady, displayName, e2sReady, e2sShare, e2sSubmitted, email, gcMessages, id, inputSubmitted, message, ok, password, policeId, policeName, r1Combined, r2Submitted, radius, rkgR1, rkgR2, role, round1Ready, serverHasSecrets, setupReady, setupSubmitted, status, suspectEmail, suspectId, suspectIds, suspectName, targets, title

## Uses of Decrypt / NewDecryptor / SecretKey in cmd/api
- main.go:60: // Δ is never decrypted. Both parties publish an E2S share (masked decryption

## Scope
This is a text search of the server source, not a review of every handler body and not a capture of real traffic.
No database, log or HTTP capture was scanned for coordinates.
