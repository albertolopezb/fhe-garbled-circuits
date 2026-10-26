package main

import (
	crand "crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"lattigo-auth-ui-demo/internal/demo"

	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/multiparty"
	"github.com/tuneinsight/lattigo/v6/multiparty/mpbgv"
	"github.com/tuneinsight/lattigo/v6/ring"
	"github.com/tuneinsight/lattigo/v6/schemes/bgv"
	"github.com/tuneinsight/lattigo/v6/utils/sampling"
)

const maxJSONBody = 64 << 20 // 64 MiB, suficiente para los artefactos serializados de la demo.

type encryptedInput struct {
	CTX    string
	CTY    string
	Radius int64
}

type session struct {
	mu sync.Mutex

	ID            string
	CreatedAt     time.Time
	CRSSeed       string
	PoliceUserID  int64
	SuspectUserID int64
	TargetID      int64
	Params        bgv.Parameters
	CRPCKG        multiparty.PublicKeyGenCRP
	CRPRKG        multiparty.RelinearizationKeyGenCRP

	CKGShare map[string]string
	R1Share  map[string]string
	R2Share  map[string]string

	CPKB64        string
	R1CombinedB64 string
	EVK           *rlwe.MemEvaluationKeySet

	Inputs  map[string]encryptedInput
	CTDelta string

	// Δ is never decrypted. Both parties publish an E2S share (masked decryption
	// share); the server only aggregates them. The aggregate looks uniformly random.
	E2SShare map[string]string
	E2SAgg   string

	// Mailbox for the garbled-circuit and oblivious-transfer messages (opaque to the server).
	GC map[string]string
}

type store struct {
	mu       sync.RWMutex
	sessions map[string]*session
}

var sessions = store{sessions: map[string]*session{}}

type setupShareRequest struct {
	Role     string `json:"role"`
	CKGShare string `json:"ckgShare"`
	RKGR1    string `json:"rkgR1"`
}

type r2Request struct {
	Role  string `json:"role"`
	RKGR2 string `json:"rkgR2"`
}

type inputRequest struct {
	Role   string `json:"role"`
	CTX    string `json:"ctX"`
	CTY    string `json:"ctY"`
	Radius int64  `json:"radius,omitempty"`
}

type e2sRequest struct {
	Role     string `json:"role"`
	E2SShare string `json:"e2sShare"`
}

type gcRequest struct {
	Role string `json:"role"`
	Data string `json:"data"`
}

type stateResponse struct {
	ID               string          `json:"id"`
	CRSSeed          string          `json:"crsSeed"`
	AgeSeconds       int64           `json:"ageSeconds"`
	SetupSubmitted   map[string]bool `json:"setupSubmitted"`
	Round1Ready      bool            `json:"round1Ready"`
	R2Submitted      map[string]bool `json:"r2Submitted"`
	SetupReady       bool            `json:"setupReady"`
	InputSubmitted   map[string]bool `json:"inputSubmitted"`
	DeltaReady       bool            `json:"deltaReady"`
	E2SSubmitted     map[string]bool `json:"e2sSubmitted"`
	E2SReady         bool            `json:"e2sReady"`
	GCMessages       map[string]bool `json:"gcMessages"`
	ServerHasSecrets bool            `json:"serverHasSecrets"`
}

type setupArtifactsResponse struct {
	CPK        string `json:"cpk"`
	R1Combined string `json:"r1Combined"`
}

type deltaResponse struct {
	CTDelta string `json:"ctDelta"`
}

type e2sAggResponse struct {
	Agg string `json:"agg"`
}

type gcResponse struct {
	Data string `json:"data"`
}

type messageResponse struct {
	OK      bool   `json:"ok"`
	Message string `json:"message"`
}

func roleOK(role string) bool { return role == "police" || role == "suspect" }

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.Printf("write json: %v", err)
	}
}

func writeError(w http.ResponseWriter, status int, err error) {
	writeJSON(w, status, map[string]any{"ok": false, "error": err.Error()})
}

func decodeJSON(w http.ResponseWriter, r *http.Request, dst any) error {
	r.Body = http.MaxBytesReader(w, r.Body, maxJSONBody)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	return dec.Decode(dst)
}

func randomToken(bytesN int) (string, error) {
	b := make([]byte, bytesN)
	if _, err := crand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func createSession(policeUserID, suspectUserID, targetID int64) (*session, error) {
	id, err := randomToken(18)
	if err != nil {
		return nil, err
	}
	seed, err := randomToken(32)
	if err != nil {
		return nil, err
	}
	params, err := demo.Parameters()
	if err != nil {
		return nil, err
	}
	crs, err := sampling.NewKeyedPRNG([]byte(seed))
	if err != nil {
		return nil, err
	}
	ckg := multiparty.NewPublicKeyGenProtocol(params)
	crpCKG := ckg.SampleCRP(crs)
	rkg := multiparty.NewRelinearizationKeyGenProtocol(params)
	crpRKG := rkg.SampleCRP(crs)

	s := &session{
		ID:            id,
		CreatedAt:     time.Now(),
		CRSSeed:       seed,
		PoliceUserID:  policeUserID,
		SuspectUserID: suspectUserID,
		TargetID:      targetID,
		Params:        params,
		CRPCKG:        crpCKG,
		CRPRKG:        crpRKG,
		CKGShare:      map[string]string{},
		R1Share:       map[string]string{},
		R2Share:       map[string]string{},
		Inputs:        map[string]encryptedInput{},
		E2SShare:      map[string]string{},
		GC:            map[string]string{},
	}

	sessions.mu.Lock()
	sessions.sessions[id] = s
	sessions.mu.Unlock()
	return s, nil
}

func getSession(id string) (*session, bool) {
	sessions.mu.RLock()
	defer sessions.mu.RUnlock()
	s, ok := sessions.sessions[id]
	return s, ok
}

func sessionRoleForUser(s *session, u userRecord) string {
	if u.ID == s.PoliceUserID && u.Role == "police" {
		return "police"
	}
	if u.ID == s.SuspectUserID && u.Role == "suspect" {
		return "suspect"
	}
	return ""
}

func requireSession(w http.ResponseWriter, r *http.Request) (*session, userRecord, string) {
	u, ok := requireUser(w, r)
	if !ok {
		return nil, userRecord{}, ""
	}
	id := r.PathValue("id")
	s, found := getSession(id)
	if !found {
		writeError(w, http.StatusNotFound, fmt.Errorf("sesión criptográfica no encontrada; si reiniciaste el servidor abre el caso otra vez para regenerarla"))
		return nil, userRecord{}, ""
	}
	role := sessionRoleForUser(s, u)
	if role == "" {
		writeError(w, http.StatusForbidden, errors.New("no perteneces a esta sesión criptográfica"))
		return nil, userRecord{}, ""
	}
	return s, u, role
}

func decodeB64(s string) ([]byte, error) { return demo.FromB64(s) }

func combineRound1Locked(s *session) error {
	if s.CPKB64 != "" && s.R1CombinedB64 != "" {
		return nil
	}
	if s.CKGShare["police"] == "" || s.CKGShare["suspect"] == "" || s.R1Share["police"] == "" || s.R1Share["suspect"] == "" {
		return nil
	}

	ckg := multiparty.NewPublicKeyGenProtocol(s.Params)
	pCKG := ckg.AllocateShare()
	qCKG := ckg.AllocateShare()
	ckgCombined := ckg.AllocateShare()

	data, err := decodeB64(s.CKGShare["police"])
	if err != nil {
		return err
	}
	if err := pCKG.UnmarshalBinary(data); err != nil {
		return err
	}
	data, err = decodeB64(s.CKGShare["suspect"])
	if err != nil {
		return err
	}
	if err := qCKG.UnmarshalBinary(data); err != nil {
		return err
	}
	ckg.AggregateShares(pCKG, ckgCombined, &ckgCombined)
	ckg.AggregateShares(qCKG, ckgCombined, &ckgCombined)

	cpk := rlwe.NewPublicKey(s.Params)
	ckg.GenPublicKey(ckgCombined, s.CRPCKG, cpk)
	cpkB64, err := demo.MarshalB64(cpk)
	if err != nil {
		return err
	}

	rkg := multiparty.NewRelinearizationKeyGenProtocol(s.Params)
	_, pR1, _ := rkg.AllocateShare()
	_, qR1, _ := rkg.AllocateShare()
	_, r1Combined, _ := rkg.AllocateShare()

	data, err = decodeB64(s.R1Share["police"])
	if err != nil {
		return err
	}
	if err := pR1.UnmarshalBinary(data); err != nil {
		return err
	}
	data, err = decodeB64(s.R1Share["suspect"])
	if err != nil {
		return err
	}
	if err := qR1.UnmarshalBinary(data); err != nil {
		return err
	}
	rkg.AggregateShares(pR1, r1Combined, &r1Combined)
	rkg.AggregateShares(qR1, r1Combined, &r1Combined)
	r1B64, err := demo.MarshalB64(r1Combined)
	if err != nil {
		return err
	}

	s.CPKB64 = cpkB64
	s.R1CombinedB64 = r1B64
	return nil
}

func finalizeRKGIfReadyLocked(s *session) error {
	if s.EVK != nil {
		return nil
	}
	if s.R2Share["police"] == "" || s.R2Share["suspect"] == "" || s.R1CombinedB64 == "" {
		return nil
	}

	rkg := multiparty.NewRelinearizationKeyGenProtocol(s.Params)
	_, r1Combined, _ := rkg.AllocateShare()
	_, _, pR2 := rkg.AllocateShare()
	_, _, qR2 := rkg.AllocateShare()
	_, _, r2Combined := rkg.AllocateShare()

	data, err := decodeB64(s.R1CombinedB64)
	if err != nil {
		return err
	}
	if err := r1Combined.UnmarshalBinary(data); err != nil {
		return err
	}
	data, err = decodeB64(s.R2Share["police"])
	if err != nil {
		return err
	}
	if err := pR2.UnmarshalBinary(data); err != nil {
		return err
	}
	data, err = decodeB64(s.R2Share["suspect"])
	if err != nil {
		return err
	}
	if err := qR2.UnmarshalBinary(data); err != nil {
		return err
	}

	rkg.AggregateShares(pR2, r2Combined, &r2Combined)
	rkg.AggregateShares(qR2, r2Combined, &r2Combined)

	rlk := rlwe.NewRelinearizationKey(s.Params)
	rkg.GenRelinearizationKey(r1Combined, r2Combined, rlk)
	s.EVK = rlwe.NewMemEvaluationKeySet(rlk)
	return nil
}

func parseCiphertext(params bgv.Parameters, encoded string) (*rlwe.Ciphertext, error) {
	data, err := decodeB64(encoded)
	if err != nil {
		return nil, err
	}
	ct := bgv.NewCiphertext(params, 1, params.MaxLevel())
	if err := ct.UnmarshalBinary(data); err != nil {
		return nil, err
	}
	return ct, nil
}

func parsePublicKey(params bgv.Parameters, encoded string) (*rlwe.PublicKey, error) {
	data, err := decodeB64(encoded)
	if err != nil {
		return nil, err
	}
	pk := rlwe.NewPublicKey(params)
	if err := pk.UnmarshalBinary(data); err != nil {
		return nil, err
	}
	return pk, nil
}

func evaluateIfReadyLocked(s *session) error {
	if s.CTDelta != "" {
		return nil
	}
	if s.EVK == nil || s.Inputs["police"].CTX == "" || s.Inputs["suspect"].CTX == "" {
		return nil
	}

	p := s.Inputs["police"]
	q := s.Inputs["suspect"]
	if p.Radius < 0 {
		return fmt.Errorf("radio negativo")
	}

	ctPx, err := parseCiphertext(s.Params, p.CTX)
	if err != nil {
		return err
	}
	ctPy, err := parseCiphertext(s.Params, p.CTY)
	if err != nil {
		return err
	}
	ctQx, err := parseCiphertext(s.Params, q.CTX)
	if err != nil {
		return err
	}
	ctQy, err := parseCiphertext(s.Params, q.CTY)
	if err != nil {
		return err
	}

	evaluator := bgv.NewEvaluator(s.Params, s.EVK, true)
	ctDx, err := evaluator.SubNew(ctPx, ctQx)
	if err != nil {
		return err
	}
	ctDy, err := evaluator.SubNew(ctPy, ctQy)
	if err != nil {
		return err
	}

	ctDx2 := bgv.NewCiphertext(s.Params, 2, ctDx.Level())
	if err := evaluator.Mul(ctDx, ctDx, ctDx2); err != nil {
		return err
	}
	if err := evaluator.Relinearize(ctDx2, ctDx2); err != nil {
		return err
	}

	ctDxDy := bgv.NewCiphertext(s.Params, 2, ctDx.Level())
	if err := evaluator.Mul(ctDx, ctDy, ctDxDy); err != nil {
		return err
	}
	if err := evaluator.Relinearize(ctDxDy, ctDxDy); err != nil {
		return err
	}

	ctDy2 := bgv.NewCiphertext(s.Params, 2, ctDy.Level())
	if err := evaluator.Mul(ctDy, ctDy, ctDy2); err != nil {
		return err
	}
	if err := evaluator.Relinearize(ctDy2, ctDy2); err != nil {
		return err
	}

	ctTemp, err := evaluator.SubNew(ctDx2, ctDxDy)
	if err != nil {
		return err
	}
	ctDist2, err := evaluator.AddNew(ctTemp, ctDy2)
	if err != nil {
		return err
	}

	radiusSquared := p.Radius * p.Radius
	radiusVector := make([]int64, s.Params.MaxSlots())
	radiusVector[0] = radiusSquared
	ctDelta, err := evaluator.SubNew(ctDist2, radiusVector)
	if err != nil {
		return err
	}

	out, err := demo.MarshalB64(ctDelta)
	if err != nil {
		return err
	}
	s.CTDelta = out
	return nil
}

func newE2SProtocol(params bgv.Parameters) (mpbgv.EncToShareProtocol, error) {
	return mpbgv.NewEncToShareProtocol(
		params,
		ring.DiscreteGaussian{Sigma: 1 << 30, Bound: 6 * (1 << 30)},
	)
}

// aggregateE2SIfReadyLocked adds the two parties' public E2S shares. The result is
// Δ minus both secret masks plus noise, i.e. uniformly random for anyone but the parties.
func aggregateE2SIfReadyLocked(s *session) error {
	if s.E2SAgg != "" {
		return nil
	}
	if s.CTDelta == "" || s.E2SShare["police"] == "" || s.E2SShare["suspect"] == "" {
		return nil
	}
	ctDelta, err := parseCiphertext(s.Params, s.CTDelta)
	if err != nil {
		return err
	}
	e2s, err := newE2SProtocol(s.Params)
	if err != nil {
		return err
	}
	pShare := e2s.AllocateShare(ctDelta.Level())
	qShare := e2s.AllocateShare(ctDelta.Level())
	combined := e2s.AllocateShare(ctDelta.Level())

	data, err := decodeB64(s.E2SShare["police"])
	if err != nil {
		return err
	}
	if err := pShare.UnmarshalBinary(data); err != nil {
		return err
	}
	data, err = decodeB64(s.E2SShare["suspect"])
	if err != nil {
		return err
	}
	if err := qShare.UnmarshalBinary(data); err != nil {
		return err
	}
	if err := e2s.AggregateShares(pShare, combined, &combined); err != nil {
		return err
	}
	if err := e2s.AggregateShares(qShare, combined, &combined); err != nil {
		return err
	}
	out, err := demo.MarshalB64(combined)
	if err != nil {
		return err
	}
	s.E2SAgg = out
	return nil
}

func currentStateLocked(s *session) stateResponse {
	return stateResponse{
		ID:         s.ID,
		CRSSeed:    s.CRSSeed,
		AgeSeconds: int64(time.Since(s.CreatedAt).Seconds()),
		SetupSubmitted: map[string]bool{
			"police":  s.CKGShare["police"] != "" && s.R1Share["police"] != "",
			"suspect": s.CKGShare["suspect"] != "" && s.R1Share["suspect"] != "",
		},
		Round1Ready: s.CPKB64 != "" && s.R1CombinedB64 != "",
		R2Submitted: map[string]bool{
			"police":  s.R2Share["police"] != "",
			"suspect": s.R2Share["suspect"] != "",
		},
		SetupReady: s.EVK != nil,
		InputSubmitted: map[string]bool{
			"police":  s.Inputs["police"].CTX != "",
			"suspect": s.Inputs["suspect"].CTX != "",
		},
		DeltaReady: s.CTDelta != "",
		E2SSubmitted: map[string]bool{
			"police":  s.E2SShare["police"] != "",
			"suspect": s.E2SShare["suspect"] != "",
		},
		E2SReady:         s.E2SAgg != "",
		GCMessages:       gcPresentLocked(s),
		ServerHasSecrets: false,
	}
}

type createCaseRequest struct {
	Title      string  `json:"title"`
	Radius     int64   `json:"radius"`
	SuspectIDs []int64 `json:"suspectIds"`
}

type resultRequest struct {
	Classification string `json:"classification"`
}

func roleMatchesSession(s *session, u userRecord, requested string) bool {
	return requested != "" && requested == sessionRoleForUser(s, u)
}

func ensureTargetSession(t targetRecord) (targetRecord, error) {
	if t.Status == "complete" {
		return t, nil
	}
	if t.CryptoSession != "" {
		if _, ok := getSession(t.CryptoSession); ok {
			return t, nil
		}
	}
	s, err := createSession(t.PoliceID, t.SuspectID, t.ID)
	if err != nil {
		return t, err
	}
	if err := updateTargetCryptoSession(t.ID, s.ID); err != nil {
		return t, err
	}
	t.CryptoSession = s.ID
	t.Status = "pending"
	t.Classification = nil
	return t, nil
}

func handlePoliceSuspects(w http.ResponseWriter, r *http.Request) {
	if _, ok := requireRole(w, r, "police"); !ok {
		return
	}
	users, err := listSuspects()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "users": users})
}

func handlePoliceCases(w http.ResponseWriter, r *http.Request) {
	u, ok := requireRole(w, r, "police")
	if !ok {
		return
	}
	cases, err := listCasesForPolice(u.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "cases": cases})
}

func handleCreateCase(w http.ResponseWriter, r *http.Request) {
	u, ok := requireRole(w, r, "police")
	if !ok {
		return
	}
	var req createCaseRequest
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	id, err := createCaseWithTargets(r.Context(), u.ID, req.Title, req.Radius, req.SuspectIDs)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"ok": true, "caseId": id})
}

func handleSuspectAssignments(w http.ResponseWriter, r *http.Request) {
	u, ok := requireRole(w, r, "suspect")
	if !ok {
		return
	}
	items, err := listAssignmentsForSuspect(u.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	for i := range items {
		items[i], err = ensureTargetSession(items[i])
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "assignments": items})
}

func parseTargetID(r *http.Request) (int64, error) {
	return strconv.ParseInt(r.PathValue("targetID"), 10, 64)
}

func handleTargetContext(w http.ResponseWriter, r *http.Request) {
	u, ok := requireUser(w, r)
	if !ok {
		return
	}
	id, err := parseTargetID(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, errors.New("target inválido"))
		return
	}
	t, err := getTarget(id)
	if err != nil {
		writeError(w, http.StatusNotFound, errors.New("asignación no encontrada"))
		return
	}
	role := ""
	if u.Role == "police" && u.ID == t.PoliceID {
		role = "police"
	} else if u.Role == "suspect" && u.ID == t.SuspectID {
		role = "suspect"
	}
	if role == "" {
		writeError(w, http.StatusForbidden, errors.New("no perteneces a esta asignación"))
		return
	}
	t, err = ensureTargetSession(t)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	otherName := t.SuspectName
	if role == "suspect" {
		otherName = t.PoliceName
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":             true,
		"role":           role,
		"target":         t,
		"otherPartyName": otherName,
	})
}

func handleTargetResult(w http.ResponseWriter, r *http.Request) {
	u, ok := requireRole(w, r, "police")
	if !ok {
		return
	}
	id, err := parseTargetID(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, errors.New("target inválido"))
		return
	}
	t, err := getTarget(id)
	if err != nil || t.PoliceID != u.ID {
		writeError(w, http.StatusForbidden, errors.New("no puedes registrar resultado para esta asignación"))
		return
	}
	var req resultRequest
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if err := saveTargetResult(id, req.Classification); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, messageResponse{OK: true, Message: "resultado guardado sin almacenar Delta ni coordenadas"})
}

func resetSessionLocked(s *session) error {
	seed, err := randomToken(32)
	if err != nil {
		return err
	}
	crs, err := sampling.NewKeyedPRNG([]byte(seed))
	if err != nil {
		return err
	}
	ckg := multiparty.NewPublicKeyGenProtocol(s.Params)
	rkg := multiparty.NewRelinearizationKeyGenProtocol(s.Params)

	s.CreatedAt = time.Now()
	s.CRSSeed = seed
	s.CRPCKG = ckg.SampleCRP(crs)
	s.CRPRKG = rkg.SampleCRP(crs)
	s.CKGShare = map[string]string{}
	s.R1Share = map[string]string{}
	s.R2Share = map[string]string{}
	s.CPKB64 = ""
	s.R1CombinedB64 = ""
	s.EVK = nil
	s.Inputs = map[string]encryptedInput{}
	s.CTDelta = ""
	s.E2SShare = map[string]string{}
	s.E2SAgg = ""
	s.GC = map[string]string{}

	return updateTargetCryptoSession(s.TargetID, s.ID)
}

func handleResetSession(w http.ResponseWriter, r *http.Request) {
	s, _, _ := requireSession(w, r)
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := resetSessionLocked(s); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, messageResponse{OK: true, Message: "sesión criptográfica reiniciada; ambas partes deben generar nuevamente su estado local"})
}

func handleState(w http.ResponseWriter, r *http.Request) {
	s, _, _ := requireSession(w, r)
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	writeJSON(w, http.StatusOK, currentStateLocked(s))
}

func handleSetupShare(w http.ResponseWriter, r *http.Request) {
	s, u, sessionRole := requireSession(w, r)
	if s == nil {
		return
	}
	var req setupShareRequest
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if !roleMatchesSession(s, u, req.Role) || req.Role != sessionRole || req.CKGShare == "" || req.RKGR1 == "" {
		writeError(w, http.StatusBadRequest, errors.New("rol o shares inválidas para este usuario"))
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if old := s.CKGShare[req.Role]; old != "" && old != req.CKGShare {
		writeError(w, http.StatusConflict, errors.New("ese rol ya registró otra secret-key share en esta sesión"))
		return
	}
	s.CKGShare[req.Role] = req.CKGShare
	s.R1Share[req.Role] = req.RKGR1
	if err := combineRound1Locked(s); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	markTargetProcessing(s.TargetID)
	writeJSON(w, http.StatusOK, messageResponse{OK: true, Message: "CKG/RKG round 1 recibidos"})
}

func handleSetupArtifacts(w http.ResponseWriter, r *http.Request) {
	s, _, _ := requireSession(w, r)
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.CPKB64 == "" || s.R1CombinedB64 == "" {
		writeError(w, http.StatusConflict, errors.New("round 1 todavía no está listo"))
		return
	}
	writeJSON(w, http.StatusOK, setupArtifactsResponse{CPK: s.CPKB64, R1Combined: s.R1CombinedB64})
}

func handleR2(w http.ResponseWriter, r *http.Request) {
	s, u, sessionRole := requireSession(w, r)
	if s == nil {
		return
	}
	var req r2Request
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if !roleMatchesSession(s, u, req.Role) || req.Role != sessionRole || req.RKGR2 == "" {
		writeError(w, http.StatusBadRequest, errors.New("rol o rkgR2 inválidos para este usuario"))
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.R1CombinedB64 == "" {
		writeError(w, http.StatusConflict, errors.New("round 1 todavía no está agregado"))
		return
	}
	if old := s.R2Share[req.Role]; old != "" && old != req.RKGR2 {
		writeError(w, http.StatusConflict, errors.New("ese rol ya envió otra round-2 share"))
		return
	}
	s.R2Share[req.Role] = req.RKGR2
	if err := finalizeRKGIfReadyLocked(s); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	markTargetProcessing(s.TargetID)
	writeJSON(w, http.StatusOK, messageResponse{OK: true, Message: "RKG round 2 recibida"})
}

func handleInput(w http.ResponseWriter, r *http.Request) {
	s, u, sessionRole := requireSession(w, r)
	if s == nil {
		return
	}
	var req inputRequest
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if !roleMatchesSession(s, u, req.Role) || req.Role != sessionRole || req.CTX == "" || req.CTY == "" {
		writeError(w, http.StatusBadRequest, errors.New("rol o ciphertexts inválidos"))
		return
	}
	if req.Role == "police" && req.Radius < 0 {
		writeError(w, http.StatusBadRequest, errors.New("radio negativo"))
		return
	}
	if req.Role == "suspect" {
		req.Radius = 0
	}
	if _, err := parseCiphertext(s.Params, req.CTX); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Errorf("ctX inválido: %w", err))
		return
	}
	if _, err := parseCiphertext(s.Params, req.CTY); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Errorf("ctY inválido: %w", err))
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.Inputs[req.Role].CTX != "" {
		writeError(w, http.StatusConflict, errors.New("ese rol ya envió sus coordenadas cifradas"))
		return
	}
	s.Inputs[req.Role] = encryptedInput{CTX: req.CTX, CTY: req.CTY, Radius: req.Radius}
	if err := evaluateIfReadyLocked(s); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	markTargetProcessing(s.TargetID)
	writeJSON(w, http.StatusOK, messageResponse{OK: true, Message: "ciphertexts recibidos; la API nunca recibió las coordenadas plaintext"})
}

func handleDelta(w http.ResponseWriter, r *http.Request) {
	s, _, _ := requireSession(w, r)
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.CTDelta == "" {
		writeError(w, http.StatusConflict, errors.New("Enc(Delta) todavía no está listo"))
		return
	}
	writeJSON(w, http.StatusOK, deltaResponse{CTDelta: s.CTDelta})
}

func handleE2S(w http.ResponseWriter, r *http.Request) {
	s, u, sessionRole := requireSession(w, r)
	if s == nil {
		return
	}
	var req e2sRequest
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if !roleMatchesSession(s, u, req.Role) || req.Role != sessionRole || req.E2SShare == "" {
		writeError(w, http.StatusBadRequest, errors.New("rol o e2sShare inválidos"))
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.CTDelta == "" {
		writeError(w, http.StatusConflict, errors.New("Enc(Delta) todavía no está listo"))
		return
	}
	if old := s.E2SShare[req.Role]; old != "" && old != req.E2SShare {
		writeError(w, http.StatusConflict, errors.New("ese rol ya envió otra E2S share"))
		return
	}
	s.E2SShare[req.Role] = req.E2SShare
	if err := aggregateE2SIfReadyLocked(s); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	markTargetProcessing(s.TargetID)
	writeJSON(w, http.StatusOK, messageResponse{OK: true, Message: "E2S share recibida"})
}

func handleE2SAgg(w http.ResponseWriter, r *http.Request) {
	s, _, _ := requireSession(w, r)
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.E2SAgg == "" {
		writeError(w, http.StatusConflict, errors.New("el agregado E2S todavía no está listo"))
		return
	}
	writeJSON(w, http.StatusOK, e2sAggResponse{Agg: s.E2SAgg})
}

// Garbled-circuit mailbox. Who may write each message: the suspect garbles and answers
// the OT, the police makes the OT selection. The server just stores opaque bytes.
var gcWriters = map[string]string{
	"garbled":  "suspect",
	"gcLabels": "suspect",
	"otA":      "suspect",
	"otE":      "suspect",
	"otR":      "police",
}

const maxGCMessage = 1 << 20 // 1 MiB, the real messages are a few KiB

func gcPresentLocked(s *session) map[string]bool {
	out := make(map[string]bool, len(gcWriters))
	for name := range gcWriters {
		out[name] = s.GC[name] != ""
	}
	return out
}

func handleGCPut(w http.ResponseWriter, r *http.Request) {
	s, u, sessionRole := requireSession(w, r)
	if s == nil {
		return
	}
	name := r.PathValue("name")
	writer, known := gcWriters[name]
	if !known {
		writeError(w, http.StatusNotFound, errors.New("mensaje GC desconocido"))
		return
	}
	var req gcRequest
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if !roleMatchesSession(s, u, req.Role) || req.Role != sessionRole || req.Role != writer {
		writeError(w, http.StatusForbidden, errors.New("este rol no puede enviar ese mensaje"))
		return
	}
	if req.Data == "" || len(req.Data) > maxGCMessage {
		writeError(w, http.StatusBadRequest, errors.New("mensaje vacío o demasiado grande"))
		return
	}
	if _, err := decodeB64(req.Data); err != nil {
		writeError(w, http.StatusBadRequest, errors.New("mensaje no es base64 válido"))
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.E2SAgg == "" {
		writeError(w, http.StatusConflict, errors.New("las shares aditivas de Δ todavía no están listas"))
		return
	}
	if old := s.GC[name]; old != "" && old != req.Data {
		writeError(w, http.StatusConflict, errors.New("ese mensaje ya fue enviado con otro contenido"))
		return
	}
	s.GC[name] = req.Data
	markTargetProcessing(s.TargetID)
	writeJSON(w, http.StatusOK, messageResponse{OK: true, Message: "mensaje recibido"})
}

func handleGCGet(w http.ResponseWriter, r *http.Request) {
	s, _, _ := requireSession(w, r)
	if s == nil {
		return
	}
	name := r.PathValue("name")
	if _, known := gcWriters[name]; !known {
		writeError(w, http.StatusNotFound, errors.New("mensaje GC desconocido"))
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.GC[name] == "" {
		writeError(w, http.StatusConflict, errors.New("mensaje todavía no disponible"))
		return
	}
	writeJSON(w, http.StatusOK, gcResponse{Data: s.GC[name]})
}

func main() {
	if err := initDatabase(); err != nil {
		log.Fatalf("database: %v", err)
	}
	defer db.Close()

	mux := http.NewServeMux()

	// Auth
	mux.HandleFunc("POST /api/auth/register", handleRegister)
	mux.HandleFunc("POST /api/auth/login", handleLogin)
	mux.HandleFunc("POST /api/auth/logout", handleLogout)
	mux.HandleFunc("GET /api/me", handleMe)

	// Dashboards
	mux.HandleFunc("GET /api/police/suspects", handlePoliceSuspects)
	mux.HandleFunc("GET /api/police/cases", handlePoliceCases)
	mux.HandleFunc("POST /api/police/cases", handleCreateCase)
	mux.HandleFunc("GET /api/suspect/assignments", handleSuspectAssignments)
	mux.HandleFunc("GET /api/targets/{targetID}/context", handleTargetContext)
	mux.HandleFunc("POST /api/targets/{targetID}/result", handleTargetResult)

	// Protocolo criptográfico, autorizado por usuario + rol + asignación.
	mux.HandleFunc("GET /api/sessions/{id}", handleState)
	mux.HandleFunc("POST /api/sessions/{id}/reset", handleResetSession)
	mux.HandleFunc("POST /api/sessions/{id}/setup/share", handleSetupShare)
	mux.HandleFunc("GET /api/sessions/{id}/setup/artifacts", handleSetupArtifacts)
	mux.HandleFunc("POST /api/sessions/{id}/setup/r2", handleR2)
	mux.HandleFunc("POST /api/sessions/{id}/input", handleInput)
	mux.HandleFunc("GET /api/sessions/{id}/delta", handleDelta)
	mux.HandleFunc("POST /api/sessions/{id}/e2s", handleE2S)
	mux.HandleFunc("GET /api/sessions/{id}/e2s", handleE2SAgg)
	mux.HandleFunc("POST /api/sessions/{id}/gc/{name}", handleGCPut)
	mux.HandleFunc("GET /api/sessions/{id}/gc/{name}", handleGCGet)

	webDir := os.Getenv("WEB_DIR")
	if webDir == "" {
		webDir = "web"
	}
	mux.Handle("/", http.FileServer(http.Dir(webDir)))

	addr := os.Getenv("ADDR")
	if addr == "" {
		addr = ":8080"
	}

	server := &http.Server{
		Addr:              addr,
		Handler:           securityHeaders(mux),
		ReadHeaderTimeout: 10 * time.Second,
	}
	log.Printf("Lattigo auth/UI demo escuchando en http://localhost%s", strings.TrimPrefix(addr, "0.0.0.0"))
	log.Printf("web dir: %s", webDir)
	log.Fatal(server.ListenAndServe())
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "same-origin")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		w.Header().Set("X-Frame-Options", "DENY")
		next.ServeHTTP(w, r)
	})
}
