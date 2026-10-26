package main

import (
	"encoding/json"
	"fmt"
	"syscall/js"

	"lattigo-auth-ui-demo/internal/demo"
	"lattigo-auth-ui-demo/internal/gc"

	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/multiparty"
	"github.com/tuneinsight/lattigo/v6/schemes/bgv"
	"github.com/tuneinsight/lattigo/v6/utils/sampling"
)

type partyState struct {
	initialized bool
	role        string
	params      bgv.Parameters
	encoder     *bgv.Encoder
	sk          *rlwe.SecretKey
	ephRKG      *rlwe.SecretKey

	// Δ is never decrypted: each party only keeps an additive share of it (see gc.go).
	e2sMask  *multiparty.AdditiveShare
	share    uint64
	hasShare bool

	// garbled-circuit state. The suspect garbles, the police evaluates.
	gcCtx    string
	gcSecret *gc.Secret
	otSender *gc.OTSender
	otRecv   *gc.OTReceiver
	msgs     map[string]string // messages already produced, so every step is idempotent
}

var state partyState

type request struct {
	Op         string `json:"op"`
	Role       string `json:"role,omitempty"`
	CRSSeed    string `json:"crsSeed,omitempty"`
	R1Combined string `json:"r1Combined,omitempty"`
	CPK        string `json:"cpk,omitempty"`
	X          int64  `json:"x,omitempty"`
	Y          int64  `json:"y,omitempty"`
	CTDelta    string `json:"ctDelta,omitempty"`
	E2SAgg     string `json:"e2sAgg,omitempty"`
	Ctx        string `json:"ctx,omitempty"`
	Garbled    string `json:"garbled,omitempty"`
	GCLabels   string `json:"gcLabels,omitempty"`
	OTA        string `json:"otA,omitempty"`
	OTR        string `json:"otR,omitempty"`
	OTE        string `json:"otE,omitempty"`
	LocalState string `json:"localState,omitempty"`
}

type response struct {
	OK         bool   `json:"ok"`
	Error      string `json:"error,omitempty"`
	Role       string `json:"role,omitempty"`
	Message    string `json:"message,omitempty"`
	CKGShare   string `json:"ckgShare,omitempty"`
	RKGR1      string `json:"rkgR1,omitempty"`
	RKGR2      string `json:"rkgR2,omitempty"`
	CTX        string `json:"ctX,omitempty"`
	CTY        string `json:"ctY,omitempty"`
	E2SShare   string `json:"e2sShare,omitempty"`
	Garbled    string `json:"garbled,omitempty"`
	GCLabels   string `json:"gcLabels,omitempty"`
	OTA        string `json:"otA,omitempty"`
	OTR        string `json:"otR,omitempty"`
	OTE        string `json:"otE,omitempty"`
	Class      string `json:"classification,omitempty"`
	LocalState string `json:"localState,omitempty"`
}

type localStateSnapshot struct {
	Version int    `json:"version"`
	Role    string `json:"role"`
	SK      string `json:"sk"`
	EphRKG  string `json:"ephRkg"`

	E2SMask  string            `json:"e2sMask,omitempty"`
	HasShare bool              `json:"hasShare,omitempty"`
	Share    uint64            `json:"share,omitempty"`
	GCCtx    string            `json:"gcCtx,omitempty"`
	GCSecret string            `json:"gcSecret,omitempty"`
	OTSender string            `json:"otSender,omitempty"`
	OTRecv   string            `json:"otRecv,omitempty"`
	Msgs     map[string]string `json:"msgs,omitempty"`
}

func fail(err error) response {
	return response{OK: false, Error: err.Error(), Role: state.role}
}

func initParty(role, crsSeed string) response {
	if state.initialized {
		return response{OK: false, Error: "esta pestaña ya inicializó una secret key; recarga solo si vas a reiniciar la sesión", Role: state.role}
	}
	if role != "police" && role != "suspect" {
		return response{OK: false, Error: "role debe ser police o suspect"}
	}
	if crsSeed == "" {
		return response{OK: false, Error: "crsSeed vacío"}
	}

	params, err := demo.Parameters()
	if err != nil {
		return fail(err)
	}
	crs, err := sampling.NewKeyedPRNG([]byte(crsSeed))
	if err != nil {
		return fail(err)
	}

	kgen := rlwe.NewKeyGenerator(params)
	sk := kgen.GenSecretKeyNew()

	ckg := multiparty.NewPublicKeyGenProtocol(params)
	crpCKG := ckg.SampleCRP(crs)
	ckgShare := ckg.AllocateShare()
	ckg.GenShare(sk, crpCKG, &ckgShare)

	rkg := multiparty.NewRelinearizationKeyGenProtocol(params)
	crpRKG := rkg.SampleCRP(crs)
	eph, r1, _ := rkg.AllocateShare()
	rkg.GenShareRoundOne(sk, crpRKG, eph, &r1)

	ckgB64, err := demo.MarshalB64(ckgShare)
	if err != nil {
		return fail(err)
	}
	r1B64, err := demo.MarshalB64(r1)
	if err != nil {
		return fail(err)
	}

	state = partyState{
		initialized: true,
		role:        role,
		params:      params,
		encoder:     bgv.NewEncoder(params),
		sk:          sk,
		ephRKG:      eph,
	}

	return response{
		OK:       true,
		Role:     role,
		Message:  "secret key generada localmente dentro de este navegador; nunca se envía a la API",
		CKGShare: ckgB64,
		RKGR1:    r1B64,
	}
}

func exportLocalState() response {
	if err := requireInit(); err != nil {
		return fail(err)
	}

	skB64, err := demo.MarshalB64(state.sk)
	if err != nil {
		return fail(err)
	}
	ephB64, err := demo.MarshalB64(state.ephRKG)
	if err != nil {
		return fail(err)
	}

	snapshot := localStateSnapshot{
		Version: 1,
		Role:    state.role,
		SK:      skB64,
		EphRKG:  ephB64,
	}
	if err := exportProtocolState(&snapshot); err != nil {
		return fail(err)
	}

	b, err := json.Marshal(snapshot)
	if err != nil {
		return fail(err)
	}
	return response{OK: true, Role: state.role, LocalState: string(b), Message: "estado criptográfico local exportado para persistencia exclusiva del navegador"}
}

func importLocalState(encoded string) response {
	if state.initialized {
		return response{OK: false, Error: "el cliente WASM ya tiene estado criptográfico cargado", Role: state.role}
	}
	var snapshot localStateSnapshot
	if err := json.Unmarshal([]byte(encoded), &snapshot); err != nil {
		return fail(err)
	}
	if snapshot.Version != 1 {
		return response{OK: false, Error: "versión de estado local no soportada"}
	}
	if snapshot.Role != "police" && snapshot.Role != "suspect" {
		return response{OK: false, Error: "rol inválido en estado local"}
	}
	if snapshot.SK == "" || snapshot.EphRKG == "" {
		return response{OK: false, Error: "estado local incompleto"}
	}

	params, err := demo.Parameters()
	if err != nil {
		return fail(err)
	}

	sk := rlwe.NewSecretKey(params)
	skBytes, err := demo.FromB64(snapshot.SK)
	if err != nil {
		return fail(err)
	}
	if err := sk.UnmarshalBinary(skBytes); err != nil {
		return fail(err)
	}

	eph := rlwe.NewSecretKey(params)
	ephBytes, err := demo.FromB64(snapshot.EphRKG)
	if err != nil {
		return fail(err)
	}
	if err := eph.UnmarshalBinary(ephBytes); err != nil {
		return fail(err)
	}

	state = partyState{
		initialized: true,
		role:        snapshot.Role,
		params:      params,
		encoder:     bgv.NewEncoder(params),
		sk:          sk,
		ephRKG:      eph,
	}
	if err := importProtocolState(&snapshot); err != nil {
		state = partyState{}
		return fail(err)
	}

	return response{OK: true, Role: state.role, Message: "estado criptográfico local restaurado dentro de esta pestaña"}
}

func requireInit() error {
	if !state.initialized || state.sk == nil {
		return fmt.Errorf("cliente WASM no inicializado")
	}
	return nil
}

func rkgRound2(r1CombinedB64 string) response {
	if err := requireInit(); err != nil {
		return fail(err)
	}
	data, err := demo.FromB64(r1CombinedB64)
	if err != nil {
		return fail(err)
	}

	rkg := multiparty.NewRelinearizationKeyGenProtocol(state.params)
	_, r1Combined, r2 := rkg.AllocateShare()
	if err := r1Combined.UnmarshalBinary(data); err != nil {
		return fail(err)
	}
	rkg.GenShareRoundTwo(state.ephRKG, state.sk, r1Combined, &r2)
	out, err := demo.MarshalB64(r2)
	if err != nil {
		return fail(err)
	}
	return response{OK: true, Role: state.role, RKGR2: out, Message: "RKG round 2 generada localmente"}
}

func parsePublicKey(encoded string) (*rlwe.PublicKey, error) {
	b, err := demo.FromB64(encoded)
	if err != nil {
		return nil, err
	}
	pk := rlwe.NewPublicKey(state.params)
	if err := pk.UnmarshalBinary(b); err != nil {
		return nil, err
	}
	return pk, nil
}

func parseCiphertext(encoded string) (*rlwe.Ciphertext, error) {
	b, err := demo.FromB64(encoded)
	if err != nil {
		return nil, err
	}
	ct := bgv.NewCiphertext(state.params, 1, state.params.MaxLevel())
	if err := ct.UnmarshalBinary(b); err != nil {
		return nil, err
	}
	return ct, nil
}

func encryptPoint(cpkB64 string, x, y int64) response {
	if err := requireInit(); err != nil {
		return fail(err)
	}
	cpk, err := parsePublicKey(cpkB64)
	if err != nil {
		return fail(err)
	}
	encryptor := rlwe.NewEncryptor(state.params, cpk)

	ctX, err := demo.EncryptScalar(state.params, state.encoder, encryptor, x)
	if err != nil {
		return fail(err)
	}
	ctY, err := demo.EncryptScalar(state.params, state.encoder, encryptor, y)
	if err != nil {
		return fail(err)
	}

	xB64, err := demo.MarshalB64(ctX)
	if err != nil {
		return fail(err)
	}
	yB64, err := demo.MarshalB64(ctY)
	if err != nil {
		return fail(err)
	}

	return response{OK: true, Role: state.role, CTX: xB64, CTY: yB64, Message: "coordenadas cifradas localmente bajo la CPK"}
}

func handle(req request) response {
	switch req.Op {
	case "init":
		return initParty(req.Role, req.CRSSeed)
	case "rkgRound2":
		return rkgRound2(req.R1Combined)
	case "encryptPoint":
		return encryptPoint(req.CPK, req.X, req.Y)
	case "e2sShare":
		return e2sGenShare(req.CTDelta)
	case "e2sFinish":
		return e2sFinish(req.CTDelta, req.E2SAgg)
	case "gcGarble":
		return gcGarble(req.Ctx)
	case "gcOTRespond":
		return gcOTRespond(req.OTR)
	case "gcOTChoose":
		return gcOTChoose(req.Ctx, req.OTA)
	case "gcEvaluate":
		return gcEvaluate(req.Garbled, req.GCLabels, req.OTE)
	case "exportState":
		return exportLocalState()
	case "importState":
		return importLocalState(req.LocalState)
	default:
		return response{OK: false, Error: "operación desconocida: " + req.Op, Role: state.role}
	}
}

func partyCall(_ js.Value, args []js.Value) interface{} {
	if len(args) != 1 {
		b, _ := json.Marshal(response{OK: false, Error: "partyCall espera un JSON string"})
		return string(b)
	}
	var req request
	if err := json.Unmarshal([]byte(args[0].String()), &req); err != nil {
		b, _ := json.Marshal(response{OK: false, Error: err.Error()})
		return string(b)
	}

	var res response
	func() {
		defer func() {
			if r := recover(); r != nil {
				res = response{OK: false, Error: fmt.Sprint(r), Role: state.role}
			}
		}()
		res = handle(req)
	}()

	b, _ := json.Marshal(res)
	return string(b)
}

var partyFunc js.Func

func main() {
	partyFunc = js.FuncOf(partyCall)
	js.Global().Set("partyCall", partyFunc)
	fmt.Println("party.wasm listo")
	select {}
}
