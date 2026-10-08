package main

import (
	"encoding/json"
	"fmt"
	"syscall/js"

	"lattigo-auth-ui-demo/internal/demo"

	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/multiparty"
	"github.com/tuneinsight/lattigo/v6/ring"
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
	skOut       *rlwe.SecretKey
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
	PKOut      string `json:"pkOut,omitempty"`
	CTOut      string `json:"ctOut,omitempty"`
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
	PKOut      string `json:"pkOut,omitempty"`
	PCKS       string `json:"pcksShare,omitempty"`
	Delta      int64  `json:"delta,omitempty"`
	Class      string `json:"classification,omitempty"`
	LocalState string `json:"localState,omitempty"`
}

type localStateSnapshot struct {
	Version int    `json:"version"`
	Role    string `json:"role"`
	SK      string `json:"sk"`
	EphRKG  string `json:"ephRkg"`
	SKOut   string `json:"skOut,omitempty"`
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
	if state.skOut != nil {
		skOutB64, err := demo.MarshalB64(state.skOut)
		if err != nil {
			return fail(err)
		}
		snapshot.SKOut = skOutB64
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

	var skOut *rlwe.SecretKey
	if snapshot.SKOut != "" {
		skOut = rlwe.NewSecretKey(params)
		skOutBytes, err := demo.FromB64(snapshot.SKOut)
		if err != nil {
			return fail(err)
		}
		if err := skOut.UnmarshalBinary(skOutBytes); err != nil {
			return fail(err)
		}
	}

	state = partyState{
		initialized: true,
		role:        snapshot.Role,
		params:      params,
		encoder:     bgv.NewEncoder(params),
		sk:          sk,
		ephRKG:      eph,
		skOut:       skOut,
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

func generateOutputKey() response {
	if err := requireInit(); err != nil {
		return fail(err)
	}
	if state.role != "police" {
		return response{OK: false, Error: "solo la policía genera la llave de salida", Role: state.role}
	}
	if state.skOut != nil {
		return response{OK: false, Error: "la llave de salida ya fue generada en esta pestaña", Role: state.role}
	}

	kgen := rlwe.NewKeyGenerator(state.params)
	skOut, pkOut := kgen.GenKeyPairNew()
	state.skOut = skOut

	pkB64, err := demo.MarshalB64(pkOut)
	if err != nil {
		return fail(err)
	}
	return response{OK: true, Role: state.role, PKOut: pkB64, Message: "pk_out lista; sk_out permanece local en el navegador de policía"}
}

func pcksShare(ctDeltaB64, pkOutB64 string) response {
	if err := requireInit(); err != nil {
		return fail(err)
	}
	ctDelta, err := parseCiphertext(ctDeltaB64)
	if err != nil {
		return fail(err)
	}
	pkOut, err := parsePublicKey(pkOutB64)
	if err != nil {
		return fail(err)
	}

	pcks, err := multiparty.NewPublicKeySwitchProtocol(
		state.params,
		ring.DiscreteGaussian{Sigma: 1 << 30, Bound: 6 * (1 << 30)},
	)
	if err != nil {
		return fail(err)
	}
	share := pcks.AllocateShare(ctDelta.Level())
	pcks.GenShare(state.sk, pkOut, ctDelta, &share)
	shareB64, err := demo.MarshalB64(share)
	if err != nil {
		return fail(err)
	}
	return response{OK: true, Role: state.role, PCKS: shareB64, Message: "PCKS share generada con la secret key local"}
}

func decryptOutput(ctOutB64 string) response {
	if err := requireInit(); err != nil {
		return fail(err)
	}
	if state.role != "police" || state.skOut == nil {
		return response{OK: false, Error: "sk_out no está disponible en este cliente", Role: state.role}
	}

	ctOut, err := parseCiphertext(ctOutB64)
	if err != nil {
		return fail(err)
	}
	decryptor := rlwe.NewDecryptor(state.params, state.skOut)
	pt := bgv.NewPlaintext(state.params, ctOut.Level())
	decryptor.Decrypt(ctOut, pt)

	values := make([]uint64, state.params.MaxSlots())
	if err := state.encoder.Decode(pt, values); err != nil {
		return fail(err)
	}
	delta := demo.Centered(values[0], state.params.PlaintextModulus())

	classification := "FUERA DEL RADIO"
	if delta < 0 {
		classification = "DENTRO DEL RADIO"
	} else if delta == 0 {
		classification = "EXACTAMENTE EN EL LIMITE"
	}
	return response{OK: true, Role: state.role, Class: classification, Message: "resultado clasificado localmente; Delta no se expone a la UI"}
}

func handle(req request) response {
	switch req.Op {
	case "init":
		return initParty(req.Role, req.CRSSeed)
	case "rkgRound2":
		return rkgRound2(req.R1Combined)
	case "encryptPoint":
		return encryptPoint(req.CPK, req.X, req.Y)
	case "generateOutputKey":
		return generateOutputKey()
	case "pcksShare":
		return pcksShare(req.CTDelta, req.PKOut)
	case "decryptOutput":
		return decryptOutput(req.CTOut)
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
