# Private Proximity · Multi-tab Auth + SQLite + Lattigo/WASM

**Private proximity check with homomorphic encryption and garbled circuits.** A demo in which the police can find out whether a suspect was inside the radius of a crime scene **without either side revealing their coordinates**, and without learning the exact distance. Locations are encrypted in the browser with multiparty BGV homomorphic encryption ([Lattigo](https://github.com/tuneinsight/lattigo) v6, compiled to WebAssembly). The squared-distance margin is then converted into secret shares and fed to a garbled circuit, so the only output is one of three results: inside the radius, outside the radius, or exactly on the boundary. The backend is a Go API with SQLite that never sees anything in clear.

**Stack:** Go · Lattigo (BGV, multiparty) · WebAssembly · garbled circuits + oblivious transfer · SQLite · vanilla JS.

> The rest of this document is in Spanish.

Esta versión está pensada para demostrar el protocolo con **Policía + tres usuarios abiertos al mismo tiempo**, sin hacer logout/login entre cada rol.

## Arquitectura

- **Go API**: autenticación, SQLite, coordinación de sesiones multiparty, evaluación homomórfica y buzón de mensajes del circuito garbleado (no ve nada en claro).
- **SQLite**: usuarios, sesiones de autenticación, casos, participantes y clasificación final.
- **party.wasm**: criptografía local en cada vista (Lattigo + circuitos garbleados).
- **sessionStorage**: cada cuenta demo usa su propio Bearer token, por lo que Policía, Carlos, Fer y Ximena pueden coexistir sin sustituir sus identidades.
- **IndexedDB local**: conserva el estado criptográfico serializado por `cryptoSession` para que navegar al dashboard o recargar no genere una nueva secret key.
- **Secret keys**: nunca se envían a la API ni se guardan en SQLite. En esta demo sí se serializan **solo localmente** dentro de `IndexedDB` del navegador para poder regresar al dashboard y continuar la misma sesión.

## Base de datos

Archivo:

```text
data/demo.db
```

Tablas:

```text
users
auth_sessions
cases
case_targets
```

La base **no guarda** `sk_P`, `sk_S`, `sk_out`, coordenadas, `dx`, `dy`, `D²` ni `Delta`.

> Nota de demo: las secret keys sí se serializan localmente en `IndexedDB` para mantener continuidad al navegar. Nunca salen del navegador. Para producción convendría usar almacenamiento local protegido/IndexedDB o un contenedor de claves más robusto.

## Cuentas demo

| Rol | Usuario | Contraseña |
|---|---|---|
| Policía | `police@demo.local` | `Police123!` |
| Carlos | `carlos@demo.local` | `Demo1234!` |
| Fer | `fer@demo.local` | `Demo1234!` |
| Ximena | `ximena@demo.local` | `Demo1234!` |

## Ejecutar

Requiere Go compatible con Lattigo v6.2.0.

```bash
go mod tidy
chmod +x build.sh
./build.sh
./bin/lattigo-api
```

Abrir:

```text
http://localhost:8080
```

## Demo Control Center

La página principal muestra **Policía a la izquierda** y el panel de **Sospechosos a la derecha**. Usa los botones Carlos, Fer y Ximena para cambiar de cuenta en el panel derecho. Cada cuenta conserva su pantalla al cambiar de persona.

### Flujo recomendado

1. Crea un caso en el panel de Policía y selecciona a los participantes.
2. Abre el protocolo de una persona en Policía y selecciona a esa persona a la derecha para abrir su solicitud.
3. Genera la secret key en cada panel. El primero espera a la otra parte para completar CPK/RLK.
4. Policía cifra y envía el punto de referencia. La otra parte ingresa su ubicación y pulsa **Autorizar y enviar ubicación cifrada**.
5. Mantén ambos protocolos visibles hasta ver la clasificación en Policía. Luego vuelve al panel de casos y repite con la siguiente persona.

### Autenticación

Cada cuenta demo usa un token Bearer con una clave propia en `sessionStorage`. Los paneles comparten el origen y el almacenamiento del navegador, por lo que el modo demo simula roles en un solo equipo. Para ensayar con almacenamiento separado, usa **Modo normal** en perfiles de navegador distintos.

## Modo normal

Desde el Control Center también existe **Modo normal · Login**.

Ahí puedes:

- iniciar sesión manualmente;
- registrar usuarios nuevos;
- usar el mismo dashboard y protocolo.

Los registros nuevos se crean siempre con rol `suspect`.

## DBeaver

1. Database → New Database Connection.
2. Elegir SQLite.
3. Seleccionar:

```text
<proyecto>/data/demo.db
```

Ahí puedes inspeccionar usuarios, casos, participantes y sesiones de autenticación.

## Privacidad de la consola

La consola visible al usuario puede mostrar eventos como:

```text
[LOCAL] Secret key generada dentro del navegador
[CPK] Share generada
[RLK] Round 1/2 completadas
[INPUT] Coordenadas cifradas localmente
[SERVER] Enc(dx), Enc(dy), Enc(D²), Enc(Delta) calculados
[E2S] Share generada
[POLICE LOCAL] Resultado final obtenido del circuito garbleado
```

No imprime valores de coordenadas, secret keys, `D²` ni `Delta`.

## Resultado sin descifrar Δ (circuitos garbleados)

Antes, la policía descifraba `Enc(Δ)` y veía `Δ = dist² − R²` completo, lo que revela la distancia exacta del sospechoso a la escena. Ahora `Δ` nunca se descifra:

1. **E2S (encryption-to-shares, `mpbgv.EncToShareProtocol`)**: cada parte elige una máscara aleatoria y publica su share de descifrado menos esa máscara. El servidor solo suma las dos shares públicas (el resultado parece aleatorio). Al final cada parte tiene una share aditiva de `Δ` módulo 65537; cada share por separado es uniforme.
2. **Circuito garbleado** (`internal/gc`): el **sospechoso** garblea un circuito que suma las dos shares módulo 65537 (17 bits) y entrega dos bits: `Δ < 0` y `Δ = 0`. Sus labels viajan directamente; la **policía** obtiene los labels de su share con una **transferencia ciega** (OT, edwards25519), sin revelar sus bits.
3. La policía evalúa el circuito y solo decodifica los bits de salida: `DENTRO DEL RADIO`, `FUERA DEL RADIO` o `EXACTAMENTE EN EL LIMITE`. El sospechoso no recibe el resultado.

Mensajes nuevos de la API: `POST/GET /api/sessions/{id}/e2s` y `POST/GET /api/sessions/{id}/gc/{garbled|gcLabels|otA|otR|otE}`. Se eliminaron `pk_out`, `sk_out`, `/pcks`, `/output-key` y `/output`.

Pruebas: `go test ./internal/gc` (circuito, garbling, OT y la tubería completa BGV → E2S → circuito).

El cálculo usa `Δ = dx² + dy² − R²`. Ambos clientes validan coordenadas enteras de 0 a 100 antes de cifrarlas y la API usa el radio de 0 a 100 guardado en el caso. Así, con clientes semi-honestos, `Δ` queda entre −10000 y 20000 dentro del rango del módulo 65537. La API no verifica el rango de las coordenadas contenidas en un ciphertext.

## Límites de la demo

- Una evaluación por asignación y hasta tres en una ventana móvil de una hora por pareja Policía–Usuario, incluso entre casos distintos. SQLite registra el consumo antes de publicar `Enc(Δ)`. Recargar y retransmitir el mismo mensaje no consume otra evaluación. Cada consulta nueva requiere el envío de la ubicación cifrada del usuario.
- Se puede reiniciar la sesión antes de evaluar. Si se pierde el estado criptográfico después de consumir la evaluación, se necesita una nueva asignación y aplica la misma cuota.
- La API limita el login a 20 intentos por minuto por IP, la creación a 10 casos por minuto por cuenta y el reinicio a 5 intentos por minuto por cuenta. Las cuotas temporales responden con `429` y `Retry-After`.
- La clasificación se guarda después del intercambio del circuito. El servidor la conserva y el usuario consultado solo recibe el estado. El protocolo supone participantes semi-honestos y las clasificaciones repetidas todavía pueden aportar información sobre la ubicación.

## Mapa de la demo

El mapa del panel de Policía ubica los iconos de forma ilustrativa según la clasificación. Para probar los roles con almacenamiento separado, abre Policía y Usuario en perfiles de navegador distintos.


## Recuperación de sesión criptográfica

La versión anterior podía mostrar:

```text
ese rol ya registró otra secret-key share en esta sesión
```

si regresabas al dashboard y luego volvías a abrir el protocolo. La API recordaba la share anterior, pero la nueva página había perdido la secret key en memoria y generaba otra distinta.

Esta versión lo corrige de dos formas:

1. guarda/restaura el estado criptográfico local por `cryptoSession`;
2. si el estado local se perdió de verdad, muestra **Reiniciar sesión criptográfica**, que borra CPK/RLK/inputs/shares de Δ/mensajes del circuito de esa pareja y obliga a ambas partes a comenzar de nuevo con un CRS nuevo.
