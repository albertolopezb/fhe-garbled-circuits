# Private Proximity · Multi-tab Auth + SQLite + Lattigo/WASM

Esta versión está pensada para demostrar el protocolo con **Policía + tres usuarios abiertos al mismo tiempo**, sin hacer logout/login entre cada rol.

## Arquitectura

- **Go API**: autenticación, SQLite, coordinación de sesiones multiparty y evaluación homomórfica.
- **SQLite**: usuarios, sesiones de autenticación, casos, participantes y clasificación final.
- **party.wasm**: criptografía local en cada pestaña.
- **sessionStorage**: cada pestaña conserva su propio Bearer token, por lo que Policía, Carlos, Fer y Ximena pueden coexistir sin sustituir sus identidades.
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

La página principal permite abrir individualmente:

```text
Policía
Carlos
Fer
Ximena
```

o usar **Abrir todas las vistas**.

Cada pestaña pasa por `/demo-login.html?account=...`, elimina cualquier token heredado, inicia una sesión demo y guarda el token únicamente en su `sessionStorage`.

### Flujo recomendado

1. Abrir las cuatro vistas.
2. En Policía, crear un caso y seleccionar Carlos, Fer y Ximena.
3. En cada usuario, abrir su solicitud.
4. En Policía y en el usuario correspondiente, generar su secret key local. La primera parte quedará en “esperando a la otra parte”; eso es normal porque la CPK/RLK necesita las dos shares.
5. Cuando ambas partes estén listas, el botón de cifrado se habilita automáticamente.
6. Ingresar la ubicación y cifrarla localmente.
7. Puedes volver al dashboard y regresar al protocolo: el estado local se restaura desde `IndexedDB` y **no genera una secret key nueva**.
8. Volver a Policía; el dashboard se actualiza automáticamente.

Si el navegador bloquea múltiples pop-ups, permite pop-ups para `localhost:8080` o abre las vistas con los botones individuales.

## Autenticación por pestaña

La API acepta:

```http
Authorization: Bearer <token>
```

`shared.js` obtiene el token desde `sessionStorage`. Esto evita el problema de una cookie global que haría que el login de Carlos reemplazara el login de Policía en todas las pestañas.

El backend conserva soporte de cookie únicamente como fallback de compatibilidad, pero las vistas nuevas usan Bearer token.

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
[PCKS] Share generada
[POLICE LOCAL] Resultado final descifrado
```

No imprime valores de coordenadas, secret keys, `D²` ni `Delta`.

## Siguiente etapa

La siguiente capa de UI puede dibujar un aro representando el radio del caso y colocar cada icono de usuario **de forma ilustrativa** dentro o fuera del aro según la clasificación, sin mostrar su posición real.


## Recuperación de sesión criptográfica

La versión anterior podía mostrar:

```text
ese rol ya registró otra secret-key share en esta sesión
```

si regresabas al dashboard y luego volvías a abrir el protocolo. La API recordaba la share anterior, pero la nueva página había perdido la secret key en memoria y generaba otra distinta.

Esta versión lo corrige de dos formas:

1. guarda/restaura el estado criptográfico local por `cryptoSession`;
2. si el estado local se perdió de verdad, muestra **Reiniciar sesión criptográfica**, que borra CPK/RLK/inputs/PCKS de esa pareja y obliga a ambas partes a comenzar de nuevo con un CRS nuevo.
