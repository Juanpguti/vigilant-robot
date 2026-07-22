# DevSecOps Pipeline — Proyecto Definitivo

Pipeline CI/CD con seguridad integrada de extremo a extremo sobre una API Node.js: análisis estático, dependencias, secretos, imagen de contenedor, análisis dinámico, SBOM, firma de imagen y un **dashboard de seguridad publicado automáticamente en GitHub Pages**.

Este repositorio consolida y reemplaza dos iteraciones previas (`devsecops-pipeline` y `DevSec-Pipe`), tomando lo mejor de cada una y agregando quality gates reales, supply-chain security y visualización de resultados.

---

## 1. Flujo del pipeline

```
                          ┌──────────────────────┐
                          │   Push / Pull Request │
                          └──────────┬───────────┘
                                     │
      ┌──────────────┬───────────────┼───────────────┬──────────────┐
      ▼              ▼               ▼               ▼              │
┌───────────┐ ┌─────────────┐ ┌───────────┐ ┌─────────────────┐    │
│ Lint+Test │ │   Secrets   │ │   SAST    │ │      SCA        │    │
│ ESLint    │ │  Gitleaks   │ │  Semgrep  │ │ npm audit +     │    │
│ Jest 80%  │ │ (historial) │ │ OWASP T10 │ │ Trivy fs        │    │
└─────┬─────┘ └──────┬──────┘ └─────┬─────┘ └────────┬────────┘    │
      │              │              │                │             │
      ▼              │              │                │             │
┌──────────────────┐ │              │                │             │
│ Build imagen     │ │              │                │             │
│ Trivy image scan │ │              │                │             │
│ SBOM CycloneDX   │ │              │                │             │
└────────┬─────────┘ │              │                │             │
         ▼           │              │                │             │
┌──────────────────┐ │              │                │             │
│ DAST · OWASP ZAP │ │              │                │             │
│ (red Docker)     │ │              │                │             │
└────────┬─────────┘ │              │                │             │
         └───────────┴──────┬───────┴────────────────┘             │
                            ▼                                      ▼
              ┌──────────────────────────┐        ┌─────────────────────────┐
              │  Security Dashboard      │        │  Push firmado a GHCR    │
              │  → GitHub Pages          │        │  (Cosign keyless)       │
              │  (solo main, siempre)    │        │  (solo main, si pasa)   │
              └──────────────────────────┘        └─────────────────────────┘
```

## 2. Qué controla cada etapa (y su quality gate)

| Etapa | Herramienta | Gate que rompe el pipeline |
|---|---|---|
| Calidad | ESLint + Jest | Errores de lint · cobertura < 80% |
| Secretos | Gitleaks (historial completo) | Cualquier secreto detectado |
| SAST | Semgrep (`p/owasp-top-ten` + reglas propias) | Hallazgos de severidad `ERROR` |
| SCA | npm audit + Trivy fs | Vulnerabilidades `HIGH`/`CRITICAL` con fix disponible |
| Container | Trivy image | Vulnerabilidades `HIGH`/`CRITICAL` con fix disponible |
| DAST | OWASP ZAP baseline | Alertas de nivel `FAIL` (los `WARN` se toleran y quedan visibles en el dashboard) |

Las excepciones se gestionan de forma **auditable**, nunca desactivando el gate:

- `.trivyignore` — CVEs aceptados, con justificación y fecha de revisión.
- `.zap/rules.tsv` — reglas de ZAP degradadas o ignoradas, con justificación.
- `security/sast/.semgrep.yml` — reglas SAST propias del proyecto.

## 3. Dashboard de seguridad (GitHub Pages)

En cada push a `main`, el job `dashboard`:

1. Descarga los reportes JSON de todos los escaneos (Semgrep, Trivy fs, Trivy image, ZAP, Gitleaks).
2. Recupera el `history.json` de la publicación anterior y agrega el run actual (últimos 30).
3. Genera un sitio estático (`dashboard/generate.js`) con: estado del gate, totales por severidad, desglose por herramienta, tendencia entre runs y enlace al reporte ZAP completo.
4. Lo publica con `actions/deploy-pages`.

El job corre con `if: always()`, así que el dashboard también refleja los pipelines fallidos — que es exactamente cuando más se necesita.

**Activación (una sola vez):** en el repositorio ir a *Settings → Pages → Source* y seleccionar **GitHub Actions**. La URL queda en `https://<usuario>.github.io/<repo>/`.

## 4. Supply-chain security

- **SBOM**: cada build genera un inventario CycloneDX (`sbom.cdx.json`) como artefacto.
- **Firma de imagen**: en `main`, si todos los gates pasan, la imagen se publica en GHCR etiquetada por SHA y se firma con **Cosign keyless** (OIDC de GitHub Actions, sin gestionar llaves).

Verificación de la firma:

```bash
cosign verify ghcr.io/<usuario>/<repo>:latest \
  --certificate-identity-regexp "https://github.com/<usuario>/<repo>" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

- **Dependabot**: actualizaciones semanales de npm, GitHub Actions y la imagen base de Docker.
- **Imagen endurecida**: multi-stage, usuario no root, `HEALTHCHECK`, solo `src/` y dependencias de producción.
- **Permisos mínimos**: `permissions: contents: read` global; cada job eleva únicamente lo que necesita.

## 5. Estructura del proyecto

```
├── .github/
│   ├── workflows/ci.yml        # Pipeline completo (8 jobs)
│   └── dependabot.yml          # Actualizaciones automáticas
├── .zap/rules.tsv              # Excepciones DAST justificadas
├── .trivyignore                # CVEs aceptados justificados
├── app/
│   ├── src/index.js            # API Express + Helmet
│   ├── tests/app.test.js       # Jest + Supertest (incluye test de cabeceras)
│   ├── eslint.config.mjs       # ESLint 9 con reglas de seguridad
│   └── jest.config.js          # Umbrales de cobertura
├── dashboard/generate.js       # Generador del dashboard estático
├── security/sast/.semgrep.yml  # Reglas SAST propias
├── Dockerfile                  # Multi-stage, non-root, healthcheck
└── docker-compose.yml          # Ejecución local endurecida
```

## 6. Ejecución local

```bash
# App
cd app && npm ci
npm run lint && npm test
npm start                      # http://localhost:3000/health

# Docker
docker compose up --build      # read-only + no-new-privileges

# Escaneos locales (mismos que el CI)
docker run --rm -v "$PWD:/repo" ghcr.io/gitleaks/gitleaks:latest detect --source /repo
docker run --rm -v "$PWD:/src" semgrep/semgrep semgrep scan \
  --config p/owasp-top-ten --config /src/security/sast/.semgrep.yml /src/app
trivy fs app/ --severity HIGH,CRITICAL --ignore-unfixed
trivy image demo-secure-api:local
```

## 7. Cómo probar que los gates funcionan

Agregar temporalmente en `app/src/index.js`:

```js
app.get('/vuln', (req, res) => res.json({ r: eval(req.query.c) }));
```

El push fallará en **tres** capas independientes: ESLint (`no-eval`), Semgrep (regla propia `no-eval` + OWASP Top 10) y, si llegara a desplegarse, ZAP lo evidenciaría en runtime. Eliminar el endpoint y el pipeline vuelve a verde — y ambos estados quedan registrados en la tendencia del dashboard.

## 8. Decisiones de diseño

- **La imagen se construye una sola vez** y se comparte entre jobs (`docker save` → artefacto → `docker load`): lo que se escanea es exactamente lo que se despliega.
- **Gates reales** (`exit-code: 1`) en vez de escaneos informativos: un control de seguridad que no puede detener el pipeline es solo decoración.
- **SARIF a GitHub Security** (Semgrep y Trivy image): los hallazgos aparecen en la pestaña *Security → Code scanning* con seguimiento por commit.
- **Dashboard sin infraestructura**: HTML estático + GitHub Pages. Cero costos, cero servidores, histórico persistente entre runs.

## Licencia

MIT
