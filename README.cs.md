# ssl-toolbox

[English documentation](README.md)

Go CLI pro převod PKCS#12, Java truststore a výměnu binárních souborů v YAML
manifestech Kubernetes ConfigMap. Operace s úložišti běží přímo v Go bez
OpenSSL a Javy. CLI je rozdělené na Cobra příkazy s vlastní nápovědou.

## Sestavení a přehled

Je potřeba Go 1.26 nebo novější.

```sh
go build -o ssl-toolbox .
./ssl-toolbox
./ssl-toolbox examples
./ssl-toolbox convert --help
./ssl-toolbox truststore --help
./ssl-toolbox configmap set-binary --help
./ssl-toolbox configmap extract-binary --help
./ssl-toolbox inspect --help
./ssl-toolbox extract --help
```

| Příkaz | Účel |
|---|---|
| `convert` | Převod existující identity nebo truststore z PKCS#12 na moderní PFX či JKS, případně přidání CA |
| `truststore` | Vytvoření čistého PFX/JKS truststore z CA PEM souborů |
| `configmap set-binary` | Nahrazení položky `binaryData` obsahem souboru zakódovaným do base64 |
| `csr create` | Vytvoření RSA/SHA-256 CSR a klíče nebo použití existujícího RSA klíče |
| `csr batch` | Kontrola a generování více CSR podle YAML; podpora dry-run |
| `pfx create` | Zabalení klíče, vydaného certifikátu a případného CA řetězce do moderního PFX |
| `inspect` | Rozpoznání certifikátů, klíčů a CSR podle obsahu; text, JSON nebo PDF |
| `extract` | Export klíče, certifikátu a dostupného CA řetězce z PFX do PEM souborů |
| `configmap extract-binary` | Obnova přesných binárních bajtů z klíče `binaryData` do nového souboru |
| `examples` | Přehled variant příkazů s vysvětlením a barevnými ukázkami |
| `version` | Verze a metadata sestavení; krátký výpis také přes `--version` |

Příkaz je nyní povinný: původní `ssl-toolbox --in ... --out ...` nahraď
`ssl-toolbox convert --in ... --out ...`. Pro vytvoření úložiště pouze z CA
použij `truststore`. Původní přepínače s jednou pomlčkou (`-in`, `-out`,
`-add-ca` atd.) uvnitř příkazů pro úložiště stále fungují; dokumentace používá
dvě pomlčky.

## Justfile a verzování

[just](https://just.systems/) poskytuje úlohy pro vývoj a sestavení:

```sh
just                 # přehled úloh
just check           # formátování bez změn + testy + go vet
just build           # lokální ./ssl-toolbox
just build-all       # Linux amd64, macOS arm64 a Windows amd64 do dist/
just version         # obsah VERSION
./ssl-toolbox --version
./ssl-toolbox version # verze, commit, čas buildu, Go a platforma
```

| Úloha | Účel |
|---|---|
| `build` | Nativní binárka v kořeni projektu |
| `build-linux` | `dist/ssl-toolbox-linux-amd64` |
| `build-macos` | `dist/ssl-toolbox-darwin-arm64` |
| `build-windows` | `dist/ssl-toolbox-windows-amd64.exe` |
| `build-all` | Všechny tři release platformy |
| `test`, `vet` | Testy a statická kontrola včetně lokální PKCS#12 knihovny |
| `fmt`, `fmt-check` | Naformátování, případně kontrola bez zápisu |
| `check` | `fmt-check`, `test` a `vet` |
| `version` | Aktuální číslo ze souboru `VERSION` |
| `notices` | Obnovení licenčního přehledu závislostí všech release platforem |
| `upgrade-modules` | Aktualizace externích Go modulů, checksums a notices, kontroly a lokální build |

`VERSION` je jediný výchozí zdroj verze; aktuální verze je `1.3.0`.
Před vydáním uprav číslo v tomto souboru a spusť `just check` a `just build-all`.
Běžný `go build` také obsahuje verzi díky `go:embed`. Just buildy navíc přes
linker vloží krátký Git commit a UTC čas sestavení. Bez Git repozitáře nebo
linker metadat se commit/čas zobrazují jako `unknown`. Úlohy nevytvářejí tagy,
commity a nic nepublikují.

Release buildy používají `CGO_ENABLED=0`. V `dist/` jsou také `LICENSE`,
`THIRD_PARTY_NOTICES.md`, oba README a `VERSION`; při distribuci binárek přibal
licenční soubory. `dist/` je ignorovaný Gitem. Úloha `upgrade-modules` zachovává
lokální modifikovanou PKCS#12 knihovnu přes `replace`; nesynchronizuje automaticky
její zdrojový kód s upstreamem. Notices po aktualizaci závislostí obnoví automaticky.

## GitLab Releases

Vlastní `.gitlab-ci.yml` používá stejný release postup jako `oci-toolbox`:

1. `release_notes` vygeneruje poznámky a metadata ze souboru `VERSION` a Git historie.
2. `check` a `test` ověří sestavení, formátování, `go vet` a testy aplikace i lokální PKCS#12 knihovny.
3. `release_binaries` sestaví šest archivů `.tar.gz`: Linux, macOS a Windows, vždy amd64 a arm64. Každý obsahuje binárku, obě README, `VERSION`, `LICENSE` a `THIRD_PARTY_NOTICES.md`. Vznikne i `SHA256SUMS`.
4. Archivy se nahrají do GitLab Generic Package Registry a `publish_release` je propojí s GitLab Release `v<VERSION>`.

Release se spustí při pushi změny `VERSION` na výchozí větev nebo ručně
přes **Build → Pipelines → New pipeline** pro výchozí větev. Ostatní změny
na výchozí větvi a merge requesty spustí kontroly. Soubor `VERSION` obsahuje
sémantickou verzi bez prefixu `v`; pipeline může tag vytvořit při publikaci.
Existující tag musí ukazovat na stejný commit, jinak zvýš verzi.

Build joby běží v `golang:1.27-bookworm` a kompilují přímo v Go. Žádný
Dockerfile, buildpack ani deployment job není součástí této pipeline.
Lokální `just build-all` nadále sestavuje tři hlavní cíle; release skript
navíc doplňuje arm64 pro Linux/Windows a amd64 pro macOS.

Publikace používá standardní `CI_JOB_TOKEN`; projekt musí povolovat Package
Registry a publikování Releases. Mezi joby cestují pouze malá metadata
s životností 30 dnů; archivy zůstávají v Package Registry a jsou ke stažení
z Releases. Opakování stejné verze na stejném commitu aktualizuje existující
Release a jeho odkazy. Chybné checksums nebo nesoulad tagu publikaci zastaví.

Volitelný `RELEASE_PUSH_TOKEN` s oprávněním zápisu do repozitáře umožňuje
zapsat generovaný `CHANGELOG.md` zpět do větve commitem s `[skip ci]`.
Bez něj zůstanou release notes u vydání a do repozitáře se nic nezapisuje.

Lokální příprava bez nahrávání:

```sh
bash scripts/ci_release_notes.sh
bash scripts/ci_package_release.sh
(cd dist/release && shasum -a 256 -c SHA256SUMS)
```

Go module path je `github.com/martinmares/ssl-toolbox`. GitLab pipeline
sestavuje lokální checkout, takže kvůli této cestě nepotřebuje přístup
k GitHub repozitáři. Pro publikaci používá API aktuálního GitLab projektu.

## GitHub Releases

`.github/workflows/release.yml` používá stejné skripty pro release notes a balení
jako GitLab. Spustí se při pushi změny `VERSION` na `main`, případně ručně přes
**Actions → Release → Run workflow** s vybranou větví `main`. Pro ruční spuštění
musí být workflow nejprve přítomný na výchozí větvi.

Workflow ověří formátování, sestavení, testy a `go vet` obou modulů, poté vytvoří
všech šest archivů a `SHA256SUMS`. Verzi Go převezme z `go.mod`. Publikace používá
vestavěný `GITHUB_TOKEN` s oprávněním `contents: write`; není potřeba osobní token
ani další secret. GitHub Actions musí být povolené a pravidla repozitáře nebo
organizace musí toto oprávnění umožňovat.

Nový release vznikne jako draft. Archivy a checksums se nahrají přímo jako
přílohy vydání a teprve potom se release zveřejní. Opakování stejné verze na
stejném commitu nahradí přílohy a aktualizuje poznámky. Existující tag na jiném
commitu publikaci zastaví; místo přepisování tagu zvýš `VERSION`. Verze s příponou
jako `1.0.2-rc.1` se označí jako prerelease.

Pro stejnou verzi na GitHubu i obou GitLab serverech pushni stejný commit se změnou
`VERSION` do všech repozitářů. Každý server vydá vlastní release z tohoto commitu.
Lokální build úlohy nic nepublikují.

## Vytvoření žádosti o certifikát (CSR)

```sh
ssl-toolbox csr create \
  --cn server.example.org --email admin@example.org \
  --country CZ --province "Czech Republic" --locality Prague \
  --organization Example --organizational-unit WEB \
  --sans-file dns-names.txt --ip 192.0.2.10 --ip 2001:db8::10 \
  --out-dir certificates --name server
```

`--out-dir` je adresář, který se podle potřeby vytvoří. `--name` je základ názvu
souborů bez přípony a standardně přebírá CN. Příklad vytvoří
`certificates/server.key` a `certificates/server.csr`. Existující soubory se
nepřepisují. Nové adresáře mají práva 0700 a soubory 0600. Klíč je
**nešifrovaný PKCS#8 PEM**, standardně RSA 4096; `--bits` podporuje 2048, 3072,
4096 a 8192. CSR se podepisuje SHA-256. OpenSSL se nespouští.

Povinné jsou CN a výstupní adresář. Ostatní položky Subject jsou volitelné;
`--email` nastavuje emailAddress v Subject, nikoliv e-mailový SAN. Organizace
ani lokalita nemají přednastavené hodnoty a konfigurace OpenSSL není potřeba.
`--country` přijímá dvě ASCII písmena a převede je na velká.

DNS soubor obsahuje jedno jméno na řádku:

```text
# Požadované aliasy
server.example.org
server
```

Prázdné řádky a komentáře za `#`, včetně komentářů na konci řádku, se ignorují.
Opakovatelný `--dns` přidává DNS SAN, `--ip` adresy IPv4/IPv6. Lze je kombinovat
s `--sans-file`; duplicity se odstraní. DNS jména používají ASCII nebo punycode.
Podporuje se `*.example.org`, wildcard smí být pouze prvním labelem. Pro wildcard
CN zadej explicitní `--name`. **CN se automaticky nepřidává do SAN**: všechna
požadovaná DNS jména uveď přes `--dns` nebo soubor, IP adresy přes `--ip`.

Použití existujícího RSA klíče:

```sh
ssl-toolbox csr create --cn server.example.org --dns server.example.org \
  --key existing.key --out-dir requests --name server

ssl-toolbox csr create --cn server.example.org --dns server.example.org \
  --key encrypted.key --key-pass-file "$KEY_PASSWORD_FILE" \
  --out-dir requests --name encrypted-server
```

S `--key` vznikne pouze CSR; původní klíč se nemění ani nekopíruje. Musí jít o RSA
alespoň 2048 bitů. Podporuje se PEM/DER PKCS#1 a PKCS#8, včetně šifrovaného PKCS#8
a staršího šifrovaného PEM. Pro neinteraktivní běh použij podle potřeby
`--key-pass-env KEY_PASSWORD` nebo `--key-pass-file <cesta>`.
`--key` a `--bits` nelze kombinovat.

Žádost před odesláním CA zkontroluj:

```sh
ssl-toolbox inspect certificates/server.csr
ssl-toolbox inspect certificates/server.csr --json
ssl-toolbox inspect certificates/server.csr --pdf request-report.pdf
```

Inspekce podporuje CSR v PEM (také `NEW CERTIFICATE REQUEST`) i DER. Zobrazí
Subject, veřejný klíč, SAN, algoritmus a ověření podpisu i SHA-256 otisk. Chybný
podpis se výslovně označí; jde o metadata a nemění návratový kód inspekce.
CSR nemá datum expirace a není vydaný certifikát. Jeho podpis nepotvrzuje
vlastnictví požadovaných jmen. CA pošli **jen CSR**, privátní klíč zůstává u tebe.

## Dávkové generování CSR z YAML

```sh
ssl-toolbox csr batch --config requests.yaml --out-dir certificates --dry-run
ssl-toolbox csr batch --config requests.yaml --out-dir certificates
```

Úplná ukázka je v [examples/csr-batch.yaml](examples/csr-batch.yaml).
Jedna položka vytvoří jeden privátní klíč a jednu CSR s libovolným počtem DNS/IP SAN:

```yaml
defaults:
  rsaBits: 4096
  subject:
    country: CZ
    organization: Example
    organizationalUnit: WEB
    email: admin@example.org
requests:
  - name: frontend
    subject:
      commonName: frontend.example.org
    san:
      dns: [frontend.example.org, frontend, portal.example.org]
      ip: [192.0.2.10]
  - name: backend
    subject:
      commonName: backend.example.org
      organizationalUnit: ""
    san:
      dns: [backend.example.org, backend]
      ip: [192.0.2.20, "2001:db8::20"]
```

Ve výstupním adresáři vzniknou `frontend.key`, `frontend.csr`, `backend.key`
a `backend.csr`. Povinné jsou `name` a `subject.commonName` u každé žádosti.
Jména jsou základy názvů souborů a musí být unikátní bez ohledu na velikost
písmen, aby nekolidovala na různých platformách. Oproti `csr create` se název
neodvozuje z CN. Wildcard CN lze použít s běžným názvem souboru.

Položky Subject (`country`, `province`, `locality`, `organization`,
`organizationalUnit`, `email`) se dědí z `defaults.subject` a jednotlivé
žádosti je mohou přepsat. Explicitní prázdný řetězec zděděnou položku odstraní.
`commonName` musí být uvedené přímo v žádosti. `rsaBits` je standardně 4096
s možností přepsání u žádosti pro nový klíč. SAN jsou vždy explicitní pro
konkrétní žádost; společné výchozí SAN nejsou podporované a CN se do SAN
nepřidává automaticky. Validace a odstranění duplicit jsou stejné jako u `csr create`.

Pro opětovné použití klíče přidej do žádosti místo jejího `rsaBits`:

```yaml
    key:
      file: keys/server.key
      passwordEnv: KEY_PASSWORD
      # Alternativně: passwordFile: secrets/key-password
```

S existujícím klíčem vznikne pouze CSR. Cesty `key.file` a `key.passwordFile`
jsou relativní k adresáři YAML souboru; lze použít i absolutní cestu.
`passwordEnv` je název proměnné s heslem. Zvol ENV nebo FILE, u nešifrovaného
klíče heslo vynech. Přímý zápis hesla do YAML není podporovaný. Výchozí počet
bitů se používá jen pro nové klíče; `rsaBits` přímo u žádosti nelze kombinovat s `key`.

YAML musí obsahovat právě jeden dokument. Neznámá pole, duplicitní klíče map,
duplicitní názvy žádostí, aliasy, merge klíče a hodnoty null se odmítají.
Pro dědění položku vynech, pro odstranění použij explicitní prázdný řetězec.
Celá dávka se připraví před generováním RSA nebo zápisem: ověří se výsledné
Subject/SAN, velikosti klíčů, existující RSA klíče a hesla i kolize výstupů.
Existující klíče se v této fázi načtou a uchovají pro generování.
`--dry-run` provede stejné kontroly a vypíše výsledný plán bez tvorby adresářů,
souborů nebo nových klíčů. U šifrovaného vstupního klíče může i dry-run
vyžadovat heslo; v CI jej předej přes ENV/FILE.

`--out-dir` je relativní k pracovnímu adresáři. Existující výstupy jsou chyba
i při dry-run; žádosti se automaticky nepřeskakují. Generování běží postupně.
Pokud po přípravě nastane chyba při generování nebo zápisu, dávka se zastaví
a chyba vypíše dokončené žádosti; jejich soubory zůstanou. Celá dávka není
atomická transakce. Částečný výsledek zkontroluj, potom použij nový adresář
nebo konfiguraci jen s nedokončenými žádostmi. Příkaz generuje CSR; odpovědi CA
a balení do PFX jsou samostatné kroky.

## Zabalení vydaného certifikátu do PFX

Až CA pošle podepsaný certifikát a případně certifikáty vydavatelů:

```sh
ssl-toolbox pfx create \
  --key certificates/server.key --cert issued.pem \
  --chain intermediate.pem --chain root.pem \
  --out certificates/server.pfx

ssl-toolbox inspect certificates/server.pfx
```

`--cert` přijímá právě jeden X.509 certifikát v PEM nebo DER bez ohledu na příponu
souboru. Opakovatelný `--chain` přijímá CA PEM soubory nebo balíčky, na pořadí
nezáleží. Vydavatelé se seřadí podle jmen a podpisů a duplicity se odstraní.
Nesouvisející CA a nejednoznačné řetězce se odmítnou. CA řetězec je volitelný;
balení neověřuje důvěryhodnost, platnost podle data ani revokaci. Přes `inspect`
vždy zkontroluj také **vydaný** certifikát: CA může změnit jména nebo použití
požadovaná v CSR.

Privátní klíč musí odpovídat vydanému certifikátu. Moderní PFX používá AES-256
a SHA-256 se stejným neprázdným heslem pro PFX i klíč. Interaktivně se heslo
potvrzuje; v CI ho předej přes ENV nebo FILE:

```sh
ssl-toolbox pfx create --key certificates/server.key --cert issued.cer \
  --chain ca-chain.pem --out certificates/server.pfx --out-pass-env PFX_PASSWORD

ssl-toolbox pfx create --key encrypted.key --key-pass-file "$KEY_PASSWORD_FILE" \
  --cert issued.pem --out encrypted-identity.pfx --out-pass-file "$PFX_PASSWORD_FILE"
```

`pfx create` přijímá také podporované EC/Ed25519 klíče. Pro existující šifrovaný
klíč slouží samostatné `--key-pass-env` / `--key-pass-file`. Existující výstupy
se nepřepisují; rodičovský adresář `--out` musí existovat. Pokud aplikace potřebuje
skutečné JKS, výsledné PFX převeď příkazem `convert --format jks`.

## Převod klientského PFX

```sh
ssl-toolbox convert --in legacy-client.pfx --out modern-client.pfx

ssl-toolbox convert --in legacy-client.pfx --out client.jks \
  --format jks --alias client
```

Vstup může používat staré šifry RC2/3DES nebo podporované Windows BER obaly.
Privátní klíč, klientský certifikát i přiložený CA řetězec zůstávají zachované.
Program se skrytě zeptá na původní heslo a dvakrát na nové.
**Stejné nové heslo chrání výstupní úložiště i privátní klíč.**
Původní heslo může být prázdné, nové nesmí. Dešifrovaný klíč se zpracovává
v paměti bez dočasných PEM souborů.

| Přepínač | Význam |
|---|---|
| `--in` | Povinný vstupní PKCS#12 soubor; přípona nerozhoduje |
| `--out` | Povinný nový výstupní soubor; nesmí existovat |
| `--format` | `pfx` (výchozí) nebo `jks`; přípona neurčuje formát |
| `--alias` | Alias privátního klíče v JKS, výchozí `client`; ukládá se malými písmeny |
| `--add-ca` | Opakovatelný CA PEM soubor; může obsahovat více certifikátů |
| `--in-pass-env` | Název proměnné prostředí s původním heslem |
| `--in-pass-file` | Soubor se vstupním heslem |
| `--out-pass-file` | Soubor s novým heslem |
| `--out-pass-env` | Název proměnné prostředí s novým heslem |

Výstup PFX používá AES-256-CBC, PBKDF2 a MAC SHA-256 (`Modern2023`).
Výstup JKS je skutečný Java KeyStore s vlastní starší ochranou klíče a
kontrolním součtem SHA-1. Soubor s příponou `.jks` může obsahovat PKCS#12;
přípona formát neurčuje. Java používá PKCS#12 jako výchozí od JDK 9
([dokumentace keytool](https://docs.oracle.com/en/java/javase/21/docs/specs/man/keytool.html)).

## Důvěryhodné CA a truststore

CA řetězec klientského certifikátu patří k jeho identitě. Samostatná důvěryhodná
CA naopak říká aplikaci, kterým vydavatelům může důvěřovat při ověřování protistrany.
`--add-ca` vytváří samostatné důvěryhodné položky; nepřipojuje nesouvisející CA
k řetězci klientského klíče.

```sh
ssl-toolbox convert --in client.pfx --out client-with-ca.pfx \
  --add-ca root-ca.pem --add-ca another-ca.pem

ssl-toolbox convert --in client.pfx --out client-with-ca.jks \
  --format jks --alias client --add-ca root-ca.pem
```

Čistý truststore bez privátního klíče vytvoříš takto:

```sh
ssl-toolbox truststore --out truststore.pfx \
  --add-ca root-ca.pem --add-ca ca-bundle.pem

ssl-toolbox truststore --out truststore.jks --format jks \
  --add-ca ca-bundle.pem
```

`truststore` vyžaduje `--out` a alespoň jeden `--add-ca`. Podporuje také
`--format` a `--out-pass-env`; ptá se pouze na nové heslo. Nemá `--in`,
vstupní heslo ani alias privátního klíče.

PEM může obsahovat několik certifikátů. Každý přidávaný certifikát musí mít
`CA:TRUE`. Prázdné soubory, vadné PEM/DER a jiné PEM objekty se odmítnou
před zadáváním hesla. Duplicity se odstraní a důvěryhodné položky mají alias
`ca-<SHA-256 otisk>`. PFX obsahuje Java trust atributy, takže Java položky
zobrazí jako `trustedCertEntry`; v JKS vznikají odpovídající trusted entries.
Aplikaci je potřeba nastavit, aby soubor skutečně používala jako truststore.

Příkaz `convert` načte i čistý nebo kombinovaný PKCS#12 truststore. Při dalším
převodu zachová důvěryhodnou roli certifikátů a jejich aliasy sjednotí na otisky.
JKS je zatím pouze výstupní formát. Vstup PKCS#12 podporuje jednu privátní
identitu; kontejnery s více identitami ani rozdílné vstupní heslo pro MAC a klíč
nepodporuje. Libovolná původní metadata, například friendly name klíče, se
nezachovávají. Lokální kopie SSLMate doplňuje cílenou podporu BER a kombinaci
identity s důvěryhodnými položkami; viz [lokální změny](third_party/go-pkcs12/LOCAL_CHANGES.md).

## Hesla v automatizaci

Místo interaktivního zadávání předej názvy proměnných prostředí:

```sh
# Proměnné nejprve nastav v shellu nebo pomocí poskytovatele tajných údajů.
ssl-toolbox convert --in client.pfx --out modern.pfx \
  --in-pass-env OLD_PFX_PASSWORD --out-pass-env NEW_PFX_PASSWORD

ssl-toolbox truststore --out truststore.jks --format jks \
  --add-ca root-ca.pem --out-pass-env NEW_PFX_PASSWORD
```

Názvy proměnných jsou libovolné. Chybějící proměnná způsobí chybu; výslovně
prázdná vstupní proměnná znamená prázdné původní heslo. Hodnoty hesel nejsou
argumenty programu. Skryté zadávání vyžaduje terminál. Výstupní soubory se
nepřepisují; na Unixu mají nová úložiště oprávnění `0600`.

### Hesla ze souborů a GitLab pipeline

Každý zdroj hesla má variantu ENV i FILE:

| Příkaz | ENV (název proměnné) | FILE (cesta k souboru) |
|---|---|---|
| `convert`, vstup | `--in-pass-env` | `--in-pass-file` |
| `convert` / `truststore`, nové heslo | `--out-pass-env` | `--out-pass-file` |
| `inspect`, úložiště / šifrovaný PEM nebo DER | `--pass-env` | `--pass-file` |
| `csr create` / `pfx create`, existující šifrovaný klíč | `--key-pass-env` | `--key-pass-file` |
| `pfx create`, nové heslo PFX/klíče | `--out-pass-env` | `--out-pass-file` |
| `inspect`, samostatné heslo JKS klíče | `--key-pass-env` | `--key-pass-file` |
| `extract`, vstupní PFX | `--pass-env` | `--pass-file` |

ENV a FILE pro stejné heslo se nesmějí kombinovat. Pro různá hesla je můžeš
libovolně míchat. ENV čte hodnotu přesně; FILE odstraní jeden koncový LF nebo
CRLF, ostatní znaky včetně mezer zachová. Prázdný soubor nebo ENV je platný
zdroj prázdného vstupního hesla; nové heslo musí být neprázdné. ENV/FILE nové
heslo nevyžaduje potvrzení. Chybějící proměnná, nečitelný soubor, nesprávné
heslo nebo potřeba dotazu bez terminálu skončí chybou a nenulovým návratovým
kódem. Hesla ani jejich obsah se nelogují.

U GitLab CI/CD proměnných typu **File** je hodnotou proměnné cesta; předej ji
FILE přepínači. U běžné proměnné předej její název ENV přepínači. Následující
job předpokládá dostupnou binárku a vstupní soubor; hesla nastav v CI/CD
Variables, nikoli do YAML:

```yaml
fix-keystore:
  script:
    - ssl-toolbox convert --in client.pfx --out modern.pfx --in-pass-file "$OLD_PFX_PASSWORD_FILE" --out-pass-file "$NEW_PFX_PASSWORD_FILE"
    - ssl-toolbox inspect modern.pfx --pass-file "$NEW_PFX_PASSWORD_FILE" --json > inspection.json
```

Varianta s běžnými ENV proměnnými:

```sh
ssl-toolbox convert --in client.pfx --out modern.pfx --in-pass-env OLD_PFX_PASSWORD --out-pass-env NEW_PFX_PASSWORD
ssl-toolbox inspect modern.pfx --pass-env NEW_PFX_PASSWORD --color never
ssl-toolbox truststore --out truststore.pfx --add-ca root-ca.pem --out-pass-file "$NEW_PFX_PASSWORD_FILE"
```

ConfigMap příkazy, `version` a `examples` hesla nepotřebují. V pipeline
použij nové výstupní soubory (`set-binary --out`, `extract-binary --out`),
případně `--dry-run`. `examples --color never` poskytne čistý text.

## Nahrazení binárního obsahu ConfigMap

Pole `binaryData` v ConfigMap obsahuje řetězce v base64
([dokumentace Kubernetes](https://kubernetes.io/docs/concepts/configuration/configmap/)).
Příkaz načte přesné bajty souboru `--file`, sám je zakóduje do base64 a
nahradí vybraný klíč. Neupravuje samotné úložiště a nekomunikuje s Kubernetes.

```sh
ssl-toolbox configmap set-binary \
  --manifest assets.yml \
  --key client.jks \
  --file new-client.jks \
  --dry-run
```

Po odstranění `--dry-run` upraví `assets.yml` přímo. Původní bajty nejprve
uloží do `assets.yml.bak`; existující zálohu nikdy nepřepíše. Náhradní soubor
se připraví a synchronizuje ve stejném adresáři a pak se atomicky přejmenuje.
Oprávnění manifestu zůstávají zachovaná; záloha má `0600`. Přímá úprava
vyžaduje běžný soubor, nikoli symlink. Pokud hodnota už odpovídá novému
souboru, nic se nezapisuje a nevzniká záloha.

| Přepínač | Význam |
|---|---|
| `--manifest` | Povinný vstupní YAML manifest |
| `--key` | Povinný klíč v `binaryData`; písmena, číslice, `.`, `_` a `-` |
| `--file` | Povinný zdrojový binární soubor |
| `--dry-run` | Zobrazí cílovou ConfigMap/klíč a původní i novou velikost v bajtech; nic nezapisuje |
| `--out` | Vytvoří nový YAML místo úpravy původního; nesmí existovat; nevzniká záloha |
| `--create` | Povolí přidat chybějící klíč nebo mapu `binaryData` |
| `--name` | Výběr podle `metadata.name`, pokud je ConfigMap více |
| `--namespace` | Upřesnění podle `metadata.namespace` |

Manifest může obsahovat více YAML dokumentů. Výběr musí určit právě jednu
`apiVersion: v1`, `kind: ConfigMap`. Klíč musí existovat, pokud nepoužiješ
`--create`. Kolize s klíčem v `data`, neplatná původní base64 a duplicitní YAML
klíče se odmítnou. Cílové mapy ani nahrazovaná hodnota nesmějí používat YAML
kotvy, aliasy nebo merge. ConfigMap uvnitř `List.items` se nevybírají.
Ostatní dokumenty, hodnoty a komentáře se zachovají; mezery, uvozovky a
formátování může YAML encoder upravit. Binární ani base64 obsah se nevypisuje,
ani při `--dry-run`.

Zápis do jiného souboru nebo přidání klíče do vybrané ConfigMap:

```sh
ssl-toolbox configmap set-binary --manifest assets.yml \
  --key client.jks --file new-client.jks --out updated-assets.yml

ssl-toolbox configmap set-binary --manifest resources.yml \
  --name client-assets --namespace prod \
  --key root-ca.der --file root-ca.der --create
```

### Ukázka v projektovém adresáři

```sh
ssl-toolbox configmap set-binary \
  --manifest manifests/configmap.yaml \
  --key client.jks \
  --file certificates/client.jks \
  --dry-run
```

Po kontrole cíle odstraň poslední `--dry-run`. Před pozdější opakovanou úpravou
nejprve sám přesuň nebo odstraň předchozí `.bak`, případně použij `--out`.

## Extrakce certifikátu a privátního klíče z PFX

```sh
ssl-toolbox extract client.pfx --out-dir ./export
ssl-toolbox extract client.pfx --out-dir ./export --pass-env STORE_PASSWORD
ssl-toolbox extract client.pfx --out-dir ./export --pass-file "$STORE_PASSWORD_FILE"
```

Jde o alternativní způsoby spuštění; vyber jeden zdroj hesla a výstupní adresář,
ve kterém cílové soubory ještě neexistují.

Vznikne `client.key` (nešifrovaný PKCS#8 PEM), `client.pem` (odpovídající
certifikát) a případně `client.chain.pem` s dostupným CA řetězcem. Názvy vycházejí
ze vstupního souboru bez poslední přípony. Výstup je čistý PEM bez metadat
OpenSSL. Soubory mají oprávnění `0600`, nové adresáře `0700`. Existující soubory
ani symlinky se nepřepisují; před zápisem se zkontrolují všechny cíle.
Exportovaný klíč není chráněn heslem. Původní PFX zůstane beze změny.

Nejprve se zkouší prázdné heslo PFX, jinak se nástroj zeptá. Přepínače
`--pass-env` a `--pass-file` fungují stejně jako u `inspect` a navzájem se
vylučují. Podporované šifrování PFX a BER odpovídá příkazu `inspect`.
Hesla ani obsah klíče se nevypisují.

Při více klíčích nejprve spusť `inspect` a vyber klíč pomocí `--entry entry-N`.
Pokud mu odpovídá více různých certifikátů, vyber také `--cert-entry entry-N`.
ID pocházejí z téhož nezměněného PFX. Při více klíčích se žádná identita
nevybírá automaticky.

```sh
ssl-toolbox inspect identities.pfx
ssl-toolbox extract identities.pfx --out-dir ./export --entry entry-3
```

Pokud je potřeba vybrat také certifikát, použij místo extrakce výše následující
variantu. Obě ID nahraď ID privátního klíče a odpovídajícího certifikátu
z výpisu `inspect`:

```sh
ssl-toolbox extract identities.pfx --out-dir ./export --entry entry-3 --cert-entry entry-2
```

CA řetězec obsahuje jen dostupné vydavatele vybraného certifikátu, od nejbližšího
po kořenový certifikát, pokud je přítomen. Nesouvisející certifikáty se vynechají.
Kontrolují se jména vydavatelů a podpisy; nejednoznačný řetězec nebo cyklus je
chyba. Chybějící certifikáty se nestahují. Extrakce neověřuje platnost podle
data, důvěryhodnost ani revokaci.

## Inspekce úložišť, certifikátů a klíčů

```sh
ssl-toolbox inspect client.jks
ssl-toolbox inspect ca-bundle.pem
ssl-toolbox inspect client.der
ssl-toolbox inspect client.pfx --pass-env STORE_PASSWORD --json > inspection.json
ssl-toolbox inspect client.jks --pass-env STORE_PASSWORD --key-pass-env KEY_PASSWORD
```

Formát se určí podle obsahu, bez ohledu na příponu: PKCS#12/PFX (včetně
podporovaného BER a legacy šifrování), skutečné JKS, PEM balíčky a DER.
DER může obsahovat certifikát, navazující certifikáty, veřejný nebo privátní
klíč; podporované klíče zahrnují PKCS#8, RSA PKCS#1 a EC SEC1. Šifrovaný
PKCS#8 a starší šifrovaný PEM se také dešifrují přímo v Go.

Vypíšou se všechny podporované položky, včetně více privátních klíčů,
certifikátů z řetězců a samostatných trusted CA. U certifikátů uvidíš subject,
issuer, sériové číslo, platnost a její stav, CA/basic constraints, SAN, KU/EKU,
podpisový algoritmus a SHA-256 otisk. U klíčů algoritmus, délku, EC křivku
a SHA-256 veřejné části (SPKI). Výpis propojí odpovídající klíče a certifikáty,
ukáže aliasy, localKeyID, dostupná data vytvoření a parametry šifrování/MAC.
Privátní bajty ani hesla se nevypisují. Stav platnosti podle data neznamená
ověření důvěryhodného řetězce nebo revokace.

Nejprve se vyzkouší prázdné heslo; pokud nestačí, následuje skrytý dotaz
v terminálu. U JKS se pro klíč nejprve zkusí heslo úložiště, pak případně
samostatný dotaz pro daný alias. `--pass-env` zadává **název proměnné**
s heslem úložiště nebo šifrovaného PEM/DER klíče; `--key-pass-env` je
samostatné heslo JKS klíčů. Chybějící proměnná nebo nesprávné zadané heslo
je chyba. `--json` mění výstup na strukturovaná metadata; dotazy zůstávají
na stderr. Inspekce kontroluje integritu PFX/JKS, pokud je přítomná.
Nepodporovaný PFX bag se označí jeho OID; nepodporovaný PEM blok,
neplatná položka nebo chyba dešifrování ukončí příkaz bez částečného výpisu.
PEM přijímá bílé znaky a metadata exportů OpenSSL (`Bag Attributes`,
`Key Attributes`, `subject=`, `issuer=`) před bloky i mezi nimi.
Jiný text mimo PEM bloky se odmítá.

### PDF report

```sh
ssl-toolbox inspect client.pfx --pdf inspection.pdf
ssl-toolbox inspect client.jks --pass-file "$STORE_PASSWORD_FILE" \
  --expiry-warning-days 60 --pdf keystore-report.pdf
```

`--pdf <soubor>` uloží barevný report A4 místo metadat v terminálu. Obsahuje
všechny položky, stejné detaily a varování jako textový výpis, UTC čas vytvoření
a čísla stránek. Dlouhé hodnoty se zalamují přes řádky a stránky. Fonty jsou
vložené do PDF a podporují českou diakritiku; jejich licence je přílohou PDF.
Export nevyžaduje prohlížeč, externí PDF program ani systémové fonty a funguje
i v CI. Volby pro hesla fungují stejně jako u textového výpisu. Hesla ani bajty
privátních klíčů report neobsahuje. Existující soubory se nepřepisují; `--pdf`
a `--json` nelze kombinovat. `--color` ovlivňuje jen terminál, PDF je vždy barevné.

U expirace je také lidsky čitelný odhad, například
`Expiry: in 989 days (about 2 years and 8 months)`. Platí k okamžiku inspekce;
uložené PDF se postupem času neaktualizuje. Odhad počítá měsíc jako 30 dní
a rok jako 365 dní. JSON nadále obsahuje přesný počet sekund.

### Barvy a expirace

`inspect` používá `--color auto|always|never`. `auto` barví pouze terminál,
respektuje `NO_COLOR` a `TERM=dumb`; `always` barvy vynutí. JSON zůstává vždy
bez ANSI barev. Nadpisy a popisky jsou tyrkysové, privátní klíče žluté,
trusted certifikáty modré; aliasy a subject jsou zvýrazněné, otisky tlumené.
Stav `EXPIRED` je červený, `EXPIRING SOON` a `NOT YET VALID` žlutý a platný
certifikát zelený. Explicitní textové značky zůstávají i bez barev.

Na začátku je souhrn problémových dat platnosti, u každé položky termín
expirace a zbývající čas. Výchozí varování je **30 dnů**; změň jej přes
`--expiry-warning-days 60`, nebo použij `0` pro vypnutí varování předem.
Expirované certifikáty se označují vždy. JSON obsahuje `expiry_warning_days`,
`validity` a podepsaný `expires_in_seconds`. Tyto stavy jsou informativní,
samy o sobě nemění návratový kód; čtení/dešifrování musí být úspěšné.

```sh
ssl-toolbox inspect client.pfx --expiry-warning-days 60
ssl-toolbox inspect client.pfx --color always
ssl-toolbox inspect client.pfx --pass-env STORE_PASSWORD --color never
```

## Extrakce binárního souboru z ConfigMapy

```sh
ssl-toolbox configmap extract-binary assets.yml client.jks --out extracted.jks
ssl-toolbox configmap extract-binary resources.yml client.jks \
  --name client-assets --namespace prod --out client.jks
ssl-toolbox inspect extracted.jks
```

Manifest a klíč jsou poziční argumenty. Povinné `--out` vytvoří nový soubor
s oprávněními `0600`; existující soubor ani symlink se nepřepíše. Zdrojový
YAML se vůbec nemění a nevzniká `.bak`. Hodnota `binaryData` se dekóduje
z base64 do přesných původních bajtů, včetně prázdného souboru. Výpis
obsahuje jen cíl, počet bajtů a SHA-256 otisk.

Výběr `--name`/`--namespace` a ověřování YAML sdílí pravidla s `set-binary`.
Vybraná ConfigMap musí být jednoznačná a klíč musí existovat v `binaryData`.
`data` se tímto příkazem neextrahuje. Neplatná base64, duplicitní klíče,
kolize s `data` a kotvy/aliasy v cílových mapách či hodnotě se odmítnou.

## Vysvětlené příklady a barvy

```sh
ssl-toolbox examples
ssl-toolbox examples --color always
ssl-toolbox examples --color never > examples.txt
```

Katalog má podobné členění jako `oci-toolbox examples`: tyrkysové nadpisy,
žluté názvy příkladů, zelené shell příkazy a modré ukázky souborů.
Každá varianta vysvětluje přepínače a účinky. `example` je alias příkazu.
Výchozí `--color auto` barví jen výstup do terminálu; přesměrování, `NO_COLOR`
a `TERM=dumb` barvy vypínají. `always` výslovně vynutí ANSI barvy.
Výpis příklady zobrazuje, nespouští je.

## Ověření a testy

```sh
go test ./... software.sslmate.com/src/go-pkcs12
go vet ./... software.sslmate.com/src/go-pkcs12

# Volitelné externí ověření; nástroje se zeptají na nové heslo.
openssl pkcs12 -in modern.pfx -info -noout
keytool -list -v -storetype JKS -keystore client.jks
keytool -list -v -storetype PKCS12 -keystore truststore.pfx
```

Testy ověřují legacy/BER vstupy, hesla, zachování klíče a řetězce, PEM balíčky,
duplicity, trusted entries a opětovný převod. Pokud jsou nástroje dostupné,
OpenSSL/LibreSSL dešifruje vytvořený klíč a Java `keytool` importuje a kontroluje
oba výstupní formáty. YAML testy ověřují výběr dokumentu, zachování obsahu,
base64, režimy create/dry-run/out, ochranu zálohy a oprávnění. Testy katalogu
ověřují ANSI režimy a chyby výstupu. Platnost certifikátů a oprávnění ke Kafce
se převodem nemění; výsledek ověř ve skutečném klientském prostředí.

Testy nových příkazů ověřují více identit v PFX/JKS, samostatná hesla JKS klíčů,
PEM/DER, metadata OpenSSL v PEM, šifrovaný PKCS#8, metadata JSON bez privátního
materiálu a přesnou extrakci binárních bajtů bez změny manifestu. Testy extrakce
PFX kontrolují obsah klíče a certifikátu, pořadí a nejednoznačnost CA řetězce,
výběr identity, zdroje hesel, oprávnění a odmítnutí přepsání výstupů.

## Licence a správa projektu

Kód projektu je pod standardní [MIT License](LICENSE),
Copyright (c) 2026 Martin Mareš. Software je poskytován „AS IS“, bez záruk a
bez nároku na bezplatnou komunitní podporu. Přijetí nebo review externích pull
requestů není garantované. Tato pravidla neomezují práva udělená MIT licencí.

Licence a copyright notices závislostí zůstávají zachované; viz
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md). Lokální PKCS#12 knihovna si
ponechává původní [BSD licenci](third_party/go-pkcs12/LICENSE).

Po publikování na GitHubu vypni Issues a Discussions a nastav ochranu větve
`main`; oprávnění k zápisu dej pouze vlastníkovi a výslovně pověřeným maintainerům.
Na GitLabu nastav odpovídající ochranu a dostupnost podpůrných funkcí.
Podrobný stav aplikace licenční politiky je v [LICENSING_STATUS.md](LICENSING_STATUS.md).
