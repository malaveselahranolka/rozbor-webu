# Rozbor webu

Lokální aplikace pro technický rozbor webů a AI asistentů na Windows a macOS. V jedné analýze lze spojit URL, jeden nebo více síťových záznamů HAR, screenshoty, vložený text a klientské soubory. Výstup v Markdownu se dá vložit do ChatGPT nebo Claude. Export JSON obsahuje stejné nálezy ve strukturované podobě.

## Stažení a spuštění

Stáhni **Rozbor-webu.zip** v sekci [Releases](../../releases/latest) a rozbal ho. Běh aplikace a zpracování souborů probíhají na tvém počítači.

### MacBook

Potřebuješ **macOS 14 Sonoma nebo novější** a **Python 3.11+**. Otevři **Spustit-Mac.command**. Při prvním spuštění skript vytvoří ve složce projektu virtuální prostředí a stáhne závislosti a Chromium. Rozpoznávání screenshotů používá místní Apple Vision.

Stejný spouštěč lze otevřít z Terminálu ve složce projektu.

~~~bash
bash ./Spustit-Mac.command
~~~

### Windows

Potřebuješ **Python 3.10+**. Otevři **Spustit.cmd** a nech běžet okno příkazové řádky po dobu používání aplikace. HAR, text a kód fungují se samotným Pythonem. Rozbor URL používá Playwright a Chromium. Pro OCR screenshotů používá aplikace Pillow a Windows s nainstalovaným jazykem rozpoznávání.

Pokud chybí knihovny, spusť ve složce projektu v PowerShellu:

~~~powershell
py -3 -m pip install -r requirements.txt
py -3 -m playwright install chromium
~~~

Pokud už máš Chrome nebo Edge, aplikace je zkusí použít i bez stahování Chromia.

[Instalace Pythonu na Macu](https://www.python.org/downloads/macos/) · [Požadavky Playwrightu](https://playwright.dev/python/docs/intro#system-requirements)

## Vstupy a důkazy

| Vstup | Co může report doložit |
| --- | --- |
| **URL** | Požadavky, které Chromium zachytilo při načtení. Volitelný záznam v novém okně zachytí i ruční akce po dobu 30, 60 nebo 120 sekund. |
| **HAR** | Zaznamenaná volání včetně metod, HTTP stavů, typů přenosu a dostupných struktur dat. Důkaz odkazuje na číslo položky v souboru. |
| **Screenshot** | Text přečtený OCR a funkce, jejichž názvy se v něm objevují. Kvalita závisí na čitelnosti a jazyku OCR. |
| **HTML, JS, TS, JSON, OpenAPI, mapa nebo text** | Odkazy a signatury technologie s umístěním v dodaném materiálu. Cesty nalezené v kódu jsou kandidáty k ověření. |

Pro podrobný rozbor konkrétního kroku, třeba odeslání zprávy nebo generování obrázku, použij v Chrome či Edge **F12 → Network → Preserve log**. Proveď akci a vyber **Export HAR (sanitized)**. Každá akce může mít vlastní HAR s výstižným názvem.

## Čtení reportu

- **Pozorovaná síťová volání** seskupují požadavky podle metody a normalizované URL. Report ukládá názvy parametrů a polí, vybrané názvy operací GraphQL a rozpoznané kódy služby. Hodnoty parametrů, cookie a autorizační hlavičky report vynechává.
- **Stavy přístupu a účtování** ukazují zachycené HTTP 401, 402, 403 a 429 nebo explicitní kód v JSON odpovědi, například SUBSCRIPTION_REQUIRED. Konkrétní tarif lze potvrdit z popisu služby nebo jejím testem s příslušným přístupem.
- **Technologické stopy** ukazují oporu v doméně, hlavičce nebo klientském kódu. Například volání na Firestore potvrzuje kontakt s danou službou. K úplnému doložení architektury a obsahu databáze jsou potřeba další podklady.
- **Klientské soubory** obsahují velikost a SHA-256. Analýza URL může načíst deklarované zdrojové mapy v originu příslušného skriptu. Tyto samostatné požadavky mají v reportu označení „načtení deklarované mapy“. Pokud mapa obsahuje zdroj uvnitř sourcesContent, analyzují se i jeho dostupné části.
- Po zapnutí volby **Přibalit původní JavaScript a zdrojové mapy** lze stáhnout ZIP se zachycenými soubory. Původní obsah těchto souborů může zahrnovat data vložená autorem webu. Exportovaný text ze screenshotů může zachytit viditelné údaje.

Serverový kód, interní konfigurace, databáze a kroky vyžadující přístup lze doložit z příslušného účtu nebo předaných zdrojů. Výsledky pro URL pokrývají zaznamenané okno. Záznam počítá události WebSocket bez ukládání rámců. SSE vychází ze síťového typu nebo hlavičky odpovědi.

Podklady a zpracování zůstávají na počítači. Při analýze URL se prohlížeč připojuje k vybranému webu a jeho běžným závislostem. Celkový limit je 6 příloh do 64 MiB na jednu analýzu. Zpracování zahrne nejvýše 3 500 položek z jednoho HAR, 1 500 požadavků z prohlížeče, 4 MiB na klientský soubor a 8 samostatně načtených map.

## Spuštění ze skriptu

Windows

~~~powershell
py -3 -X utf8 app.py analyze --url "https://example.com" --file ".\konverzace.har" --archive --out ".\rozbor.zip"
~~~

macOS po prvním spuštění

~~~bash
./.venv/bin/python -X utf8 app.py analyze --url "https://example.com" --file "./konverzace.har" --archive --out "./rozbor.zip"
~~~

ZIP obsahuje report.md a report.json. Argument --file lze zadat vícekrát. --window 60 zapne minutový ruční záznam.

[Export HAR v Chrome](https://developer.chrome.com/docs/devtools/network/reference/#save-all-network-requests-to-a-har-file) · [Podporované prohlížeče Playwrightu](https://playwright.dev/python/docs/browsers)

## Licence

MIT. [Úplné znění licence](LICENSE)
