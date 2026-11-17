import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


def _describe_ocr(engine, lines):
    if not lines:
        return [], f"OCR ({engine}) · v obrázku nebyl čitelný text."
    return lines, f"OCR ({engine}) · {len(lines)} řádků textu, zpracováno {min(len(lines), 100)}."


def _windows_ocr(image):
    powershell = shutil.which("powershell.exe")
    if not powershell:
        return [], "Windows PowerShell pro OCR se nepodařilo najít."
    try:
        with tempfile.TemporaryDirectory(prefix="rozbor-ocr-") as temporary:
            filename = Path(temporary) / "screenshot.png"
            image.save(filename)
            result = subprocess.run(
                [powershell, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
                 "-File", str(Path(__file__).with_name("ocr.ps1").resolve()), "-Path", str(filename)],
                capture_output=True, timeout=22, creationflags=subprocess.CREATE_NO_WINDOW,
            )
    except (OSError, subprocess.SubprocessError):
        return [], "Windows OCR se nepodařilo spustit nebo nedoběhlo v časovém limitu."
    if result.returncode:
        if "Windows OCR language is unavailable" in result.stderr.decode("utf-8", errors="replace"):
            return [], "Windows potřebuje aspoň jeden jazykový balíček s podporou OCR."
        return [], "Windows OCR v tomto prostředí nepřečetlo obrázek."
    try:
        result_data = json.loads(result.stdout)
        lines = [line for line in result_data.get("lines", []) if isinstance(line, str)]
        language = result_data.get("language", "")
    except (ValueError, AttributeError, TypeError):
        return [], "Výstup Windows OCR má neznámý formát."
    return _describe_ocr(language, lines)


def _macos_ocr(image):
    try:
        import objc
        from Foundation import NSData
        from Vision import VNImageRequestHandler, VNRecognizeTextRequest, VNRequestTextRecognitionLevelAccurate
    except ImportError:
        return [], "Pro OCR na Macu nainstaluj závislosti pomocí Spustit-Mac.command."
    buffer = io.BytesIO()
    image.save(buffer, format="PNG")
    png = buffer.getvalue()
    try:
        with objc.autorelease_pool():
            data = NSData.dataWithBytes_length_(png, len(png))
            request = VNRecognizeTextRequest.alloc().init()
            request.setRecognitionLevel_(VNRequestTextRecognitionLevelAccurate)
            request.setAutomaticallyDetectsLanguage_(True)
            # A Mac without GPU acceleration can still run the OCR request.
            request.setUsesCPUOnly_(True)
            handler = VNImageRequestHandler.alloc().initWithData_options_(data, {})
            success, error = handler.performRequests_error_([request], None)
            if not success:
                code = f" (kód {error.code()})" if error else ""
                return [], f"Apple Vision se nepodařilo přečíst obrázek{code}."
            lines = []
            for observation in request.results() or ():
                candidates = observation.topCandidates_(1)
                if candidates:
                    lines.append(str(candidates[0].string()))
    except (objc.error, OSError, TypeError, ValueError, AttributeError):
        return [], "Rozpoznávání textu přes Apple Vision se nepodařilo dokončit."
    return _describe_ocr("Apple Vision", lines)


def recognize_image(data, _suffix):
    if os.name != "nt" and sys.platform != "darwin":
        return [], "Rozpoznávání textu ze screenshotů je dostupné ve Windows a macOS."
    try:
        from PIL import Image, ImageOps
    except ImportError:
        return [], "Pro rozpoznání textu v obrázku nainstaluj Pillow podle README."
    try:
        with Image.open(io.BytesIO(data)) as source:
            if source.width * source.height > 30_000_000:
                return [], "Obrázek je nad limitem 30 megapixelů."
            image = ImageOps.exif_transpose(source)
            image.thumbnail((2400, 2400))
            layer = image.convert("RGBA")
            background = Image.new("RGBA", layer.size, "white")
            background.alpha_composite(layer)
    except (OSError, ValueError, Image.DecompressionBombError):
        return [], "Obrázek se nepodařilo přečíst."
    image = background.convert("RGB")
    if sys.platform == "darwin":
        return _macos_ocr(image)
    return _windows_ocr(image)
