"""Icônes S3m dérivées de LogoS3M.png (racine du dépôt).

Produit, à côté de ce script :
- tray-<état>.rgba : icônes 32×32 RGBA brutes de la barre des tâches (marque
  « S » sur pastille claire, point d'état en bas à droite) ;
- s3m.ico : icône de l'exécutable (16 à 256 px) ;
- logo.png : marque 64×64 pour les dashboards (copiée côté Nœud aussi).

Usage, depuis la racine du dépôt :  python impl/connector/assets/make_icons.py
"""
import os
import sys

from PIL import Image, ImageDraw, ImageFilter

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", "..", ".."))
STATES = {
    "ok": (46, 157, 91),
    "sync": (47, 127, 216),
    "paused": (138, 138, 138),
    "offline": (224, 145, 43),
    "error": (210, 59, 50),
}


def mark(src: Image.Image) -> Image.Image:
    """Marque « S » (partie haute du logo), fond blanc rendu transparent."""
    g = src.convert("L")
    w, h = g.size
    top = g.crop((0, 0, w, int(h * 0.68)))  # au-dessus du texte « S3M »
    bbox = top.point(lambda v: 255 if v < 200 else 0).getbbox()
    m = src.convert("RGB").crop(bbox)
    alpha = m.convert("L").point(lambda v: max(0, min(255, int((235 - v) * 1.6))))
    navy = Image.new("RGBA", m.size, (11, 37, 69, 255))
    navy.putalpha(alpha)
    side = max(m.size)
    sq = Image.new("RGBA", (side, side), (0, 0, 0, 0))
    sq.paste(navy, ((side - m.size[0]) // 2, (side - m.size[1]) // 2), navy)
    return sq


def badge(m: Image.Image, size: int, dot=None) -> Image.Image:
    """Marque sur pastille arrondie claire (lisible sur barre sombre ou claire)."""
    s = size * 4  # suréchantillonnage puis réduction : bords lisses
    img = Image.new("RGBA", (s, s), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    d.rounded_rectangle((0, 0, s - 1, s - 1), radius=s // 5, fill=(250, 250, 248, 255))
    inner = int(s * 0.80)
    if size <= 48:
        # Petites tailles : traits épaissis, sinon le réseau devient un gris délavé.
        m = m.filter(ImageFilter.MaxFilter(15))
    mm = m.resize((inner, inner), Image.LANCZOS)
    img.alpha_composite(mm, ((s - inner) // 2, (s - inner) // 2))
    if dot is not None:
        r = int(s * 0.15)
        cx, cy = s - r - 2, s - r - 2
        d.ellipse((cx - r - 6, cy - r - 6, cx + r + 6, cy + r + 6), fill=(255, 255, 255, 255))
        d.ellipse((cx - r, cy - r, cx + r, cy + r), fill=dot + (255,))
    return img.resize((size, size), Image.LANCZOS)


def main() -> None:
    src = Image.open(os.path.join(ROOT, "LogoS3M.png"))
    m = mark(src)
    for name, color in STATES.items():
        icon = badge(m, 32, color)
        open(os.path.join(HERE, f"tray-{name}.rgba"), "wb").write(icon.tobytes())
    sizes = [16, 24, 32, 48, 64, 128, 256]
    big = badge(m, 256)
    big.save(os.path.join(HERE, "s3m.ico"), sizes=[(s, s) for s in sizes])
    logo = m.resize((64, 64), Image.LANCZOS)
    logo.save(os.path.join(HERE, "logo.png"))
    for dash in ["impl/connector/dashboard", "impl/node/dashboard"]:
        logo.save(os.path.join(ROOT, dash, "logo.png"))
    print("icônes écrites dans", HERE, file=sys.stderr)


if __name__ == "__main__":
    main()
