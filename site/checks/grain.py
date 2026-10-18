from pathlib import Path
from PIL import Image
import random
r=random.Random(1741)
im=Image.new('L',(128,128));im.putdata([r.randrange(45,210) for _ in range(128*128)])
im.convert('RGB').save(Path(__file__).resolve().parents[1]/'public/assets/grain.png',optimize=True)
