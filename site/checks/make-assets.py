from pathlib import Path
from PIL import Image, ImageDraw, ImageFont
from fontTools.ttLib import TTFont
from fontTools.varLib.instancer import instantiateVariableFont
import base64, json, shutil
R=Path(__file__).resolve().parents[2]; S=R/'site/public'; D=R/'docs/images'; B=R/'assets/brand'; F=S/'fonts'
for name in ['spacegrotesk','manrope','jetbrainsmono','instrument-serif-italic']:
 f=TTFont(F/(name+'.woff2'))
 if 'fvar' in f:
  axes={a.axisTag:(600 if a.axisTag=='wght' else a.defaultValue) for a in f['fvar'].axes};f=instantiateVariableFont(f,axes)
 f.flavor=None;f.save(R/'tmp/landing-proof'/ (name+'.ttf'))
 if (F/(name+'.woff2')).read_bytes()[:4] != b'wOF2':
  f.flavor='woff2';f.save(F/(name+'.woff2'))
def font(n,s):return ImageFont.truetype(str(R/'tmp/landing-proof'/(n+'.ttf')),s)
def text(draw,xy,s,size,color,n='spacegrotesk'):draw.text(xy,s,font=font(n,size),fill=color)
mark=Image.open(B/'ralx-mark.png').convert('RGBA'); mark=mark.crop(mark.getbbox());mark.save(B/'ralx-mark.png')
light=mark.copy(); p=light.load()
for y in range(light.height):
 for x in range(light.width):
  rr,gg,bb,aa=p[x,y]
  if bb>rr or rr<60:p[x,y]=(245,242,235,aa)
mark.save(S/'assets/ralx-mark.png');light.save(S/'assets/ralx-mark-light.png')
hero=Image.open(B/'explorations/hero-b.png').convert('RGBA');hero=hero.crop(hero.getbbox());hero.thumbnail((1000,1000));hero.save(S/'assets/hero.webp',quality=84)
poster=Image.open(D/'poster.png').convert('RGB');poster.save(S/'assets/poster.webp',quality=85)
for theme,bg,fg in [('light','#f5f2eb','#0e1320'),('dark','#0e1320','#f5f2eb')]:
 im=Image.new('RGB',(1280,480),bg);dr=ImageDraw.Draw(im);mk=(mark if theme=='light' else light).copy();mk.thumbnail((63,63));im.paste(mk,(76,65),mk);text(dr,(153,61),'RalX',63,fg)
 text(dr,(76,181),'Your agent signs in.',49,fg);text(dr,(76,244),'You keep the key.',59,'#ad8140' if theme=='light' else '#d3b176','instrument-serif-italic');text(dr,(78,369),'Connect once. Give your agent the job.',18,'#6c6d73' if theme=='light' else '#a7adba','manrope')
 h=hero.copy();h.thumbnail((530,420));im.paste(h,(730+(530-h.width)//2,(480-h.height)//2),h)
 im.quantize(colors=192).save(D/f'readme-banner-{theme}.png',optimize=True)
 # Real source mark plus actual end-card lettering, preserved as a vector wrapper.
 wm=Image.new('RGBA',(480,130));d=ImageDraw.Draw(wm);mm=(mark if theme=='light' else light).copy();mm.thumbnail((96,96));wm.alpha_composite(mm,(9,15));text(d,(130,0),'RalX',108,fg)
 wm=wm.crop(wm.getbbox());wm.save(B/f'ralx-wordmark-{theme}.png')
 b64=base64.b64encode((B/f'ralx-wordmark-{theme}.png').read_bytes()).decode();(B/f'ralx-wordmark-{theme}.svg').write_text(f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {wm.width} {wm.height}"><image width="{wm.width}" height="{wm.height}" href="data:image/png;base64,{b64}"/></svg>')
 # Crisp native flow with generous spacing, matching the HTML diagram.
 im=Image.new('RGB',(1280,480),bg);d=ImageDraw.Draw(im);text(d,(64,39),'The password stays with you.',33,fg)
 labels=[('Your agent','asks to sign in'),('RalX checks','the site + your yes'),('RalX types','in the browser'),('Your agent gets','a signed-in browser')]
 for i,(a,b) in enumerate(labels):
  x=64+i*303;d.rounded_rectangle((x,161,x+245,319),radius=12,outline='#c4ad80' if theme=='light' else '#675f50',width=2)
  text(d,(x+20,201),a,23,fg);text(d,(x+20,244),b,16,'#78746c' if theme=='light' else '#b2b6c1','manrope')
  if i<3:d.line((x+258,239,x+284,239),fill='#b68c49',width=2);d.line((x+278,233,x+284,239,x+278,245),fill='#b68c49',width=2)
 text(d,(64,384),'No password in the agent conversation through RalX.',20,'#9b7337' if theme=='light' else '#d3b176','manrope');im.save(D/f'how-it-works-{theme}.png',optimize=True)
 # PNG within SVG keeps the exact diagram appearance on GitHub and in other readers.
 b64=base64.b64encode((D/f'how-it-works-{theme}.png').read_bytes()).decode();(D/f'how-it-works-{theme}.svg').write_text(f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1280 480"><image width="1280" height="480" href="data:image/png;base64,{b64}"/></svg>')
for name,w,h in [('github-social',1280,640),('site-og',1200,630)]:
 im=Image.new('RGB',(w,h),'#0e1320');d=ImageDraw.Draw(im);mm=light.copy();mm.thumbnail((53,53));im.paste(mm,(65,60),mm);text(d,(134,57),'RalX',56,'#f5f2eb')
 text(d,(65,218),'Your agent',66,'#f5f2eb');text(d,(65,288),'signs in.',66,'#f5f2eb');text(d,(65,378),'You keep the key.',60,'#d3b176','instrument-serif-italic');text(d,(68,530),'Free and open source.',21,'#abb1bf','manrope')
 hh=hero.copy();hh.thumbnail((570,500));im.paste(hh,(w-585,(h-hh.height)//2),hh);im.quantize(colors=192).save(B/(name+'.png'),optimize=True)
shutil.copy(B/'site-og.png',S/'og.png')
base=Image.new('RGBA',(512,512),'#f5f2eb');scale=354/max(mark.size);m=mark.resize((round(mark.width*scale),round(mark.height*scale)),Image.Resampling.LANCZOS);base.alpha_composite(m,((512-m.width)//2,(512-m.height)//2));base.save(S/'icon-512.png');base.resize((192,192),Image.Resampling.LANCZOS).save(S/'icon-192.png');base.resize((180,180),Image.Resampling.LANCZOS).save(S/'apple-touch-icon.png')
for size in [16,32]:base.resize((size,size),Image.Resampling.LANCZOS).save(S/f'favicon-{size}.png')
base.save(S/'favicon.ico',sizes=[(16,16),(32,32),(48,48)])
b64=base64.b64encode((S/'icon-512.png').read_bytes()).decode();svg=f'<svg xmlns="http://www.w3.org/2000/svg" width="512" height="512" viewBox="0 0 512 512"><image width="512" height="512" href="data:image/png;base64,{b64}"/></svg>';(S/'favicon.svg').write_text(svg);(B/'ralx-mark.svg').write_text('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 '+str(mark.width)+' '+str(mark.height)+'"><image width="'+str(mark.width)+'" height="'+str(mark.height)+'" href="data:image/png;base64,'+base64.b64encode((B/'ralx-mark.png').read_bytes()).decode()+'"/></svg>')
# Actual-size favicon checks on light/dark tabs, plus enlarged nearest-neighbor reference.
im=Image.new('RGB',(840,300),'#e8e3d9');d=ImageDraw.Draw(im)
for i,bg in enumerate(['#f5f2eb','#0e1320']):
 d.rectangle((i*420,0,(i+1)*420,300),fill=bg);fg='#0e1320' if i==0 else '#f5f2eb';text(d,(i*420+28,20),'Actual size: 16px / 32px',18,fg)
 for j,size in enumerate([16,32]):
  ic=Image.open(S/f'favicon-{size}.png');im.paste(ic,(i*420+35+j*80,75),ic);im.paste(ic.resize((96,96),Image.Resampling.NEAREST),(i*420+35+j*130,140))
im.save(R/'tmp/landing-proof/favicon-checks.png')
for name in ['github-social','site-og']:
 image=Image.open(B/(name+'.png'));image.thumbnail((400,210));image.save(R/'tmp/landing-proof'/(name+'-small.png'))
print(json.dumps({'hero_alpha':hero.getextrema()[3], 'assets':{str(p.relative_to(R)):p.stat().st_size for p in list(B.glob('*.png'))+list(D.glob('*.png'))}},indent=2))
