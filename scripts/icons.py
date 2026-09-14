"""Rasterize the project's simple checkmark icon without external dependencies."""
import struct, zlib
from pathlib import Path

def icon(size):
    rows = bytearray()
    def distance(x,y,a,b):
        dx,dy=b[0]-a[0],b[1]-a[1]
        t=max(0,min(1,((x-a[0])*dx+(y-a[1])*dy)/(dx*dx+dy*dy)))
        return ((x-a[0]-t*dx)**2+(y-a[1]-t*dy)**2)**.5
    for y in range(size):
        rows.append(0)
        for x in range(size):
            u,v=x*192/size,y*192/size
            color=(3,15,36)
            if (u-96)**2+(v-96)**2<62**2: color=(18,97,140)
            if min(distance(u,v,(58,98),(83,123)),distance(u,v,(83,123),(135,67)))<7.5: color=(156,240,200)
            rows.extend(color)
    def chunk(name,data):return struct.pack('>I',len(data))+name+data+struct.pack('>I',zlib.crc32(name+data))
    return b'\x89PNG\r\n\x1a\n'+chunk(b'IHDR',struct.pack('>IIBBBBB',size,size,8,2,0,0,0))+chunk(b'IDAT',zlib.compress(rows))+chunk(b'IEND',b'')
for size in (192,512): Path(f'attendpro/student/icon-{size}.png').write_bytes(icon(size))
for density,size in [('mdpi',48),('hdpi',72),('xhdpi',96),('xxhdpi',144),('xxxhdpi',192)]:
    folder=Path(f'shell/android/app/src/main/res/mipmap-{density}')
    for name in ('ic_launcher','ic_launcher_round','ic_launcher_foreground'):
        (folder/f'{name}.png').write_bytes(icon(size))
