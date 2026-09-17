import py7zr
path = "/opt/neurotrace/uploads/imagery.7z"
z = py7zr.SevenZipFile(path, "r")
for info in z.list():
    print(f"{info.uncompressed:12d}  {info.filename}")
z.close()
