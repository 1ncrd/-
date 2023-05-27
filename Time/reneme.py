import os

files = os.listdir("./")

for f in files:
    if f.startswith("CTF Study Record"):
        new_name = f.replace("Study Record", "SR").replace(" -Incrd", "")
        os.rename(f, new_name)