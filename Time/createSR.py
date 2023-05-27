import time

localtime = time.localtime(time.time())
year = str(localtime.tm_year)[-2:]
month = str(localtime.tm_mon)
day = str(localtime.tm_mday)
file_name = f"CTF SR {year}.{month.zfill(2)}.{day.zfill(2)}"
file_extension = "md"
# create file
with open(file_name + "." + file_extension, "w") as f:
    print(f"# {file_name}" + " - Incrd", file=f)