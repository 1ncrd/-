import time

localtime = time.localtime(time.time())
year = str(localtime.tm_year)[-2:]
month = str(localtime.tm_mon)
day = str(localtime.tm_mday)
file_name = f"CTF SR {year}.{month}.{day}.md"

# create file
with open(file_name, "w") as f:
    print(f"# {file_name}", file=f)