ports = []

filepath = 'ports.txt'
with open(filepath) as fp:
   line = fp.readline()
   cnt = 1
   while line:
       s = line.split()
       ports.append(int(s[0]))
       line = fp.readline()
       cnt += 1

print(ports)
