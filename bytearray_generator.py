# importing sys to pass badchars to not print.
import sys

goodchars = 0
badchars = "\\x00"
print("bytearray:\n")
for x in range(1, 256):
	# :02 says to print x as 2 digits in hex
	if "{:02x}".format(x) not in sys.argv:
  		print("\\x" + "{:02x}".format(x), end='')
  		goodchars += 1
	else:
  		badchars += "\\x"+"{:02x}".format(x)
print()
print("\nbadchars not printed: " + (str) (x - goodchars + 1 ))
print("\nbadchars: " + badchars)
