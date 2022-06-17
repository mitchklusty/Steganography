#steg.py

from PIL import Image
import stepic
from cryptography.fernet import Fernet
from datetime import datetime
import time
import sys
import os

fernet = None

def convert_to_ASCII(data):
	ascii_data = []
	for d in data:
		ascii_data.append(format(ord(d), '08b'))
	return ascii_data

def modify_pixels(pixels, data):
	ascii_data = convert_to_ASCII(data)
	image_data = iter(pixels)

	for i in range(len(ascii_data)):
		pix = [value for value in image_data.__next__()[:3] + image_data.__next__()[:3] + image_data.__next__()[:3]]
		for j in range(0, 8):
			if (ascii_data[i][j] == '0' and pix[j]% 2 != 0):
				pix[j] -= 1

			elif (ascii_data[i][j] == '1' and pix[j] % 2 == 0):
				if(pix[j] != 0):
					pix[j] -= 1
				else:
					pix[j] += 1
 
		if (i == len(ascii_data) - 1):
			if (pix[-1] % 2 == 0):
				if(pix[-1] != 0):
					pix[-1] -= 1
				else:
					pix[-1] += 1
 
		else:
			if (pix[-1] % 2 != 0):
				pix[-1] -= 1
 
		pix = tuple(pix)
		yield pix[0:3]
		yield pix[3:6]
		yield pix[6:9]

def encode_enc(newimg, data):
	w = newimg.size[0]
	(x, y) = (0, 0)

	for pixel in modify_pixels(newimg.getdata(), data):
		newimg.putpixel((x, y), pixel)
		if (x == w - 1):
			x = 0
			y += 1
		else:
			x += 1

def encode_img(img, data):
	image = Image.open(img, 'r')
	newimg = image.copy()
	# encode_enc(newimg, data)
	newimg = stepic.encode(newimg, data)
	new_img_name = "encoded.png"
	newimg.save(new_img_name, str(new_img_name.split(".")[1].upper()))

def decode(img):
	image = Image.open(img, 'r')
	return stepic.decode(image)


def encrypt_file(file):
	global fernet
	with open(file, 'rb') as og_file:
		original = og_file.read()
	try:
		encrypted = fernet.encrypt(original)
	except Exception as e:
		print(f'Failed to encrypt {original}')
		print(e)
	with open(file, 'wb') as encrypted_file:
		encrypted_file.write(encrypted)


def decrypt_file(file):
	global fernet
	with open(file, 'rb') as enc_file:
		encrypted = enc_file.read()
	try:
		decrypted = fernet.decrypt(encrypted)
		print(decrypted)
	except:
		print(f'Failed to decrypt {encrypted}')
		return
	with open(file, 'wb') as dec_file:
		dec_file.write(decrypted)


def encoding(fname, img_fname):
	global fernet
	key_filename = f'key.key'
	key = Fernet.generate_key()
	with open(key_filename, 'w') as keyfile:
		keyfile.write(key.decode('utf-8'))
	fernet = Fernet(key)
	file = open(fname, "rb")
	file_bytes = file.read()
	file.close()
	file_bytes = fernet.encrypt(file_bytes)
	file_bytes = bytes(f"{fname} ", "utf-8") + file_bytes
	encode_img(img_fname, file_bytes)

def decoding(key_filename, img_fname):
	global fernet
	with open(key_filename, 'rb') as filekey:
		key = filekey.read()
	fernet = Fernet(key)
	# fname = "test1.txt"
	message = decode(img_fname)
	# print(message)
	fname = message[:message.index(" ")]
	decoded_bytes = message[message.index(" ")+1:]
	decoded_bytes = bytes(decoded_bytes, "utf-8")
	file = open(fname, "w+")
	file.write(fernet.decrypt(decoded_bytes).decode("utf-8"))
	file.close()
	

def main():
	if "-e" not in sys.argv and "-d" not in sys.argv:
		print(f"Use the command 'python3 {sys.argv[0]}' with flag '-e filename image_filename'")
		print("to encode, or the flag '-d key_filename, image_filename to decode")
		exit(0)
	if "-e" in sys.argv:
		if len(sys.argv) > 4:
			print("Only encode one file at a time.")
			exit(0)
		elif len(sys.argv) < 4:
			print("Enter command with form '-e filename image_filename'")
			exit(0)
		try:
			encoding(sys.argv[2], sys.argv[3])
		except Exception as e:
			print("Failed to encode.")
			print(e)
	elif "-d" in sys.argv:
		if len(sys.argv) > 4:
			print("Only decode one file at a time.")
			exit(0)
		elif len(sys.argv) < 4:
			print("Enter command with form '-d key_filename image_filename'")
			exit(0)
		try:
			decoding(sys.argv[2], sys.argv[3])
		except Exception as e:
			print("Failed to decode.")
			# print(e)


	# encoding("test1.txt", "t.png")
	# decoding('key.key')

	

if __name__ == '__main__' :
	main()