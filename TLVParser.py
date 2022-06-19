


def hex_to_integer(hex):
	match (hex):
		case 'A':
			return 10
		case 'B':
			return 11
		case 'C':
			return 12
		case 'D':
			return 13
		case 'E':
			return 14
		case 'F':
			return 15
		case _:
			return int(hex)



def get_bit_at(number, index):
	n_shifts = 4 - index
	bit_set = number & (1 << n_shifts) != 0
	return 1 if bit_set else 0



def parse_tlv(s):

	#constructed
	if get_bit_at(hex_to_integer(s[0]), 3):

		#TAG continues on a 2nd byte
		if (get_bit_at(hex_to_integer(s[0]), 4)) and (hex_to_integer(s[1]) == 15):

			#size in chars. Also used for indexing
			size_T = 0
			size_L = 0
			size_V = 0

			#calculate size of TAG
			#s[0], s[1]
			size_T += 2
			#check for third, fourth, etc. bytes
			while get_bit_at(hex_to_integer(s[size_T]), 1):
				size_T += 2
			#s[2], s[3]
			size_T += 2

			#calculate size of LENGTH
			#0XXX'XXXX
			if get_bit_at(hex_to_integer(s[size_T]), 1) == 0:
				size_L = 2
				#in bytes:
				size_V = (16 * hex_to_integer(s[size_T])) + hex_to_integer(s[size_T + 1])
			#1XXX'XXXX...
			else:
				#1000'0001'XXXX'XXXX
				if hex_to_integer(s[size_T]) == 8 and hex_to_integer(s[size_T + 1]) == 1:
					size_L = 4
					#in bytes:
					size_V = (16 * hex_to_integer(s[size_T + 2])) + hex_to_integer(s[size_T + 3])
				#1000'0010'XXXX'XXXX'XXXX'XXXX
				elif hex_to_integer(s[size_T]) == 8 and hex_to_integer(s[size_T + 1]) == 2:
					size_L = 6
					#in bytes:
					size_V = (4096 * hex_to_integer(s[size_T + 2])) + (256 * hex_to_integer(s[size_T + 3])) + (16 * hex_to_integer(s[size_T + 4])) + hex_to_integer(s[size_T + 5])
				else:
					print("Badly formatted length. Can't parse TLV string.")
					quit()
			#bytes to chars:
			size_V *= 2

			#print TAG
			for i in range(size_T):
				print(f'{s[i]}', end = '')
			print()

			#use recursion until all characters of VALUE are parsed
			chars_done = 0
			while chars_done != size_V:
				chars_done += parse_tlv(s[size_T + size_L + chars_done:])

			#if this was a recursive call, return number of parsed characters to caller
			return size_T + size_L + chars_done

		#TAG is only 1 byte long
		else:

			#size in chars. Also used for indexing
			size_T = 2
			size_L = 0
			size_V = 0

			#calculate size of LENGTH
			#0XXX'XXXX
			if get_bit_at(hex_to_integer(s[2]), 1) == 0:
				size_L = 2
				#in bytes:
				size_V = (16 * hex_to_integer(s[2])) + hex_to_integer(s[3])
			#1XXX'XXXX...
			else:
				#1000'0001'XXXX'XXXX
				if hex_to_integer(s[2]) == 8 and hex_to_integer(s[3]) == 1:
					size_L = 4
					#in bytes:
					size_V = (16 * hex_to_integer(s[4])) + hex_to_integer(s[5])
				#1000'0010'XXXX'XXXX'XXXX'XXXX
				elif hex_to_integer(s[2]) == 8 and hex_to_integer(s[3]) == 2:
					size_L = 6
					#in bytes:
					size_V = (4096 * hex_to_integer(s[4])) + (256 * hex_to_integer(s[5])) + (16 * hex_to_integer(s[6])) + hex_to_integer(s[7])
				else:
					print("Badly formatted length. Can't parse TLV string.")
					quit()
			#bytes to chars:
			size_V *= 2

			#print TAG
			print(f'{s[0]}{s[1]}', end = '')
			print()

			#use recursion until all characters of VALUE are parsed
			chars_done = 0
			while chars_done != size_V:
				chars_done += parse_tlv(s[size_T + size_L + chars_done:])

			#if this was a recursive call, return number of parsed characters to caller
			return size_T + size_L + chars_done

	#primitive
	else:

		#TAG continues on a 2nd byte
		if (get_bit_at(hex_to_integer(s[0]), 4)) and (hex_to_integer(s[1]) == 15):

			#size in chars. Also used for indexing
			size_T = 0
			size_L = 0
			size_V = 0

			#calculate size of TAG
			#s[0], s[1]
			size_T += 2
			#check for third, fourth, etc. bytes
			while get_bit_at(hex_to_integer(s[size_T]), 1):
				size_T += 2
			#s[2], s[3]
			size_T += 2

			#calculate size of LENGTH
			#0XXX'XXXX
			if get_bit_at(hex_to_integer(s[size_T]), 1) == 0:
				size_L = 2
				#in bytes:
				size_V = (16 * hex_to_integer(s[size_T])) + hex_to_integer(s[size_T + 1])
			#1XXX'XXXX...
			else:
				#1000'0001'XXXX'XXXX
				if hex_to_integer(s[size_T]) == 8 and hex_to_integer(s[size_T + 1]) == 1:
					size_L = 4
					#in bytes:
					size_V = (16 * hex_to_integer(s[size_T + 2])) + hex_to_integer(s[size_T + 3])
				#1000'0010'XXXX'XXXX'XXXX'XXXX
				elif hex_to_integer(s[size_T]) == 8 and hex_to_integer(s[size_T + 1]) == 2:
					size_L = 6
					#in bytes:
					size_V = (4096 * hex_to_integer(s[size_T + 2])) + (256 * hex_to_integer(s[size_T + 3])) + (16 * hex_to_integer(s[size_T + 4])) + hex_to_integer(s[size_T + 5])
				else:
					print("Badly formatted length. Can't parse TLV string.")
					quit()
			#bytes to chars:
			size_V *= 2

			#print TAG
			for i in range(size_T):
				print(f'{s[i]}', end = '')
			print(f' ', end = '')

			#print VALUE
			for i in range(size_T + size_L, size_T + size_L + size_V):
				print(f'{s[i]}', end = '')
			print()

			#if this was a recursive call, return number of parsed characters to caller
			return size_T + size_L + size_V

		#TAG is only 1 byte long
		else:
	
			#size in chars. Also used for indexing
			size_T = 2
			size_L = 0
			size_V = 0

			#calculate size of LENGTH
			#0XXX'XXXX
			if get_bit_at(hex_to_integer(s[2]), 1) == 0:
				size_L = 2
				#in bytes:
				size_V = (16 * hex_to_integer(s[2])) + hex_to_integer(s[3])
			#1XXX'XXXX...
			else:
				#1000'0001'XXXX'XXXX
				if hex_to_integer(s[2]) == 8 and hex_to_integer(s[3]) == 1:
					size_L = 4
					#in bytes:
					size_V = (16 * hex_to_integer(s[4])) + hex_to_integer(s[5])
				#1000'0010'XXXX'XXXX'XXXX'XXXX
				elif hex_to_integer(s[2]) == 8 and hex_to_integer(s[3]) == 2:
					size_L = 6
					#in bytes:
					size_V = (4096 * hex_to_integer(s[4])) + (256 * hex_to_integer(s[5])) + (16 * hex_to_integer(s[6])) + hex_to_integer(s[7])
				else:
					print("Badly formatted length. Can't parse TLV string.")
					quit()
			#bytes to chars:
			size_V *= 2
			#print("bla" + str(size_V))

			#print TAG
			print(f'{s[0]}{s[1]} ', end = '')
			
			#print VALUE
			for i in range(size_T + size_L, size_T + size_L + size_V):
				print(f'{s[i]}', end = '')
			print()

			#if this was a recursive call, return number of parsed characters to caller
			return size_T + size_L + size_V



input_string = input('Insert the TLV string you want to be parsed: ')
print()

#remove white spaces between bytes
input_string = input_string.replace(" ", "")
#replace all lowercase letter with their uppercase equivalents
input_string = input_string.upper()

parse_tlv(input_string)