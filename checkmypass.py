import requests
import hashlib
import sys

# trebuie verificat ce SHA foloseste respectivul api, 
#in cazul nostru foloseste SHA1, 
# https://passwordsgenerator.net/sha1-hash-generator/

def request_api_data(query_char):
	url = 'https://api.pwnedpasswords.com/range/' + query_char # <- asta e SHA1(hash codeul parolei) -> password123(doaR primele 5)
	res = requests.get(url)
	if res.status_code != 200:
		raise RuntimeError(f'Error fetching: {res.status_code}, check the api and try again')
	return res

def get_password_leaks_count(hashes, hash_to_check):
	hashes = (line.split(':') for line in hashes.text.splitlines())
	for h, count in hashes:
		if h == hash_to_check:			# <- functia care verifica daca Hash-urile sunt compatibile
			return count
	return 0



def pwned_api_check(password):
	# verifica daca exixta in raspunsul API-ului
	sha1password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
	first5_char, tail = sha1password[:5], sha1password[5:]	#<- asa iei primele 5 caractere si ultimele 5 dintr-un string
	response = request_api_data(first5_char)
	print(first5_char, tail)
	return get_password_leaks_count(response, tail)

def main(args):
	for password in args:
		count = pwned_api_check(password)
		if count:
			print(f'{password} was found {count} times...maybe you should change🤓')
		else :
			print(f'{password} was not found.Beast🥳')
	return 'done'

if __name__ == '__main__':
	sys.exit(main(sys.argv[1:]))


#API -> Aplication Programming Interface
