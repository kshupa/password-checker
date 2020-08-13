import requests
import hashlib
import sys

def get_api_data(hash_chars):
    url = 'https://api.pwnedpasswords.com/range/' + hash_chars
    result = requests.get(url)
    if result.status_code != 200:
        raise RuntimeError(f'Error fetching: {result.status_code}')
    return result


def get_password_leak_count(hashes, hash_to_check):
    hashes = (line.split(':') for line in hashes.text.splitlines())
    for h, count in hashes:
        if h == hash_to_check:
            return count
    return 0


def pwned_api_check(password):
    sha1password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    first5_char, tail = sha1password[:5], sha1password[5:]
    response = get_api_data(first5_char)
    return get_password_leak_count(response, tail)


def main(args):
    for password in args:
        count = pwned_api_check(password)
        if count:
            print(f'{password} has been found {count} times. You should change your password')
        else:
            print(f'{password} was not leaked and is safe to use for now!')
    return 'Done!'


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))