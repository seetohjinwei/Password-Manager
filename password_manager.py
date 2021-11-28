'''
Built by See Toh Jin Wei

*** DISCLAIMER ***
DO NOT use for storing any important passwords/accounts/information.
This is just a fun side project, NOT intended to be secure or used to store any information.
'''

import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from dataclasses import dataclass
import json
import os.path
from typing import Union


# Outputs
ERROR_ALR_EXISTS: str = "ERROR: Account already exists."
ERROR_INVALID_COMMAND: str = "ERROR: Invalid command. Try again."
ERROR_NO_ACCOUNTS: str = "Error: No accounts."
ERROR_NOT_FOUND: str = "ERROR: Account not found."

INPUT_ACCOUNT: str = "Input Account/Site:"
INPUT_MASTER: str = "Input Master Key:"
INPUT_PASSWORD: str = "Input Password:"
INPUT_USERNAME: str = "Input Username:"

MISC_DISCLAIMER_UNSAFE: str = "*** DISCLAIMER ***\nThis program has NO GURANTEE of being secure.\nDO NOT save any important passwords or information with this!\n"
MISC_DISCLAIMER_SAFE_EXIT: str = "*** DISCLAIMER ***\nProgram has NO autosave.\nMust exit with 0 to save modifications.\n"
MISC_COMMANDS: str = "--- COMMANDS ---\n1 -- View all Accounts\n2 -- Check Account\n3 -- Add Account\n4 -- Update Account\n5 -- Remove Account\n9 -- Commands\n0 -- Exit"
MISC_PRINT_FORMAT: str = "Site := Username Password"

SUCCESS_DONE: str = "Done."
SUCCESS_EXITING: str = "Exiting..."


class Hash:
    '''Handles encryption and decryption of password.'''
    @staticmethod
    def encode(password: str, key: bytes) -> tuple[str, str]:
        '''Returns a tuple of iv and hashed_password.'''
        cipher = AES.new(key, AES.MODE_CBC)
        ct_bytes = cipher.encrypt(pad(password.encode("utf-8"), AES.block_size))
        iv = base64.b64encode(cipher.iv).decode("utf-8")
        ct = base64.b64encode(ct_bytes).decode("utf-8")
        return (iv, ct)
    
    @staticmethod
    def decode(iv: str, hashed_password: str, key: bytes) -> str:
        '''Returns decoded password.'''
        iv = base64.b64decode(iv)
        ct = base64.b64decode(hashed_password)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        pt = unpad(cipher.decrypt(ct), AES.block_size).decode("utf-8")
        return pt
    
    @staticmethod
    def decode_with_quotes(iv: str, hashed_password: str, key: bytes) -> str:
        '''Adds nice air quotes.'''
        password: str = Hash.decode(iv, hashed_password, key)
        return f"\"{password}\""


@dataclass
class Account:
    '''Dataclass'''
    site: str
    username: str
    iv: str
    hashed_password: str
    
    def __str__(self) -> str:
        # not responsible for printing out password
        return f"{self.site} := \"{self.username}\""


class Passwords:
    '''Handles all the accounts and master key.'''
    def __init__(self, master: bytes, data: dict[str, dict[str, str]]) -> None:
        '''Prepares data.'''
        self.accounts: dict[str, Account] = {
            site: Account(site, d["un"], d["iv"], d["pw"])
            for site, d in data.items()
        }
        self.master: bytes = master
    
    def list_all(self) -> list[Account]:
        '''Returns a list of all accounts.'''
        return self.accounts.values()
    
    def check(self, account: str) -> Union[bool, str]:
        '''Returns a single account's data.'''
        if account not in self.accounts:
            return False
        entry = self.accounts[account]
        return f"{entry} {Hash.decode_with_quotes(entry.iv, entry.hashed_password, self.master)}"
    
    def force_change(self, account: str, username: str, password: str) -> None:
        '''Handles updating of data.'''
        iv, hashed_password = Hash.encode(password, self.master)
        self.accounts[account] = Account(account, username, iv, hashed_password)
    
    def add(self, account: str, username: str, password: str) -> bool:
        '''Checks eligiblity of adding account and passes onto force_change, if possible.'''
        if account in self.accounts:
            return False
        self.force_change(account, username, password)
        return True
    
    def remove(self, account: str) -> bool:
        '''Checks eligiblity of removing account and removes account, if possible.'''
        if account not in self.accounts:
            return False
        self.accounts.pop(account)
        return True
    
    def update(self, account: str, username: str, password: str) -> bool:
        '''Checks eligiblity of updating account and passes onto force_change, if possible.'''
        if account not in self.accounts:
            return False
        self.force_change(account, username, password)
        return True

    def to_json_dict(self) -> dict[str, dict[str, str]]:
        '''Returns a JSON-able dictionary of account data.'''
        return {
            account.site: {"un": account.username, "iv": account.iv, "pw": account.hashed_password}
            for account in self.accounts.values()
        }


def options(option: int, passwords: Passwords, master: bytes) -> bool:
    '''Handles user input.'''
    if option == 1:
        # print all accounts
        accounts: list[Account] = passwords.list_all()
        print(MISC_PRINT_FORMAT)
        if not accounts:
            print(ERROR_NO_ACCOUNTS)
        else:
            for account in accounts:
                print(f"{account} {Hash.decode_with_quotes(account.iv, account.hashed_password, master)}")
    
    elif option == 2:
        # print selected account
        print(INPUT_ACCOUNT)
        account = input()
        output: Union[bool, str] = passwords.check(account)
        if output:
            print(output)
        else:
            print(ERROR_NOT_FOUND)
    
    elif option == 3:
        # add account
        print(INPUT_ACCOUNT)
        account: str = input()
        print(INPUT_USERNAME)
        username: str = input()
        print(INPUT_PASSWORD)
        password: str = input()
        if not passwords.add(account, username, password):
            print(ERROR_ALR_EXISTS)
        else:
            print(SUCCESS_DONE)
    
    elif option == 4:
        # update account
        print(INPUT_ACCOUNT)
        account: str = input()
        print(INPUT_USERNAME)
        username: str = input()
        print(INPUT_PASSWORD)
        password: str = input()
        if not passwords.update(account, username, password):
            print(ERROR_ALR_EXISTS)
        else:
            print(SUCCESS_DONE)
    
    elif option == 5:
        # remove account
        print(INPUT_ACCOUNT)
        account: str = input()
        if not passwords.remove(account):
            print(ERROR_NOT_FOUND)
        else:
            print(SUCCESS_DONE)
    
    elif option == 9:
        # prints available commands
        print(MISC_COMMANDS)
    
    elif option == 0:
        # terminate program
        print(SUCCESS_EXITING)
        json_accounts = passwords.to_json_dict()
        json.dump(json_accounts, open("passwords.json", "w"))
        exit()
    else:
        # invalid command
        return False
    return True


def main() -> None:
    '''Main Function'''
    data = json.load(open("passwords.json"))
    
    print(MISC_DISCLAIMER_UNSAFE)
    print(MISC_DISCLAIMER_SAFE_EXIT)
    print(INPUT_MASTER)
    master: bytes = pad(input().encode("utf-8"), 32)
    passwords: Passwords = Passwords(master, data)
    print(MISC_COMMANDS)
    
    while True:
        option: str = input()
        try:
            option = int(option)
        except ValueError:
            pass
        if not options(option, passwords, master):
            print(ERROR_INVALID_COMMAND)


def passwords_file() -> None:
    '''Creates passwords.json if it does not exist.'''
    if not os.path.isfile("passwords.json"):
        with open("passwords.json", "x") as f:
            f.write("{}")


if __name__ == "__main__":
    passwords_file()
    main()
