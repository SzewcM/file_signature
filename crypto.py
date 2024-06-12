from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA3_256
from Crypto.Signature import pss
from Crypto import Random

def main():
    while(1):

        text_file = 'text.txt'

        program_option = input("Podaj dzialanie programu: \n1. Tworzenie kluczy \n2. Sprawdzanie poprawnosci: \n Aby wyjsc, wybierz cokolwiek innego \n Wybierz opcje: ")

        if(program_option == "1"):
            # Tworzenie kluczy
            print("Tworzenie kluczy i podpisu \n")

            key = RSA.generate(2048, Random.new().read)

            private_key = key
            public_key = key.publickey()
            print("RSA keys generated successfully.")

            # Zapis klucza prywatnego
            print("Klucz prywatny:")
            print(private_key.export_key().decode())
            user_private_file_name = input("Podaj nazwe pliku dla klucza prywatnego (musi zawierac rozszerzenie .pem): ")
            f = open(user_private_file_name, 'w')
            f.write(private_key.export_key().decode())
            f.close()

            # Zapis klucza publicznego
            print("\nKlucz publiczny:")
            print(public_key.export_key().decode())
            user_public_file_name = input("Podaj nazwe pliku dla klucza publicznego (musi zawierac rozszerzenie .pem): ")
            w = open(user_public_file_name, 'w')
            w.write(public_key.export_key().decode())
            w.close()

            print("Udalo sie wygenerowac klucze!")

            # Odczyt wiadomości z pliku
            with open(text_file, 'rb') as f:
                message = f.read()
        
            # Oblicz skrót wiadomości (SHA-3)
            hash_obj1 = SHA3_256.new(message)

            print("\nSkrót wiadomości (SHA3):")
            print(hash_obj1.hexdigest())

            # Tworzenie sygnatury
            signature = pkcs1_15.new(private_key).sign(hash_obj1)

            print("Podpisany plik:")
            print(signature)
            
            # Zapis sygnatury do pliku
            user_signature_file = input("Podaj nazwe dla pliku sygnatury (musi zawierac rozszerzenie .sign): ")
            with open(user_signature_file, "wb") as f:
                f.write(signature)
        
        
        elif(program_option == "2"):
            # Sprawdzenie poprawnosci
            print("Sprawdzanie poprawnosci \n")

            # Wybór klucza publicznego
            public_key_name = input('Podaj nazwe klucza publicznego (musi zawierac rozszerzenie .pem): ')
            file = open(public_key_name, "rb")  
            public_key_file = RSA.import_key(file.read())

            # Wybór sygnatury
            user_signature_name = input("Podaj nazwe dla pliku sygnatury (musi zawierac rozszerzenie .sig): ")
            with open(user_signature_name, "rb") as f:
                user_signature_file =  f.read()
            

            # Ponowny odczyt wiadomosci
            with open(text_file, 'rb') as f:
                message = f.read()

            # Weryfikacja podpisu kluczem publicznym
            verification_hash_obj = SHA3_256.new(message)
            
            
            try:
                pkcs1_15.new(public_key_file).verify(verification_hash_obj, user_signature_file)
                print("Podpis jest prawidłowy. \n")
            except (ValueError, TypeError):
                print("Podpis jest nieprawidłowy. \n")
        
        else:
            break
    
if __name__ == "__main__":
    main()
