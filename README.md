# Applied cryptography - first assignment

Author:                 Valts Liepiņš (vl19032)
Programming language:   Haskell
Cryptography library:   cryptonite
Block cipher algorithm: AES
Chosen feedback mode:   OFB

## Usage instructions

The application is provided as a single, statically linked, Linux compatible binary, so it is expected to work on any Linux distribution as is.

The application has three modes of operation: encryption, decryption and key generation.
Executing the binary without arguments or with a `--help` flag, will list these modes.
Each mode has seperate short help description, when executed without arguments or with a `--help` flag.

### Mode: Key generation

Command: `hcrypter keygen (-s|--size NUMBER) FILENAME`

This mode acts as a simple, cryptographically random key generation utility.
The desired key size can be specified in bytes with the `size` option.

Examples of key generation for the three supported block ciphers:

* `hcrypter keygen -s 16 example-AES128.key`
* `hcrypter keygen -s 24 example-AES192.key`
* `hcrypter keygen -s 32 example-AES256.key`

### Mode: Encryption

Command: `hcrypter encrypt (-m|--mode CBC|OFB) [-c|--cipher AES128|AES192|AES256] (-k|--key FILENAME) [-a|--mac-key FILENAME] [-o|--out FILENAME] INPUT`

This mode encrypts message provided in the file `INPUT` and writes the encrypted message to a file named after input file, with `.out` appended, or to the file specified with `out` option.
The required arguments are the `mode`, which is one of the block cipher modes of operation (CBC or OFB), and `key` which is the key file to use for encryption.
Key file can be generated with the `keygen` command.
As per assignment requirement, CBC mode uses a constant initialization vector in order to produce cipher text that has same length as the input text, so same message will always produce same resulting cipher text.
OFB block cipher mode will use random initialization vector, so encrypting same message with same key will produce different output file on each encryption.
OFB block cipher mode also accepts optional `mac-key` argument with a key file to use for message authentication code calculation.
This tool uses AES for encryption/decryption defaulting to AES128 for ease of testing.
Stronger AES versions can be chosen using `cipher` argument.

Usage examples:

* `hcrypter encrypt -m cbc -k example-AES128.key secret-message.txt`
* `hcrypter encrypt -m cbc -k example-AES128.key -o encrypted-message.bin secret-message.txt`
* `hcrypter encrypt -m ofb -k example-AES128.key secret-message.txt`
* `hcrypter encrypt -m ofb -a MAC-AES128.key -k example-AES128.key secret-message.txt`
* `hcrypter encrypt -m ofb -c aes256 -k example-AES256.key secret-message.txt`

### Mode: Decryption

Command: `hcrypter decrypt (-m|--mode CBC|OFB) [-c|--cipher AES128|AES192|AES256] (-k|--key FILENAME) [-a|--mac-key FILENAME] [-o|--out FILENAME] INPUT`

This mode decrypts message in file `INPUT` encrypted by the `encrypt` mode and writes the decrypted message in file named after input file, with `.out` appended, or to the file specified with `out` option.
The `decrypt` command is symmetric to the `encrypt` command, so in order to succesfully decrypt a message, following arguments must match the ones used to encrypt message: `mode`, `cipher`, `key`, `mac-key`.
In case of OFB cipher block mode, if the encrypted message contains MAC and the MAC key is omitted or if recalculated MAC mismatches, the program will refuse to decrypt with an error.

Usage examples:

* `hcrypter decrypt -m cbc -k example-AES128.key secret-message.txt.out`
* `hcrypter decrypt -m cbc -k example-AES128.key -o decrypted-message.txt encrypted-message.bin`
* `hcrypter decrypt -m ofb -k example-AES128.key secret-message.txt.out`
* `hcrypter decrypt -m ofb -a MAC-AES128.key -k example-AES128.key secret-message.txt.out`
* `hcrypter decrypt -m ofb -c aes256 -k example-AES256.key secret-message.txt.out`

## Binary format of the encrypted messages

For CBC block cipher mode, the encrypted message is written to file as is.
Tail block misalignment is corrected using cipher stealing technique.

For OFB block cipher mode, the encrypted message is prepended with a single byte signifying the size of the MAC, MAC itself and 16 bytes long initalization vector.
If the message was encrypted without specifying a MAC key, the first byte will contain value `0x0`, next 16 bytes will contain initialization vector and rest of the bytes will contain the encrypted message.
Otherwise, first byte will describe length of MAC in bytes.
Since this tool will use same block cipher(AES) to calculate the OMAC, MAC length will always be 16 bytes.

Byte schematic:

[ MAC LENGTH : 1 byte ][ MAC : (MAC LENGTH) bytes ][ IV : 16 bytes ][ CIPHER TEXT : > 16 bytes ]

## Source files

* `./app/Main.hs` : Application entry point, contains main IO logic
* `./lib/Cryptography.hs` : Cryptography functions for encryption, decryption, CBC and OFB block modes and MAC generation
* `./lib/Cli.hs`  : User interface definition, using optparse-applicative library
* `./lib/ByteUtils.hs` : Miscelaneous functions for byte strings
* `./lib/Types.hs` : Error data type definition
