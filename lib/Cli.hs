module Cli
( Options(..)
, CryptOptions(..)
, KeygenOptions(..)
, Command(..)
, CipherMode(..)
, CipherType(..)
, optionParser
) where

import Data.Char (toLower)
import Options.Applicative

newtype Options = Options
  { cliCommand :: Command
  } deriving Show

data CryptOptions = CryptOptions
  { cryptCipherMode :: CipherMode
  , cryptCipherType :: CipherType
  , cryptKeyPath :: FilePath
  , cryptMacKeyPath :: Maybe FilePath
  , cryptOutFile :: Maybe FilePath
  , cryptInFile :: FilePath
  } deriving Show

data KeygenOptions = KeygenOptions
  { keygenSize :: Int
  , keygenOutFile :: FilePath
  } deriving Show

data Command
  = Encrypt CryptOptions
  | Decrypt CryptOptions
  | Keygen KeygenOptions
  deriving Show

data CipherMode
  = CipherModeCBC
  | CipherModeOFB
  deriving Show

data CipherType
  = CipherAES128
  | CipherAES192
  | CipherAES256
  deriving Show

optionParser :: IO Options
optionParser = customExecParser p opts
  where
    opts = info (Cli.options <**> helper)
      ( fullDesc
     <> header "hcrypter - cryptography tool for first assignment" )
    p = prefs showHelpOnEmpty

options :: Parser Options
options = Options
  <$> hsubparser
    ( command "encrypt" (info (Encrypt <$> commonCryptOptions) ( progDesc "Encrypt input file(s)" ))
   <> command "decrypt" (info (Decrypt <$> commonCryptOptions) ( progDesc "Decrypt input file(s)" ))
   <> command "keygen"  (info (Keygen  <$> keygenOptions)      ( progDesc "Generate a key file" ))
    )

keygenOptions :: Parser KeygenOptions
keygenOptions = KeygenOptions
  <$> option auto
    ( long "size"
   <> short 's'
   <> metavar "NUMBER"
   <> help "Size of random key in bytes"
    )
  <*> argument str (metavar "FILENAME")

commonCryptOptions :: Parser CryptOptions
commonCryptOptions = CryptOptions
  <$> option parseCipherMode
    ( long "mode"
   <> short 'm'
   <> metavar "CBC|OFB"
   <> help "Block cipher mode of operation: cbc, ofb"
    )
  <*> option parseCipherType
    ( long "cipher"
   <> short 'c'
   <> metavar "AES128|AES192|AES256"
   <> value CipherAES128
   <> help "Block cipher type: AES128, AES192, AES256. Default: AES128"
    )
  <*> strOption
    ( long "key"
   <> short 'k'
   <> metavar "FILENAME"
   <> help "Path to a key file to use for encryption/decryption"
    )
  <*> optional (strOption
    ( long "mac-key"
   <> short 'a'
   <> metavar "FILENAME"
   <> help "Path to a key file to use for MAC calculation and message authentication"
    ))
  <*> optional (strOption
    ( long "out"
   <> short 'o'
   <> metavar "FILENAME"
   <> help "Output file name. Default: [INPUT].out"
    ))
  <*> argument str (metavar "INPUT")

parseCipherMode :: ReadM CipherMode
parseCipherMode = eitherReader $ \s ->
  case toLower <$> s of
    "cbc" -> Right CipherModeCBC
    "ofb" -> Right CipherModeOFB
    _     -> Left "mode must be either \"CBC\" or \"OFB\""

parseCipherType :: ReadM CipherType
parseCipherType = eitherReader $ \s ->
  case toLower <$> s of
    "aes128" -> Right CipherAES128
    "aes192" -> Right CipherAES192
    "aes256" -> Right CipherAES256
    _        -> Left "mode must be one of \"AES128\", \"AES192\" or \"AES256\""
