module Cli
( Options(..)
, CryptOptions(..)
, KeygenOptions(..)
, Command(..)
, CipherMode(..)
, optionParser
) where

import Data.Char (toLower)
import Options.Applicative

newtype Options = Options
  { cliCommand :: Command
  } deriving Show

data CryptOptions = CryptOptions
  { cryptCipherMode :: CipherMode
  , cryptKeyPath :: FilePath
  , cryptMacKeyPath :: Maybe FilePath
  , cryptOutFile :: Maybe FilePath
  , cryptInFile :: FilePath
  } deriving Show

data KeygenOptions = KeygenOptions
  { keygenPassphrase :: Maybe String
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
  <$> optional (strOption
    ( long "passphrase"
   <> short 'p'
   <> metavar "PASSPHRASE"
   <> help "Optionally derive key from passphrase. If this option is not specified generates cryptographically random key"
    ))
  <*> argument str (metavar "FILENAME")

commonCryptOptions :: Parser CryptOptions
commonCryptOptions = CryptOptions
  <$> option parseCipherMode
    ( long "mode"
   <> short 'm'
   <> metavar "cbc|ofb"
   <> help "Block cipher mode of operation: cbc, ofb"
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
    _     -> Left "mode must be either \"cbc\" or \"ofb\""
