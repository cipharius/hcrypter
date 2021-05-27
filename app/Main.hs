module Main where

import Data.Char (toLower)

import qualified Cryptography as Crypto
import Options.Applicative

data Options = Options
  { optCommand :: Command
  } deriving Show

data CryptOptions = CryptOptions
  { cryptCipherMode :: CipherMode
  , cryptKeyPath :: FilePath
  , cryptMacKeyPath :: FilePath
  , cryptKeyFormat :: KeyFormat
  , cryptInFile :: FilePath
  } deriving Show

data KeygenOptions = KeygenOptions
  { keygenPassphrase :: Maybe String
  , keygenKeyFormat :: KeyFormat
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

data KeyFormat
  = KeyFormatHex
  | KeyFormatBin
  deriving Show

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
  <*> keyFormatOption
  <*> argument str (metavar "FILENAME")

commonCryptOptions :: Parser CryptOptions
commonCryptOptions = CryptOptions
  <$> option parseCipherMode
    ( long "mode"
   <> short 'm'
   <> metavar "{cbc, ofb}"
   <> help "Block cipher mode of operation: cbc, ofb"
    )
  <*> strOption
    ( long "key"
   <> short 'k'
   <> metavar "FILENAME"
   <> help "Path to a key file to use for encryption/decryption"
    )
  <*> strOption
    ( long "mac-key"
   <> short 'a'
   <> metavar "FILENAME"
   <> help "Path to a key file to use for MAC calculation and message authentification"
    )
  <*> keyFormatOption
  <*> argument str (metavar "FILENAME")

keyFormatOption :: Parser KeyFormat
keyFormatOption = option parseKeyFormat
  ( long "key-format"
 <> short 'f'
 <> metavar "{hex, bin}"
 <> value KeyFormatHex
 <> help "Key file format: hex, bin. Default value: hex"
  )

parseCipherMode :: ReadM CipherMode
parseCipherMode = eitherReader $ \s ->
  case toLower <$> s of
    "cbc" -> Right CipherModeCBC
    "ofb" -> Right CipherModeOFB
    _     -> Left "mode must be either \"cbc\" or \"ofb\""

parseKeyFormat :: ReadM KeyFormat
parseKeyFormat = eitherReader $ \s ->
  case toLower <$> s of
    "hex" -> Right KeyFormatHex
    "bin" -> Right KeyFormatBin
    _     -> Left "mode must be either \"hex\" or \"bin\""

hcrypter :: Options -> IO ()
hcrypter = print

main :: IO ()
main = hcrypter =<< customExecParser p opts
  where
    opts = info (options <**> helper)
      ( fullDesc
     <> header "hcrypter - cryptography tool for first assignment" )
    p = prefs showHelpOnEmpty
