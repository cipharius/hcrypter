module Types
( Error(..)
) where

import Crypto.Error (CryptoError)

data Error
  = ErrorLessThanBlock Int
  | ErrorCipherFail CryptoError
  | ErrorNonAlignedHex
  | ErrorNotHex
  | ErrorShortCipherText
  | ErrorNoMacKey
  | ErrorMacMismatch
  | ErrorFileRead FilePath

instance Show Error where
  show e =
    case e of
      ErrorLessThanBlock x -> "Input string is shorter than single block (" <> show x <> " bytes)"
      ErrorCipherFail x    -> "Failed to initialize block cipher (" <> show x <> ")"
      ErrorNonAlignedHex   -> "Hexadecimal string is not even length"
      ErrorNotHex          -> "Hexadecimal string must consist of values [0-9, a-f]"
      ErrorShortCipherText -> "Input string is too short to decrypt"
      ErrorNoMacKey        -> "Message has MAC, but no MAC key provided"
      ErrorMacMismatch     -> "Message authentication code mismatch"
      ErrorFileRead x      -> "Could not read from file (" <> x <> ")"
