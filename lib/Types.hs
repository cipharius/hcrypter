module Types
( Error(..)
) where

import Data.Word (Word8, Word16, Word32)

data Error
  = ErrorLessThanBlock Int
  | ErrorNonAlignedHex
  | ErrorNotHex

instance Show Error where
  show e =
    case e of
      ErrorLessThanBlock x -> "Input string is shorter than single block (" <> show x <> " bytes)"
      ErrorNonAlignedHex   -> "Hexadecimal string is not even length"
      ErrorNotHex          -> "Hexadecimal string must consist of values [0-9, a-f]"
