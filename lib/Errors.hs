module Errors (
  Error(..)
) where

data Error
  = Error_ShortInput
  | Error_NonAlignedHex
  deriving Show
