{-# LANGUAGE DeriveDataTypeable #-}

module Main where

import System.Console.CmdArgs
import Cryptography

data Sample = Sample { hello :: String }
              deriving (Show, Data, Typeable)

main :: IO ()
main = print =<< cmdArgs sample
