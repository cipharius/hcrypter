module Main where

import qualified Data.ByteString as ByteString
import qualified Cryptography as Crypt
import qualified Cli

import Control.Monad.IO.Class     (liftIO)
import Control.Monad.Trans.Except (ExceptT(..), runExceptT)
import System.Exit                (exitSuccess, die)
import Data.Maybe                 (fromMaybe)
import Crypto.Cipher.AES          (AES128)
import Crypto.Random              (getSystemDRG)

import Types (Error)
import Cli   (Options, Command)


hcrypter :: Options -> IO ()
hcrypter opts = computation >>= resultHandler
  where
    computation = runExceptT . commandHandler . Cli.cliCommand $ opts

    resultHandler :: Either Error () -> IO ()
    resultHandler (Right _) = exitSuccess
    resultHandler (Left err) = die $ "Error: " <> show err

    commandHandler :: Command -> ExceptT Error IO ()
    commandHandler (Cli.Encrypt opt) = do
      key <- ExceptT $ Crypt.readKey (Cli.cryptKeyPath opt)
      cipher <- ExceptT . return $ Crypt.cipher key

      macCipher <-
        case Cli.cryptMacKeyPath opt of
          Nothing         -> ExceptT . return $ Right Nothing
          Just macKeyPath -> do
            macKey <- ExceptT $ Crypt.readKey macKeyPath
            result <- ExceptT . return $ Crypt.cipher macKey
            return $ Just result

      let
        mode   = Cli.cryptCipherMode opt
        inPath = Cli.cryptInFile opt
        outPath = fromMaybe (inPath <> ".out") (Cli.cryptOutFile opt)

      message <- liftIO $ ByteString.readFile inPath
      systemDrg <- liftIO getSystemDRG
      cipherText <- ExceptT . return $ Crypt.encrypt systemDrg mode macCipher cipher message

      liftIO $ ByteString.writeFile outPath cipherText

    commandHandler (Cli.Decrypt opt) = do
      key <- ExceptT $ Crypt.readKey (Cli.cryptKeyPath opt)
      cipher <- ExceptT . return $ Crypt.cipher key

      macCipher <-
        case Cli.cryptMacKeyPath opt of
          Nothing         -> ExceptT . return $ Right Nothing
          Just macKeyPath -> do
            macKey <- ExceptT $ Crypt.readKey macKeyPath
            result <- ExceptT . return $ Crypt.cipher macKey
            return $ Just result

      let
        mode   = Cli.cryptCipherMode opt
        inPath = Cli.cryptInFile opt
        outPath = fromMaybe (inPath <> ".out") (Cli.cryptOutFile opt)

      cipherText <- liftIO $ ByteString.readFile inPath
      message <- ExceptT . return $ Crypt.decrypt mode macCipher cipher cipherText

      liftIO $ ByteString.writeFile outPath message


    commandHandler (Cli.Keygen opt) = undefined

main :: IO ()
main = hcrypter =<< Cli.optionParser
