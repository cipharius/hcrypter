module Main where

import qualified Data.ByteString as ByteString
import qualified Cryptography as Crypt
import qualified Cli

import Control.Exception          (IOException, catch)
import Control.Monad.IO.Class     (liftIO)
import Control.Monad.Trans.Except (ExceptT(..), runExceptT)
import System.Exit                (exitSuccess, die)
import Data.Maybe                 (fromMaybe)
import Data.ByteString            (ByteString)
import Crypto.Random              (getSystemDRG, getRandomBytes)

import Types (Error(ErrorFileRead))
import Cli   (Options, Command)
import ByteUtils   (toHex)


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

      let cipherType = Cli.cryptCipherType opt
      cipher <- ExceptT . return $ Crypt.cipherInit cipherType key

      macCipher <-
        case Cli.cryptMacKeyPath opt of
          Nothing         -> ExceptT . return $ Right Nothing
          Just macKeyPath -> do
            macKey <- ExceptT $ Crypt.readKey macKeyPath
            result <- ExceptT . return $ Crypt.cipherInit cipherType macKey
            return $ Just result

      let
        mode   = Cli.cryptCipherMode opt
        inPath = Cli.cryptInFile opt
        outPath = fromMaybe (inPath <> ".out") (Cli.cryptOutFile opt)

      message <- ExceptT $ readFileSafe inPath
      systemDrg <- liftIO getSystemDRG
      cipherText <- ExceptT . return $ Crypt.encrypt systemDrg mode macCipher cipher message

      liftIO $ ByteString.writeFile outPath cipherText


    commandHandler (Cli.Decrypt opt) = do
      key <- ExceptT $ Crypt.readKey (Cli.cryptKeyPath opt)

      let cipherType = Cli.cryptCipherType opt
      cipher <- ExceptT . return $ Crypt.cipherInit cipherType key

      macCipher <-
        case Cli.cryptMacKeyPath opt of
          Nothing         -> ExceptT . return $ Right Nothing
          Just macKeyPath -> do
            macKey <- ExceptT $ Crypt.readKey macKeyPath
            result <- ExceptT . return $ Crypt.cipherInit cipherType macKey
            return $ Just result

      let
        mode   = Cli.cryptCipherMode opt
        inPath = Cli.cryptInFile opt
        outPath = fromMaybe (inPath <> ".out") (Cli.cryptOutFile opt)

      cipherText <- ExceptT $ readFileSafe inPath
      message <- ExceptT . return $ Crypt.decrypt mode macCipher cipher cipherText

      liftIO $ ByteString.writeFile outPath message


    commandHandler (Cli.Keygen opt) = do
      let
        keySize = Cli.keygenSize opt
        outPath = Cli.keygenOutFile opt

      hexKey <- liftIO (toHex <$> getRandomBytes keySize)
      liftIO $ writeFile outPath hexKey

      return ()

readFileSafe :: FilePath -> IO (Either Error ByteString)
readFileSafe path = (Right <$> ByteString.readFile path) `catch` handleExists
  where
    handleExists :: IOException -> IO (Either Error ByteString)
    handleExists _ = return . Left $ ErrorFileRead path

main :: IO ()
main = hcrypter =<< Cli.optionParser
