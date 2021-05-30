{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ExistentialQuantification #-}

module Cryptography
( readKey
, cipherInit
, encrypt
, decrypt
) where

import Control.Exception     (IOException, catch)
import Crypto.Cipher.Types   (Cipher, BlockCipher)
import Crypto.Error          (CryptoFailable)
import Crypto.Cipher.AES     (AES128, AES192, AES256)
import Crypto.Random         (SystemDRG, randomBytesGenerate)
import Data.ByteArray        (xor)
import Data.ByteString       (ByteString)
import Data.Bits             (shift, zeroBits)
import Data.Bits.ByteString  ()
import Data.Char             (toLower, isSpace)
import Cli                   (CipherMode(..), CipherType(..))

import qualified Crypto.Cipher.Types as CC
import qualified Crypto.Error        as CE
import qualified Data.ByteArray      as BA

import Types
import ByteUtils

data AbstractCipher = forall c. BlockCipher c => AbstractCipher c

instance Cipher AbstractCipher where
  cipherName (AbstractCipher cipher) = CC.cipherName cipher
  cipherKeySize (AbstractCipher cipher) = CC.cipherKeySize cipher
  cipherInit = undefined

instance BlockCipher AbstractCipher where
  blockSize (AbstractCipher cipher) = CC.blockSize cipher
  ecbEncrypt (AbstractCipher cipher) = CC.ecbEncrypt cipher
  ecbDecrypt (AbstractCipher cipher) = CC.ecbDecrypt cipher

constCbcIv :: ByteString
constCbcIv = fromHexUnsafe "0ac701bf360252f019e4855d4e0e67c9"

readKey :: FilePath -> IO (Either Error ByteString)
readKey path = (fmap (fromHex . filter nonWhiteSpace . fmap toLower) . readFile $ path) `catch` handleExists
  where
    nonWhiteSpace char = not $ isSpace char

    handleExists :: IOException -> IO (Either Error ByteString)
    handleExists _ = return . Left $ ErrorFileRead path

cipherInit :: CipherType -> ByteString -> Either Error AbstractCipher
cipherInit cipherType key =
  case abstractCipherInit of
    CE.CryptoPassed ciph -> Right ciph
    CE.CryptoFailed err  -> Left $ ErrorCipherFail err
  where
    abstractCipherInit =
      case cipherType of
        CipherAES128 -> AbstractCipher <$> (CC.cipherInit key :: CryptoFailable AES128)
        CipherAES192 -> AbstractCipher <$> (CC.cipherInit key :: CryptoFailable AES192)
        CipherAES256 -> AbstractCipher <$> (CC.cipherInit key :: CryptoFailable AES256)

encrypt :: (BlockCipher cMac, BlockCipher c) =>
           SystemDRG -> CipherMode -> Maybe cMac -> c -> ByteString -> Either Error ByteString
encrypt drg mode maybeCipherMac cipher plainText = do
  let
    macMetaByte = maybe zeroBits (BA.singleton . toEnum . CC.blockSize) maybeCipherMac

  mac <- case maybeCipherMac of
    Just cipherMac -> omac cipherMac plainText
    Nothing        -> return ""

  case mode of
    CipherModeCBC ->
      ((macMetaByte <> mac) <>) <$> cbcEncrypt cipher plainText
    CipherModeOFB ->
      ((macMetaByte <> (iv `xor` mac) <> iv) <>) <$> ofbMode cipher iv plainText
      where (iv, _) = randomBytesGenerate (CC.blockSize cipher) drg

decrypt :: (BlockCipher cMac, BlockCipher c) =>
           CipherMode -> Maybe cMac -> c -> ByteString -> Either Error ByteString
decrypt mode maybeCipherMac cipher cipherText = do
  (macMetaByte, cipherMessage) <-
    case BA.uncons cipherText of
      Just (byte, rest) -> Right (fromEnum byte, rest)
      Nothing           -> Left ErrorShortCipherText

  let (xoredMacPart, ivCipherTextPart) = BA.splitAt macMetaByte cipherMessage

  (macPart, plainText) <-
    case mode of
      CipherModeCBC -> (,) xoredMacPart <$> cbcDecrypt cipher ivCipherTextPart
      CipherModeOFB -> (,) (iv `xor` xoredMacPart) <$> ofbMode cipher iv cipherTextPart
        where (iv, cipherTextPart) = BA.splitAt (CC.blockSize cipher) ivCipherTextPart

  let macPartLength = BA.length macPart
  case maybeCipherMac of
    Nothing
      | macMetaByte /= 0 -> Left ErrorNoMacKey
      | otherwise        -> return plainText
    Just cipherMac
      | macMetaByte /= CC.blockSize cipherMac -> Left ErrorMacMismatch
      | macPartLength < macMetaByte           -> Left ErrorShortCipherText
      | otherwise                             -> do
        macControl <- omac cipherMac plainText

        if macPart == macControl
          then return plainText
          else Left ErrorMacMismatch


cbcEncrypt :: BlockCipher c => c -> ByteString -> Either Error ByteString
cbcEncrypt cipher plainText
  | isBlockAligned      = Right $ encrypt' constCbcIv plainText
  | fullBlockCount > 1  = Right $ ciphertext <> ciphertextTail
  | fullBlockCount == 1 = Right $ cipherSteal' constCbcIv tailPart
  | otherwise           = Left $ ErrorLessThanBlock blockSize
  where
    ciphertext = encrypt' constCbcIv alignedPart
    ciphertextTail = cipherSteal' ciphertextLastBlock tailPart
    ciphertextLastBlock = BA.drop (BA.length ciphertext - blockSize) ciphertext

    isBlockAligned = (inputLength `mod` blockSize) == 0
    fullBlockCount = inputLength `div` blockSize
    (alignedPart, tailPart) = BA.splitAt ((fullBlockCount - 1) * blockSize) plainText

    blockSize = CC.blockSize cipher
    inputLength = BA.length plainText

    encrypt' :: ByteString -> ByteString -> ByteString
    encrypt' _ ""  = ""
    encrypt' prev txt = cipherBlock <> encrypt' cipherBlock rest
      where
        cipherBlock = CC.ecbEncrypt cipher (prev `xor` block)
        (block, rest) = BA.splitAt blockSize txt

    cipherSteal' :: ByteString -> ByteString -> ByteString
    cipherSteal' prev txt = ciphertextB <> BA.take partialLen ciphertextA
      where
        ciphertextA = CC.ecbEncrypt cipher (prev `xor` block)
        ciphertextB = CC.ecbEncrypt cipher (ciphertextA `xor` partialZeropad)
        partialZeropad = partial <> BA.zero (blockSize - partialLen)

        partialLen = BA.length partial
        (block, partial) = BA.splitAt blockSize txt

cbcDecrypt :: BlockCipher c => c -> ByteString -> Either Error ByteString
cbcDecrypt cipher ciphertext
  | isBlockAligned      = Right $ decrypt' constCbcIv ciphertext
  | fullBlockCount > 1  = Right $ decrypt' constCbcIv alignedPart <> stolenTail
  | fullBlockCount == 1 = Right $ cipherSteal' constCbcIv tailPart
  | otherwise           = Left $ ErrorLessThanBlock blockSize
  where
    stolenTail = cipherSteal' lastAlignedBlock tailPart
    lastAlignedBlock = BA.drop (BA.length alignedPart - blockSize) alignedPart

    isBlockAligned = (inputLength `mod` blockSize) == 0
    fullBlockCount = inputLength `div` blockSize
    (alignedPart, tailPart) = BA.splitAt ((fullBlockCount - 1) * blockSize) ciphertext

    blockSize = CC.blockSize cipher
    inputLength = BA.length ciphertext

    decrypt' :: ByteString -> ByteString -> ByteString
    decrypt' _ "" = ""
    decrypt' prev txt = prev `xor` (CC.ecbDecrypt cipher block) <> decrypt' block rest
      where (block, rest) = BA.splitAt blockSize txt

    cipherSteal' :: ByteString -> ByteString -> ByteString
    cipherSteal' prev txt = (prev `xor` ciphertextB) <> BA.take partialLen (pseudoBlock `xor` ciphertextA)
      where
        ciphertextA = CC.ecbDecrypt cipher block
        ciphertextB = CC.ecbDecrypt cipher pseudoBlock
        pseudoBlock = partial <> BA.drop partialLen ciphertextA

        partialLen = BA.length partial
        (block, partial) = BA.splitAt blockSize txt

ofbMode :: BlockCipher c => c -> ByteString -> ByteString -> Either Error ByteString
ofbMode cipher iv txt
  | fullBlockCount == 0 = Left $ ErrorLessThanBlock blockSize
  | otherwise           = Right $ chain' iv txt
  where
    blockSize = CC.blockSize cipher
    inputLength = BA.length txt
    fullBlockCount = inputLength `div` blockSize

    chain' :: ByteString -> ByteString -> ByteString
    chain' _ "" = ""
    chain' prev bstr = (cipherBlock `xor` block) <> chain' cipherBlock rest
      where
        (block, rest) = BA.splitAt blockSize bstr
        cipherBlock = CC.ecbEncrypt cipher prev

omac :: BlockCipher c => c -> ByteString -> Either Error ByteString
omac cipher msg
  | BA.length msg >= blockSize = Right omacTag
  | otherwise                  = Left $ ErrorLessThanBlock blockSize
  where
    omacTag = CC.ecbEncrypt cipher $ cipherTail msgTail `xor` lastCipherBlock

    cipherTail :: ByteString -> ByteString
    cipherTail txt
      | BA.null txt = BA.zero blockSize
      | otherwise = cipherTail rest `xor` CC.ecbEncrypt cipher block
      where
        (rest, block) = BA.splitAt (BA.length txt - blockSize) txt

    lastCipherBlock :: ByteString
    lastCipherBlock
      | BA.length lastBlock == blockSize = k1 `xor` lastBlock
      | otherwise                        = k2 `xor` normalize lastBlock

    k0 :: ByteString
    k0 = CC.ecbEncrypt cipher (BA.zero blockSize)

    k1 :: ByteString
    k1 = if msb k0
      then (k0 `shift` 1) `xor` c
      else k0 `shift` 1

    k2 :: ByteString
    k2 = if msb k1
      then (k1 `shift` 1) `xor` c
      else k1 `shift` 1

    c :: ByteString
    c = case blockSize of
      8  -> fromHexUnsafe "000000000000001b"
      16 -> fromHexUnsafe "00000000000000000000000000000087"
      32 -> fromHexUnsafe "0000000000000000000000000000000000000000000000000000000000000425"
      _  -> undefined

    normalize :: ByteString -> ByteString
    normalize bytes = BA.pack . mappend ((0x80:) . replicate (blockSize - len - 1) $ 0) . BA.unpack $ bytes
      where len = BA.length bytes

    (msgTail, lastBlock) = BA.splitAt lastBlockBoundary msg
    lastBlockBoundary = blockSize * (ceiling (fromIntegral (BA.length msg) / fromIntegral blockSize :: Double) - 1)
    blockSize = CC.blockSize cipher
