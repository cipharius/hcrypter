{-# LANGUAGE OverloadedStrings #-}

module Cryptography where

import Crypto.Cipher.Types   (BlockCipher)
import Crypto.Cipher.AES     (AES128)
import Data.ByteArray        (ByteArray, xor)
import Data.ByteString       (ByteString)
import Data.ByteString.Char8 (stripSuffix)
import Data.String           (IsString)
import Data.Bits             (shift, zeroBits, bit, setBit, (.|.))
import Data.Char             (toLower, isSpace)
import Cli                   (CipherMode(..))

import qualified Crypto.Cipher.Types as CC
import qualified Crypto.Error        as CE
import qualified Data.ByteArray      as BA

import Data.Bits.ByteString
import Types
import ByteUtils

readKey :: FilePath -> IO (Either Error ByteString)
readKey = fmap (fromHex . filter nonWhiteSpace . fmap toLower) . readFile
  where
    nonWhiteSpace char = not $ isSpace char

cipher :: ByteString -> Either Error AES128
cipher key = case CC.cipherInit key of
  CE.CryptoPassed ciph -> Right ciph
  CE.CryptoFailed err  -> Left $ ErrorCipherFail err

encrypt :: (BlockCipher cMac, BlockCipher c) =>
           CipherMode -> Maybe cMac -> c -> ByteString -> Either Error ByteString
encrypt mode maybeCipherMac cipher plainText = do
  let
    macMetaByte = maybe zeroBits (BA.singleton . toEnum . CC.blockSize) maybeCipherMac
    encrypt' = case mode of
      CipherModeCBC -> cbcEncrypt
      CipherModeOFB -> ofbMode

  mac <- case maybeCipherMac of
    Just cipherMac -> omac cipherMac plainText
    Nothing        -> return ""

  cipherText <- encrypt' cipher plainText

  return $ macMetaByte <> mac <> cipherText

decrypt :: (BlockCipher cMac, BlockCipher c) =>
           CipherMode -> Maybe cMac -> c -> ByteString -> Either Error ByteString
decrypt mode maybeCipherMac cipher cipherText = do
  (macMetaByte, cipherMessage) <-
    case BA.uncons cipherText of
      Just (byte, rest) -> Right (fromEnum byte, rest)
      Nothing           -> Left ErrorShortCipherText

  let
    (macPart, cipherTextPart) = BA.splitAt macMetaByte cipherMessage
    macPartLength = BA.length macPart
    decrypt' = case mode of
      CipherModeCBC -> cbcDecrypt
      CipherModeOFB -> ofbMode

  plainText <- decrypt' cipher cipherTextPart

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


constCbcIv :: ByteString
constCbcIv = fromHexUnsafe "0ac701bf360252f019e4855d4e0e67c9"

cbcEncrypt :: BlockCipher c => c -> ByteString -> Either Error ByteString
cbcEncrypt cipher plainText
  | fullBlockCount == 0 = Left $ ErrorLessThanBlock blockSize
  | isBlockAligned      = Right $ encrypt' constCbcIv plainText
  | fullBlockCount > 1  = Right $ ciphertext <> ciphertextTail
  | fullBlockCount == 1 = Right $ cipherSteal' constCbcIv tailPart
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
  | fullBlockCount == 0 = Left $ ErrorLessThanBlock blockSize
  | isBlockAligned      = Right $ decrypt' constCbcIv ciphertext
  | fullBlockCount > 1  = Right $ decrypt' constCbcIv alignedPart <> stolenTail
  | fullBlockCount == 1 = Right $ cipherSteal' constCbcIv tailPart
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

-- ofbEncrypt :: (BlockCipher c, BlockCipher cM) =>
--               Maybe cM -> c -> ByteString -> Either Error ByteString
-- ofbEncrypt Nothing cipher plainText          = ofbMode cipher plainText
-- ofbEncrypt (Just macCipher) cipher plainText = msgOmac <> msgCipherText
--   where
--     msgCipherText = ofbMode cipher plainText
--     msgOmac = omac macCipher plainText

-- ofbDecrypt :: (BlockCipher c, BlockCipher cM) =>
--               Maybe cM -> c -> ByteString -> Either Error ByteString
-- ofbDecrypt Nothing cipher cipherText          = ofbMode cipher cipherText
-- ofbDecrypt (Just macCipher) cipher cipherText
--   | inputLength < minLength = Left $ ErrorShortInput minLength inputLength
--   | otherwise               =
--     case ofbMode cipher cipherTextPart of
--       Left err        -> Left err
--       Right plainText ->
--         case omac macCipher plainText of
--           Left err                  -> Left err
--           Right macControl
--             | macPart == macControl -> Right plainText
--             | otherwise             -> Left ErrorMacMismatch
--   where
--     (macPart, cipherTextPart) = BA.splitAt (CC.blockSize macCipher) cipherText
--     inputLength = BA.length cipherText
--     minLength = CC.blockSize cipher + CC.blockSize macCipher

ofbMode :: BlockCipher c => c -> ByteString -> Either Error ByteString
ofbMode cipher txt
  | fullBlockCount == 0 = Left $ ErrorLessThanBlock blockSize
  | otherwise           = Right $ chain' constCbcIv txt
  where
    blockSize = CC.blockSize cipher
    inputLength = BA.length txt

    isBlockAligned = (inputLength `mod` blockSize) == 0
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
    k1 = case msb k0 of
      0 -> k0 `shift` 1
      1 -> (k0 `shift` 1) `xor` c

    k2 :: ByteString
    k2 = case msb k1 of
      0 -> k1 `shift` 1
      1 -> (k1 `shift` 1) `xor` c

    c :: ByteString
    c = case blockSize of
      8  -> fromHexUnsafe "000000000000001b"
      16 -> fromHexUnsafe "00000000000000000000000000000087"
      32 -> fromHexUnsafe "0000000000000000000000000000000000000000000000000000000000000425"

    normalize :: ByteString -> ByteString
    normalize bytes = BA.pack . mappend ((0x80:) . take (blockSize - len - 1) . repeat $ 0) . BA.unpack $ bytes
      where len = BA.length bytes

    (msgTail, lastBlock) = BA.splitAt lastBlockBoundary msg
    lastBlockBoundary = blockSize * (ceiling (fromIntegral (BA.length msg) / fromIntegral blockSize) - 1)
    blockSize = CC.blockSize cipher
