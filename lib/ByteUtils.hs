module ByteUtils
( toHex
, fromHex
, fromHexUnsafe
, msb
) where

import Data.Char       (ord, toLower)
import Data.Word       (Word8, Word16, Word32)
import Data.Bits       (Bits, shift, (.&.), (.|.), rotate)
import Data.ByteString (ByteString)
import Data.ByteArray  (ByteArray)

import qualified Data.ByteString as BS
import qualified Data.ByteArray as BA

import Types

toHex :: ByteString -> String
toHex bytes = concat . fmap toHex' $ BS.unpack bytes
  where
    toHex' byte = (symbols!!) . fromEnum <$> [byte `shift` (-4), byte .&. 0x0f]
    symbols = "0123456789abcdef"

fromHex :: String -> Either Error ByteString
fromHex hex
  | isAligned =
    case fromHex' . fmap toLower $ hex of
      Just result -> Right result
      Nothing -> Left ErrorNotHex
  | otherwise = Left ErrorNonAlignedHex
  where
    isAligned = even $ length hex

    fromHex' :: String -> Maybe ByteString
    fromHex' "" = Just BS.empty
    fromHex' (x:y:mrest) = do
      bx <- f x
      by <- f y
      rest <- fromHex' mrest
      Just $ BS.singleton (bx `shift` 4 .|. by) <> rest

    f :: Char -> Maybe Word8
    f x
      | x >= '0' && x <= '9' = Just . toEnum $ ord x - 48
      | x >= 'a' && x <= 'f' = Just . toEnum $ 10 + ord x - 97
      | otherwise            = Nothing

fromHexUnsafe :: String -> ByteString
fromHexUnsafe = either (\e -> error . show $ e) id . fromHex

-- bytesToBlock :: ByteArray ba => ba -> Maybe Block
-- bytesToBlock = bytesToBlock'. BA.unpack
--   where
--     bytesToBlock' [w1]       = Just . Block8  $ w1
--     bytesToBlock' [w2,w1]    = Just . Block16 $ (fromIntegral w2 `shift` 8) .|. fromIntegral w1
--     bytesToBlock' [w3,w2,w1] = Just . Block32 $ (fromIntegral w3 `shift` 16) .|. (fromIntegral w2 `shift` 8) .|. fromIntegral w1
--     bytesToBlock' _          = Nothing

-- blockToBytes :: ByteArray ba => Block -> ba
-- blockToBytes (Block8 w) = BA.pack [w]
-- blockToBytes (Block16 w) = BA.pack . fmap (fromIntegral . (.&. 0xff)) $ [w `shift` (-8), w]
-- blockToBytes (Block32 w) = BA.pack . fmap (fromIntegral . (.&. 0xff)) $ [w `shift` (-24), w `shift` (-16), w `shift` (-8), w]

msb :: ByteArray ba => ba -> Int
msb = fromEnum . (.&. 1) . (`rotate` 1) . head . BA.unpack . BA.take 1
