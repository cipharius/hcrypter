module ByteUtils
( toHex
, fromHex
, fromHexUnsafe
, msb
) where

import Data.Char       (ord, toLower)
import Data.Word       (Word8)
import Data.Bits       (shift, (.&.), (.|.), rotate)
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
    fromHex' _ = Nothing

    f :: Char -> Maybe Word8
    f x
      | x >= '0' && x <= '9' = Just . toEnum $ ord x - 48
      | x >= 'a' && x <= 'f' = Just . toEnum $ 10 + ord x - 97
      | otherwise            = Nothing

fromHexUnsafe :: String -> ByteString
fromHexUnsafe = either (\e -> error . show $ e) id . fromHex

msb :: ByteArray ba => ba -> Bool
msb = (> 0) . (.&. 1) . (`rotate` 1) . head . BA.unpack . BA.take 1
