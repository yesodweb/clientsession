{-# OPTIONS_GHC -fno-warn-orphans #-}
---------------------------------------------------------
-- |
-- Module        : Web.ClientSession
-- Copyright     : Michael Snoyman
-- License       : BSD3
--
-- Maintainer    : Michael Snoyman <michael@snoyman.com>
-- Stability     : Stable
-- Portability   : portable
--
-- Stores session data in a client cookie.
--
---------------------------------------------------------
module Web.ClientSession
    ( getKey
    , encrypt
    , decrypt
    , getDefaultKey
    ) where

import Codec.Encryption.AES (AESKey)
import qualified Data.ByteString as BS

import Data.LargeWord (Word256)
import Codec.Utils (listFromOctets, listToOctets)
import Data.Word (Word8)
import System.Random (getStdGen, randoms, Random, randomR, random)
import qualified Data.ByteString as BS
import qualified Codec.Encryption.AES as AES
import qualified Codec.Binary.Base64Url as Base64
import qualified Data.Digest.MD5 as MD5

getDefaultKey :: IO Word256
getDefaultKey = getKey "client_session_key.aes"

-- | Get a 256-bit key from the given text file.
-- If the file does not exist, or did not contain enough bits,
-- a random key will be generated and stored in that file.
getKey :: FilePath     -- ^ File name where key is stored.
       -> IO Word256   -- ^ The actual 256-bit key.
getKey keyFile = catch loadKeyFromFile $ const generateNewKey where
        loadKeyFromFile :: IO Word256
        loadKeyFromFile = do
                contents <- BS.readFile keyFile
                if BS.length contents < 32
                        then fail "Key too small"
                        else return $ head $ listFromOctets $ BS.unpack contents
        generateNewKey :: IO Word256
        generateNewKey = do
                stdGen <- getStdGen
                let word8s = take 32 $ randoms stdGen
                let newKey = head $ listFromOctets word8s
                BS.writeFile keyFile $ BS.pack word8s
                return newKey

instance Random Word8 where
        randomR (a,b) g =
                let (x, g') = randomR (toInteger a, toInteger b) g
                in (toEnum $ fromEnum $ mod x 256, g')
        random = randomR (minBound,maxBound)

-- | Encrypt with the given key and base-64 encode.
-- A hash is stored inside the encrypted key so that, upon decryption,
-- integrity can be guaranteed.
encrypt :: AES.AESKey k
        => k               -- ^ The key used for encryption.
        -> BS.ByteString   -- ^ The data to encrypt.
        -> String          -- ^ Encrypted and encoded data.
encrypt k x =
        let unpacked = BS.unpack x
        in Base64.encode . listToOctets . map (AES.encrypt k) .
           listFromOctets $ MD5.hash unpacked ++ unpacked

-- | Helper function to convert a Maybe into any monad
liftMaybe :: Monad m => Maybe a -> m a
liftMaybe Nothing = fail "Nothing"
liftMaybe (Just x) = return x

-- | Base-64 decode and decrypt with the given key, if possible.
-- If either the original string is not a valid base-64 encoded string,
-- or the hash at the beginning of the decrypted string does not match,
-- this function returns 'Nothing'.
decrypt :: (AES.AESKey k, Monad m)
        => k                    -- ^ The key used for encryption.
        -> String               -- ^ Data to decrypt.
        -> m BS.ByteString      -- ^ The decrypted data, if possible.
decrypt k x = do
        decoded <- liftMaybe $ Base64.decode x
        let decrypted = listToOctets $ map (AES.decrypt k)
                        $ listFromOctets decoded
        let (hash, rest) = splitAt 16 decrypted
        if hash == MD5.hash rest
                then return $ BS.pack rest
                else fail "Invalid"
