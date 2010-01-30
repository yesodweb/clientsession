{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE DeriveDataTypeable #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
---------------------------------------------------------
--
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
    ( -- * Automatic key generation
      getKey
    , defaultKeyFile
    , getDefaultKey
      -- * Actual encryption/decryption
    , encrypt
    , decrypt
      -- * Key types and classes.
    , Word256
    , AESKey
      -- * Exceptions
    , ClientSessionException
    ) where

import Codec.Encryption.AES (AESKey)
import qualified Data.ByteString as BS
import Control.Failure
import Control.Monad (unless)

import Data.LargeWord (Word256)
import Codec.Utils (listFromOctets, listToOctets)
import Data.Word (Word8)
import System.Random (getStdGen, randoms, Random, randomR, random)
import qualified Codec.Encryption.AES as AES
import qualified Codec.Binary.Base64Url as Base64
import qualified Data.Digest.MD5 as MD5

import Data.Typeable (Typeable)
import Control.Exception (Exception)

-- | The default key file.
defaultKeyFile :: String
defaultKeyFile = "client_session_key.aes"

-- | Simply calls 'getKey' \"client_session_key.aes\"
getDefaultKey :: IO Word256
getDefaultKey = getKey defaultKeyFile

data ClientSessionException =
      KeyTooSmall BS.ByteString
    | InvalidBase64 String
    | MismatchedHash { _expected :: [Word8]
                     , _actual :: [Word8]
                     }
    deriving (Show, Typeable)
instance Exception ClientSessionException

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
                        then failure $ KeyTooSmall contents
                        else return $ head $ listFromOctets $ BS.unpack contents
        generateNewKey :: IO Word256
        generateNewKey = do
                stdGen <- getStdGen
                let word8s = map unMyWord8 $ take 32 $ randoms stdGen
                let newKey = head $ listFromOctets word8s
                BS.writeFile keyFile $ BS.pack word8s
                return newKey

newtype MyWord8 = MyWord8 { unMyWord8 :: Word8 }
    deriving (Integral, Real, Enum, Num, Ord, Eq, Show)
instance Random MyWord8 where
        randomR (a,b) g =
                let (x, g') = randomR (toInteger a, toInteger b) g
                in (fromIntegral $ mod x 256, g')
        random = randomR (MyWord8 minBound, MyWord8 maxBound)

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

-- | Base-64 decode and decrypt with the given key, if possible.  Calls
-- 'failure' if either the original string is not a valid base-64 encoded
-- string, or the hash at the beginning of the decrypted string does not match.
decrypt :: (AES.AESKey k, MonadFailure ClientSessionException m)
        => k                    -- ^ The key used for encryption.
        -> String               -- ^ Data to decrypt.
        -> m BS.ByteString      -- ^ The decrypted data, if possible.
decrypt k x = do
        decoded <- case Base64.decode x of
                        Nothing -> failure $ InvalidBase64 x
                        Just y -> return y
        let decrypted = listToOctets $ map (AES.decrypt k)
                        $ listFromOctets decoded
        let (expected, rest) = splitAt 16 decrypted
        let actual = MD5.hash rest
        unless (expected == actual) $ failure
                                    $ MismatchedHash expected actual
        return $ BS.pack rest
