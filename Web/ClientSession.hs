{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE DeriveDataTypeable #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
---------------------------------------------------------
--
-- Module        : Web.ClientSession
-- Copyright     : Michael Snoyman
-- License       : SD3
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
      -- * Exceptions
    , ClientSessionException (..)
    ) where

import Control.Failure
import Control.Monad

import qualified Codec.Encryption.AESAux as AES
import qualified Codec.Binary.Base64Url as Base64
import qualified Data.Digest.Pure.MD5 as MD5

import Data.Typeable (Typeable)
import Control.Exception

import System.Directory

import qualified Data.ByteString as S
import qualified Data.ByteString.Lazy as L

import Data.Serialize
import Control.Applicative

data Key = Key !Word64 !Word64 !Word64 !Word64

instance Serialize Key where
    put (Key a b c d) = put a >> put b >> put c >> put d
    get = do
        a <- get
        b <- get
        c <- get
        d <- get
        return $ Key a b c d

keyToOctets :: Key -> [Word8]
keyToOctets = S.unpack . encode

-- | The default key file.
defaultKeyFile :: String
defaultKeyFile = "client_session_key.aes"

-- | Simply calls 'getKey' \"client_session_key.aes\"
getDefaultKey :: IO Key
getDefaultKey = getKey defaultKeyFile

data ClientSessionException =
      KeyTooSmall S.ByteString
    | InvalidBase64 String
    | MismatchedHash { expectedHash :: S.ByteString
                     , actualHash   :: S.ByteString
                     }
    | NotMultOf16
    | NotValidEncodedByteString
    deriving (Show, Typeable, Eq)
instance Exception ClientSessionException

-- | Get a key from the given text file.
--
-- If the file does not exist a random key will be generated and stored in that
-- file.
getKey :: FilePath     -- ^ File name where key is stored.
       -> IO Key       -- ^ The actual key.
getKey keyFile = do
    exists <- doesFileExist keyFile
    mkey <-
        if exists
            then either (const Nothing) Just . decode <$> S.readFile keyFile
            else return Nothing
    case mkey of
        Just key -> return key
        Nothing -> do
            key <- randomKey
            S.writeFile keyFile $ encode key
            return key

randomKey :: IO Key
randomKey = error "FIXME"

-- | Encrypt with the given key and base-64 encode.
-- A hash is stored inside the encrypted key so that, upon decryption,
-- integrity can be guaranteed.
encrypt :: Key             -- ^ The key used for encryption.
        -> S.ByteString    -- ^ The data to encrypt.
        -> String     -- ^ Encrypted and encoded data.
encrypt k bs =
    let bs' = encode bs
        padded = bs' `S.append` S.pack (flip replicate 0 $
                    (16 - (S.length bs' `mod` 16)))
        withHash = encode (MD5.md5 $ L.fromChunks [padded]) `S.append` padded
        encrypted = aes256Encrypt' (keyToOctets k) $ S.unpack withHash
     in Base64.encode encrypted

aes256Encrypt' _ [] = []
aes256Encrypt' key octets =
    let (x, y) = splitAt 16 octets
     in AES.aes256Encrypt key x ++ aes256Encrypt' key y

aes256Decrypt' _ [] = []
aes256Decrypt' key octets =
    let (x, y) = splitAt 16 octets
     in AES.aes256Decrypt key x ++ aes256Decrypt' key y

-- | Base-64 decode and decrypt with the given key, if possible.  Calls
-- 'failure' if either the original string is not a valid base-64 encoded
-- string, or the hash at the beginning of the decrypted string does not match.
decrypt :: (Monad m, Failure ClientSessionException m)
        => Key                  -- ^ The key used for encryption.
        -> String               -- ^ Data to decrypt.
        -> m S.ByteString       -- ^ The decrypted data, if possible.
decrypt k x = do
    decoded <- case Base64.decode x of
                    Nothing -> failure $ InvalidBase64 x
                    Just y -> return y
    when (length decoded `mod` 16 /= 0) $ failure NotMultOf16
    let decrypted = aes256Decrypt' (keyToOctets k) decoded
    let (expected, rest) = splitAt 16 decrypted
        expected' = S.pack expected
    let actual = encode $ MD5.md5 $ L.pack rest
    unless (expected' == actual) $ failure
                                 $ MismatchedHash expected' actual
    case decode $ S.pack rest of
        Left _ -> failure NotValidEncodedByteString
        Right x -> return x
