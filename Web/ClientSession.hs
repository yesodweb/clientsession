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

import Codec.Crypto.SimpleAES
import Control.Failure
import Control.Monad (unless)

import qualified Codec.Crypto.SimpleAES as AES
import qualified Codec.Binary.Base64Url as Base64
import qualified Data.Digest.Pure.MD5 as MD5

import Data.Typeable (Typeable)
import Control.Exception

import System.Directory

import qualified Data.ByteString as S
import qualified Data.ByteString.Lazy as L

import Data.Binary

-- | The default key file.
defaultKeyFile :: String
defaultKeyFile = "client_session_key.aes"

-- | Simply calls 'getKey' \"client_session_key.aes\"
getDefaultKey :: IO AES.Key
getDefaultKey = getKey defaultKeyFile

data ClientSessionException =
      KeyTooSmall S.ByteString
    | InvalidBase64 String
    | InvalidHash String
    | MismatchedHash { expectedHash :: L.ByteString
                     , actualHash   :: L.ByteString
                     }
    deriving (Show, Typeable, Eq)
instance Exception ClientSessionException

-- | Get a key from the given text file.
--
-- If the file does not exist a random key will be generated and stored in that
-- file.
getKey :: FilePath     -- ^ File name where key is stored.
       -> IO AES.Key   -- ^ The actual key.
getKey keyFile = do
    exists <- doesFileExist keyFile
    if exists
        then S.readFile keyFile
        else do
            key <- AES.randomKey
            S.writeFile keyFile key
            return key

-- | Encrypt with the given key and base-64 encode.
-- A hash is stored inside the encrypted key so that, upon decryption,
-- integrity can be guaranteed.
encrypt :: AES.Key         -- ^ The key used for encryption.
        -> L.ByteString    -- ^ The data to encrypt.
        -> IO (String)     -- ^ Encrypted and encoded data.
encrypt k bs = do
    let withHash = encode (MD5.md5 bs) `L.append` bs
    encrypted <- AES.encryptMsg mode k withHash
    return $ Base64.encode $ L.unpack encrypted

mode :: AES.Mode
mode = ECB

-- | Base-64 decode and decrypt with the given key, if possible.  Calls
-- 'failure' if either the original string is not a valid base-64 encoded
-- string, or the hash at the beginning of the decrypted string does not match.
decrypt :: (Monad m, Failure ClientSessionException m)
        => AES.Key              -- ^ The key used for encryption.
        -> String               -- ^ Data to decrypt.
        -> m L.ByteString       -- ^ The decrypted data, if possible.
decrypt k x = do
    decoded <- case Base64.decode x of
                    Nothing -> failure $ InvalidBase64 x
                    Just y -> return y
    decrypted <- case AES.decryptMsg' mode k $ L.pack decoded of
                    Left s -> failure $ InvalidHash s
                    Right z -> return z
    let (expected, rest) = L.splitAt 16 decrypted
    let actual = encode $ MD5.md5 rest
    unless (expected == actual) $ failure
                                $ MismatchedHash expected actual
    return rest
