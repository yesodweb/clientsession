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
      Key
    , getKey
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

import qualified Codec.Encryption.AES as AES
import qualified Codec.Binary.Base64Url as Base64
import qualified Data.Digest.Pure.MD5 as MD5

import Data.Typeable (Typeable)
import Control.Exception

import System.Directory

import qualified Data.ByteString as S
import qualified Data.ByteString.Lazy as L

import Data.Serialize
import System.Random

type Key = S.ByteString

-- | The default key file.
defaultKeyFile :: String
defaultKeyFile = "client_session_key.aes"

-- | Simply calls 'getKey' 'defaultKeyFile'.
getDefaultKey :: IO Key
getDefaultKey = getKey defaultKeyFile

data ClientSessionException =
      InvalidBase64 String
    | MismatchedHash { expectedHash :: S.ByteString
                     , actualHash   :: S.ByteString
                     }
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
    if exists
        then do
            key <- S.readFile keyFile
            if S.length key < minKeyLength
                then newKey
                else return key
        else newKey
  where
    newKey = do
        key' <- randomKey
        S.writeFile keyFile key'
        return key'

minKeyLength :: Int
minKeyLength = 16

randomKey :: IO Key
randomKey = do
    g <- newStdGen
    let (nums, _) =
            foldr
                (\_ (n, g') -> let (n', g'') = next g' in (n' : n, g''))
                ([], g)
                [1..minKeyLength]
    return $ S.pack $ map fromIntegral nums

-- | Encrypt with the given key and base-64 encode.
-- A hash is stored inside the encrypted key so that, upon decryption,
-- integrity can be guaranteed.
encrypt :: S.ByteString    -- ^ The key used for encryption.
        -> S.ByteString    -- ^ The data to encrypt.
        -> String     -- ^ Encrypted and encoded data.
encrypt k bs =
    let bs' = encode bs
        padded = bs' `S.append` S.pack (flip replicate 0 $
                    (16 - (S.length bs' `mod` 16)))
        withHash = encode (MD5.md5 $ L.fromChunks [padded]) `S.append` padded
        encrypted = AES.encrypt k withHash
     in Base64.encode $ S.unpack encrypted

-- | Base-64 decode and decrypt with the given key, if possible.  Calls
-- 'failure' if either the original string is not a valid base-64 encoded
-- string, or the hash at the beginning of the decrypted string does not match.
decrypt :: (Monad m, Failure ClientSessionException m)
        => S.ByteString         -- ^ The key used for encryption.
        -> String               -- ^ Data to decrypt.
        -> m S.ByteString       -- ^ The decrypted data, if possible.
decrypt k x = do
    decoded <- case Base64.decode x of
                    Nothing -> failure $ InvalidBase64 x
                    Just y -> return y
    decrypted <-
        case AES.decrypt k $ S.pack decoded of
            Nothing -> failure NotValidEncodedByteString
            Just y -> return y
    let (expected, rest) = S.splitAt 16 decrypted
    let actual = encode $ MD5.md5 $ L.fromChunks [rest]
    unless (expected == actual) $ failure
                                $ MismatchedHash expected actual
    case decode rest of
        Left _ -> failure NotValidEncodedByteString
        Right y -> return y
