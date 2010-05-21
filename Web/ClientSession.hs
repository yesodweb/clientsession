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

import Codec.Encryption.AES

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
