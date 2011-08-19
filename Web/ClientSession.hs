{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE ForeignFunctionInterface #-}
{-# LANGUAGE TemplateHaskell #-}
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
      Key
    , IV
    , randomIV
    , mkIV
    , getKey
    , defaultKeyFile
    , getDefaultKey
      -- * Actual encryption/decryption
    , encrypt
    , encryptIO
    , decrypt
    ) where

import System.Directory (doesFileExist)
import qualified Data.ByteString as S
import qualified Crypto.Cipher.AES as A
import Crypto.Cipher.AES (Key)
import qualified Data.ByteString.Base64 as B
import Crypto.Random (newGenIO, genBytes, SystemRandom)

newtype IV = IV S.ByteString
    deriving Show

mkIV :: S.ByteString -> Maybe IV
mkIV bs
    | S.length bs == 16 = Just $ IV bs
    | otherwise = Nothing

randomIV :: IO IV
randomIV = fmap IV $ randomBytes 16

-- | The default key file.
defaultKeyFile :: String
defaultKeyFile = "client_session_key.aes"

-- | Simply calls 'getKey' 'defaultKeyFile'.
getDefaultKey :: IO Key
getDefaultKey = getKey defaultKeyFile

-- | Get a key from the given text file.
--
-- If the file does not exist a random key will be generated and stored in that
-- file.
getKey :: FilePath     -- ^ File name where key is stored.
       -> IO Key       -- ^ The actual key.
getKey keyFile = do
    exists <- doesFileExist keyFile
    if exists
        then S.readFile keyFile >>= either (const newKey) return . A.initKey256
        else newKey
  where
    newKey = do
        (bs, key') <- randomKey
        S.writeFile keyFile bs
        return key'

randomBytes :: Int -> IO S.ByteString
randomBytes len = do
    g <- newGenIO
    either (error . show) (return . fst) $ genBytes len (g :: SystemRandom)

randomKey :: IO (S.ByteString, Key)
randomKey = do
    bs <- randomBytes 32
    case A.initKey256 bs of
        Left e -> error e -- should never happen
        Right key -> return (bs, key)

encryptIO :: Key -> S.ByteString -> IO S.ByteString
encryptIO key x = do
    iv <- randomIV
    return $ encrypt key iv x

encrypt :: Key
        -> IV
        -> S.ByteString -- ^ data
        -> S.ByteString
encrypt key (IV iv) x =
    B.encode $ iv `S.append` A.encryptCBC key iv y
  where
    toPad = 16 - S.length x `mod` 16
    pad = S.replicate toPad $ fromIntegral toPad
    y = pad `S.append` x

decrypt :: Key -- ^ key
        -> S.ByteString -- ^ data
        -> Maybe S.ByteString
decrypt key dataBS64 = do
    dataBS <- either (const Nothing) Just $ B.decode dataBS64
    if S.length dataBS `mod` 16 /= 0 || S.length dataBS < 16
        then Nothing
        else do
            let (iv, encrypted) = S.splitAt 16 dataBS
            let x = A.decryptCBC key iv encrypted
            (td, _) <- S.uncons x
            if td > 0 && td <= 16
                then Just $ S.drop (fromIntegral td) x
                else Nothing
