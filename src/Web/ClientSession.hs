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
      Key(..)
    , IV
    , randomIV
    , mkIV
    , getKey
    , defaultKeyFile
    , getDefaultKey
    , initKey
      -- * Actual encryption/decryption
    , encrypt
    , encryptIO
    , decrypt
    ) where

import Control.Arrow (second)
import Control.Monad (guard)
import Data.Bits (xor)
import System.Directory (doesFileExist)
import qualified Data.ByteString as S
import qualified Crypto.Cipher.AES as A
import Crypto.Hash.SHA256 (SHA256)
import Crypto.HMAC (MacKey(..), hmac')
import qualified Data.ByteString.Base64 as B
import Crypto.Random (newGenIO, genBytes, SystemRandom)
import Data.Serialize (encode)

data Key = Key { aesKey  :: A.Key
               , hmacKey :: MacKey }
         deriving (Eq, Show)

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
        then S.readFile keyFile >>= either (const newKey) return . initKey
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
    bs <- randomBytes 64
    case initKey bs of
        Left e -> error e -- should never happen
        Right key -> return (bs, key)

-- | Initializes a 'Key' from a random 'S.ByteString'.  It's
-- better to give a 'S.ByteString' with exactly 64 bytes, but
-- anything with at least 32 bytes will work.
initKey :: S.ByteString -> Either String Key
initKey bs | S.length bs < 32 = Left $ "Web.ClientSession.initKey: length of " ++
                                       show (S.length bs) ++ " too small."
initKey bs = fmap mk $ A.initKey256 preAesKey
    where
      preAesKey | S.length bs >= 64 = S.pack $ uncurry (S.zipWith xor) $ S.splitAt 32 bs
                | otherwise         = S.take 32 bs
      mk k = Key { aesKey  = k
                 , hmacKey = MacKey bs }
                 -- It's okay to have a MacKey where bs doesn't
                 -- have exactly 512 bits, the size of the block
                 -- used in SHA-256.  hmac' already deals with it.

encryptIO :: Key -> S.ByteString -> IO S.ByteString
encryptIO key x = do
    iv <- randomIV
    return $ encrypt key iv x

encrypt :: Key
        -> IV
        -> S.ByteString -- ^ data
        -> S.ByteString
encrypt key (IV iv) x =
    B.encode $ S.concat [iv, encode auth, encrypted]
  where
    toPad = 16 - S.length x `mod` 16
    pad = S.replicate toPad $ fromIntegral toPad
    y = pad `S.append` x
    encrypted = A.encryptCBC (aesKey key) iv y
    auth = hmac' (hmacKey key) encrypted :: SHA256

decrypt :: Key -- ^ key
        -> S.ByteString -- ^ data
        -> Maybe S.ByteString
decrypt key dataBS64 = do
    dataBS <- either (const Nothing) Just $ B.decode dataBS64
    if S.length dataBS `mod` 16 /= 0 || S.length dataBS < 48
        then Nothing
        else do
            let (iv, (auth, encrypted)) = second (S.splitAt 32) $ S.splitAt 16 dataBS
                auth' = hmac' (hmacKey key) encrypted :: SHA256
            guard (encode auth' == auth)
            let x = A.decryptCBC (aesKey key) iv encrypted
            (td, _) <- S.uncons x
            guard (td > 0 && td <= 16)
            return $ S.drop (fromIntegral td) x
