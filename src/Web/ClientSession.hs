{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE ForeignFunctionInterface #-}
{-# LANGUAGE TemplateHaskell #-}
---------------------------------------------------------
--
-- |
--
-- Module        : Web.ClientSession
-- Copyright     : Michael Snoyman
-- License       : BSD3
--
-- Maintainer    : Michael Snoyman <michael@snoyman.com>
-- Stability     : Stable
-- Portability   : portable
--
-- Stores session data in a client cookie.  In order to do so,
-- we:
--
-- * Encrypt the cookie data using AES in CBC mode.  This allows
-- you to store sensitive information on the client side without
-- worrying about eavesdropping.
--
-- * Sign the encrypted cookie data using HMAC-SHA256.  Besides
-- detecting potential errors in storage or transmission of the
-- cookies (integrity), the HMAC-SHA256 code also avoids
-- malicious modifications of the cookie data by assuring you
-- that the cookie data really was generated by this server
-- (authentication).
--
-- * Encode everything using Base64.  Thus we avoid problems with
-- non-printable characters by giving the browser a simple
-- string.
--
-- Simple usage of the library involves just calling
-- 'getDefaultKey' on the startup of your server, 'encryptIO'
-- when serializing cookies and 'decrypt' when parsing then back.
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

-- from base
import Control.Arrow (second)
import Control.Monad (guard)
import Data.Bits (xor)

-- from directory
import System.Directory (doesFileExist)

-- from bytestring
import qualified Data.ByteString as S
import qualified Data.ByteString.Base64 as B

-- from cereal
import Data.Serialize (encode, decode)

-- from crypto-api
import Crypto.Classes (buildKey)
import Crypto.HMAC (MacKey(..), hmac')
import Crypto.Random (newGenIO, genBytes, SystemRandom)
import qualified Crypto.Modes as Modes

-- from cryptocipher
import qualified Crypto.Cipher.AES as A

-- from cryptohash
import Crypto.Hash.SHA256 (SHA256)

-- | The keys used to store the cookies.  We have an AES key used
-- to encrypt the cookie and a HMAC-SHA256 key used verify the
-- authencity and integrity of the cookie.  The AES key needs to
-- have exactly 32 bytes (256 bits).  The HMAC-SHA256 should have
-- 64 bytes (512 bits), which is the block size of SHA256, but
-- any size may be used.
--
-- See also 'getDefaultKey' and 'initKey'.
data Key = Key { aesKey  :: A.AES256
               , hmacKey :: MacKey }

-- | The initialization vector used by AES.  Should be exactly 16
-- bytes long.
type IV = Modes.IV A.AES256

-- | Construct an initialization vector from a 'S.ByteString'.
-- Fails if there isn't exactly 16 bytes.
mkIV :: S.ByteString -> Maybe IV
mkIV bs = case (S.length bs, decode bs) of
            (16, Right iv) -> Just iv
            _              -> Nothing

-- | Randomly construct a fresh initialization vector.  You
-- /should not/ reuse initialization vectors.
randomIV :: IO IV
randomIV = Modes.getIVIO

-- | The default key file.
defaultKeyFile :: FilePath
defaultKeyFile = "client_session_key.aes"

-- | Simply calls 'getKey' 'defaultKeyFile'.
getDefaultKey :: IO Key
getDefaultKey = getKey defaultKeyFile

-- | Get a key from the given text file.
--
-- If the file does not exist or is corrupted a random key will
-- be generated and stored in that file.
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

-- | Generate the given number of random bytes.
randomBytes :: Int -> IO S.ByteString
randomBytes len = do
    g <- newGenIO
    either (error . show) (return . fst) $ genBytes len (g :: SystemRandom)

-- | Generate a random 'Key'.  Besides the 'Key', the
-- 'ByteString' passed to 'initKey' is returned so that it can be
-- saved for later use.
randomKey :: IO (S.ByteString, Key)
randomKey = do
    bs <- randomBytes 64
    case initKey bs of
        Left e -> error $ "Web.ClientSession.randomKey: never here, " ++ e
        Right key -> return (bs, key)

-- | Initializes a 'Key' from a random 'S.ByteString'.  It's
-- better to give a 'S.ByteString' with exactly 64 bytes, but
-- anything with at least 32 bytes will work.
initKey :: S.ByteString -> Either String Key
initKey bs | S.length bs < 32 = Left $ "Web.ClientSession.initKey: length of " ++
                                       show (S.length bs) ++ " too small."
initKey bs = case buildKey preAesKey of
               Nothing -> Left $ "Web.ClientSession.initKey: unknown error with buildKey."
               Just k  -> Right (mk k)
    where
      preAesKey | S.length bs >= 64 = S.pack $ uncurry (S.zipWith xor) $ S.splitAt 32 bs
                | otherwise         = S.take 32 bs
      mk k = Key { aesKey  = k
                 , hmacKey = MacKey bs }
                 -- It's okay to have a MacKey where bs doesn't
                 -- have exactly 512 bits, the size of the block
                 -- used in SHA-256.  hmac' already deals with it.

-- | Same as 'encrypt', however randomly generates the
-- initialization vector for you.
encryptIO :: Key -> S.ByteString -> IO S.ByteString
encryptIO key x = do
    iv <- randomIV
    return $ encrypt key iv x

-- | Encrypt (AES-CBC), sign (HMAC-SHA256) and encode (Base64)
-- the given cookie data.  The returned byte string is ready to
-- be used in a response header.
encrypt :: Key          -- ^ Key of the server.
        -> IV           -- ^ New, random initialization vector (see 'randomIV').
        -> S.ByteString -- ^ Serialized cookie data.
        -> S.ByteString -- ^ Encoded cookie data to be given to
                        -- the client browser.
encrypt key iv x =
    B.encode $ S.concat [encode iv, encode auth, encrypted]
  where
    (encrypted, _) = Modes.ctr' Modes.incIV (aesKey key) iv x
    auth = hmac' (hmacKey key) encrypted :: SHA256

-- | Decode (Base64), verify the integrity and authenticity
-- (HMAC-SHA256) and decrypt (AES-CBC) the given encoded cookie
-- data.  Returns the original serialized cookie data.  Fails if
-- the data is corrupted.
decrypt :: Key                -- ^ Key of the server.
        -> S.ByteString       -- ^ Encoded cookie data given by the browser.
        -> Maybe S.ByteString -- ^ Serialized cookie data.
decrypt key dataBS64 = do
    dataBS <- either (const Nothing) Just $ B.decode dataBS64
    guard (S.length dataBS >= 48) -- 16 bytes of IV + 32 bytes of HMAC-SHA256
    let (iv_e, (auth, encrypted)) = second (S.splitAt 32) $ S.splitAt 16 dataBS
        auth' = hmac' (hmacKey key) encrypted :: SHA256
    guard (encode auth' == auth)
    iv <- either (const Nothing) Just $ decode iv_e
    let (x, _) = Modes.unCtr' Modes.incIV (aesKey key) iv encrypted
    return x
