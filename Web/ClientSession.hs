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
    , getKey
    , embedKey
    , defaultKeyFile
    , getDefaultKey
    , embedDefaultKey
      -- * Actual encryption/decryption
    , encrypt
    , decrypt
    ) where

import System.Directory
import qualified Data.ByteString as S
import qualified Data.ByteString.Char8 as B

import System.Random

import Data.ByteString.Unsafe

import Foreign.C
import Foreign.Ptr
import Foreign.Marshal.Alloc
import Foreign.Storable
import System.IO.Unsafe
import Language.Haskell.TH

type Key = S.ByteString

-- | The default key file.
defaultKeyFile :: String
defaultKeyFile = "client_session_key.aes"

-- | Simply calls 'getKey' 'defaultKeyFile'.
getDefaultKey :: IO Key
getDefaultKey = getKey defaultKeyFile

-- | Simply calls 'embedKey' 'defaultKeyFile'.
embedDefaultKey :: Q Exp
embedDefaultKey = embedKey defaultKeyFile

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

-- | Embed a key from the given text file into haskell source.
--
-- Eliminates overhead of reading key file with each request.
embedKey :: FilePath -> Q Exp
embedKey keyFile = do
  k <- runIO $ getKey keyFile
  let cs = B.unpack k
  [| B.pack |] `appE` (litE $ stringL cs)

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

encrypt :: S.ByteString -- ^ key
        -> S.ByteString -- ^ data
        -> S.ByteString
encrypt keyBS dataBS = unsafePerformIO $
    unsafeUseAsCString keyBS $ \keyPtr ->
        unsafeUseAsCStringLen dataBS $ \(dataPtr, dataLen) -> do
            let keyPtr' = castPtr keyPtr
                dataPtr' = castPtr dataPtr
                dataLen' = fromIntegral dataLen
            allocaBytes 4 $ \lenp -> do
                newPtr <- c_encrypt dataLen' dataPtr' keyPtr' lenp
                let newPtr' = castPtr newPtr
                len <- peek lenp
                let len' = fromIntegral len
                unsafePackCStringFinalizer newPtr' len' $ free newPtr'

decrypt :: S.ByteString -- ^ key
        -> S.ByteString -- ^ data
        -> Maybe S.ByteString
decrypt keyBS dataBS = unsafePerformIO $
    unsafeUseAsCString keyBS $ \keyPtr ->
        unsafeUseAsCStringLen dataBS $ \(dataPtr, dataLen) -> do
            let keyPtr' = castPtr keyPtr
                dataPtr' = castPtr dataPtr
                dataLen' = fromIntegral dataLen
            allocaBytes 4 $ \lenp -> do
                newPtr <- c_decrypt dataLen' dataPtr' keyPtr' lenp
                if newPtr == nullPtr
                    then return Nothing
                    else do
                        let newPtr' = castPtr newPtr
                        len <- peek lenp
                        let len' = fromIntegral len
                        bs <- unsafePackCStringFinalizer newPtr' len'
                            $ free newPtr'
                        return $ Just bs

foreign import ccall unsafe "encrypt"
    c_encrypt :: CUInt -> Ptr CUChar -> Ptr CUChar -> Ptr CUInt
              -> IO (Ptr CChar)

foreign import ccall unsafe "decrypt"
    c_decrypt :: CUInt -> Ptr CChar -> Ptr CUChar -> Ptr CUInt
              -> IO (Ptr CUChar)
