{-# LANGUAGE ForeignFunctionInterface #-}
module Codec.Encryption.AES
    ( encrypt
    , decrypt
    ) where

import Data.ByteString (ByteString, pack)
import qualified Data.ByteString as S
import Data.ByteString.Unsafe

import Data.Serialize

import Foreign.C
import Foreign.Ptr
import Foreign.Marshal.Alloc
import System.IO.Unsafe

toMult16 :: ByteString -> ByteString
toMult16 bs =
    let bs' = encode bs
        ws  = replicate (16 - S.length bs' `mod` 16) 0
     in bs' `S.append` pack ws

fromMult16 :: ByteString -> Maybe ByteString
fromMult16 bs =
    case decode bs of
        Left _ -> Nothing
        Right x -> Just x

encrypt :: ByteString -- ^ key
        -> ByteString -- ^ data
        -> ByteString
encrypt keyBS dataBS = unsafePerformIO $
    unsafeUseAsCString keyBS $ \keyPtr ->
        unsafeUseAsCStringLen (toMult16 dataBS) $ \(dataPtr, dataLen) -> do
            let keyPtr' = castPtr keyPtr
                dataPtr' = castPtr dataPtr
                dataLen' = fromIntegral dataLen
            newPtr <- c_encrypt dataLen' dataPtr' keyPtr'
            let newPtr' = castPtr newPtr
            unsafePackCStringFinalizer newPtr' dataLen $ free newPtr'

decrypt :: ByteString -- ^ key
        -> ByteString -- ^ data
        -> Maybe ByteString
decrypt keyBS dataBS = unsafePerformIO $
    unsafeUseAsCString keyBS $ \keyPtr ->
        unsafeUseAsCStringLen dataBS $ \(dataPtr, dataLen) -> do
            let keyPtr' = castPtr keyPtr
                dataPtr' = castPtr dataPtr
                dataLen' = fromIntegral dataLen
            newPtr <- c_decrypt dataLen' dataPtr' keyPtr'
            let newPtr' = castPtr newPtr
            bs <- unsafePackCStringFinalizer newPtr' dataLen $ free newPtr'
            return $ fromMult16 bs

foreign import ccall unsafe "encrypt"
    c_encrypt :: CUInt -> Ptr CUChar -> Ptr CUChar -> IO (Ptr CUChar)

foreign import ccall unsafe "decrypt"
    c_decrypt :: CUInt -> Ptr CUChar -> Ptr CUChar -> IO (Ptr CUChar)
