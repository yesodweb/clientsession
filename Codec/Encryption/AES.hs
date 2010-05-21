{-# LANGUAGE ForeignFunctionInterface #-}
module Codec.Encryption.AES
    ( encrypt
    , decrypt
    ) where

import Data.ByteString (ByteString)
import Data.ByteString.Unsafe

import Foreign.C
import Foreign.Ptr
import Foreign.Marshal.Alloc
import Foreign.Storable
import System.IO.Unsafe

encrypt :: ByteString -- ^ key
        -> ByteString -- ^ data
        -> ByteString
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

decrypt :: ByteString -- ^ key
        -> ByteString -- ^ data
        -> Maybe ByteString
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
