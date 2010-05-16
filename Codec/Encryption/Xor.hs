{-# LANGUAGE ForeignFunctionInterface #-}
module Codec.Encryption.Xor
    ( xor
    ) where

import Data.ByteString (ByteString)
import Data.ByteString.Unsafe

import Foreign.C
import Foreign.Ptr
import Foreign.Marshal.Alloc
import System.IO.Unsafe

xor :: ByteString -- ^ key
    -> ByteString -- ^ data
    -> ByteString
xor keyBS dataBS = unsafePerformIO $ do
    unsafeUseAsCStringLen keyBS $ \(keyPtr, keyLen) ->
        unsafeUseAsCStringLen dataBS $ \(dataPtr, dataLen) -> do
            let keyLen' = fromIntegral keyLen
                keyPtr' = castPtr keyPtr
            let dataLen' = fromIntegral dataLen
                dataPtr' = castPtr dataPtr
            newPtr <- c_xor keyLen' keyPtr' dataLen' dataPtr'
            let newPtr' = castPtr newPtr
            unsafePackCStringFinalizer newPtr' dataLen $ free newPtr'

foreign import ccall unsafe "xor"
    c_xor :: CInt -> Ptr CChar -> CInt -> Ptr CChar -> IO (Ptr CChar)
