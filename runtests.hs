{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}
import Test.Framework (defaultMain)
import Test.QuickCheck
import Test.Framework.Providers.QuickCheck2

import qualified Data.ByteString as S

import qualified Codec.Encryption.AES as AES
import Web.ClientSession
import System.IO.Unsafe
import Data.Word
import Control.Failure

main :: IO ()
main = defaultMain
    [ testProperty "encrypt/decrypt success" propEncDec
    , testProperty "encrypt/decrypt failure" propEncDecFailure
    , testProperty "AES encrypt/decrypt success" propAES
    , testProperty "AES encryption changes bs" propAESChanges
    ]

propEncDec :: S.ByteString -> Bool
propEncDec bs = unsafePerformIO $ do
    key <- getDefaultKey
    let s = encrypt key bs
    let bs' = decrypt key s :: Either ClientSessionException S.ByteString
    return $ Right bs == bs'

propEncDecFailure :: S.ByteString -> Bool
propEncDecFailure bs = unsafePerformIO $ do
    key <- getDefaultKey
    let s = encrypt key bs
    let bs' = decrypt key $ (head s `addChar` 1) : drop 1 s
    return $ Just bs /= bs'

propAES :: S.ByteString -> S.ByteString -> Bool
propAES key bs = AES.decrypt key (AES.encrypt key bs) == Just bs

propAESChanges :: S.ByteString -> S.ByteString -> Bool
propAESChanges key bs = AES.encrypt key bs /= bs

addChar :: Char -> Int -> Char
addChar c i = toEnum $ fromEnum c + i

instance Arbitrary S.ByteString where
    arbitrary = S.pack `fmap` arbitrary

instance Arbitrary Word8 where
    arbitrary = arbitraryBoundedIntegral

instance Failure a (Either a) where
    failure = Left
instance Monad (Either a) where
    return = Right
    Left l >>= _ = Left l
    Right r >>= f = f r
