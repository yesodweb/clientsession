{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}
import Test.Framework (defaultMain)
import Test.QuickCheck
import Test.Framework.Providers.QuickCheck2

import qualified Data.ByteString as S

import Web.ClientSession
import System.IO.Unsafe
import Data.Word

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
    let bs' = decrypt key s
    return $ Just bs == bs'

propEncDecFailure :: S.ByteString -> Bool
propEncDecFailure bs = unsafePerformIO $ do
    key <- getDefaultKey
    let s = encrypt key bs
    let bs' = decrypt key $ (S.head s + 1) `S.cons` S.drop 1 s
    return $ Just bs /= bs'

propAES :: S.ByteString -> S.ByteString -> Bool
propAES key bs = decrypt key (encrypt key bs) == Just bs

propAESChanges :: S.ByteString -> S.ByteString -> Bool
propAESChanges key bs = encrypt key bs /= bs

instance Arbitrary S.ByteString where
    arbitrary = S.pack `fmap` arbitrary

instance Arbitrary Word8 where
    arbitrary = arbitraryBoundedIntegral
