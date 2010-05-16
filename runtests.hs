{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE MultiParamTypeClasses #-}
import Test.Framework (defaultMain, testGroup, Test)
import Test.QuickCheck
import Test.Framework.Providers.QuickCheck2

import qualified Data.ByteString.Lazy as L
import qualified Data.ByteString as S

import Web.ClientSession
import System.IO.Unsafe
import Data.Word
import Control.Failure

main :: IO ()
main = defaultMain
    [ testProperty "encrypt/decrypt success" caseEncDec
    , testProperty "encrypt/decrypt failure" caseEncDecFailure
    ]

caseEncDec :: S.ByteString -> Bool
caseEncDec bs = unsafePerformIO $ do
    key <- getDefaultKey
    let s = encrypt key bs
    let bs' = decrypt key s :: Either ClientSessionException S.ByteString
    return $ Right bs == bs'

caseEncDecFailure :: S.ByteString -> Bool
caseEncDecFailure bs = unsafePerformIO $ do
    key <- getDefaultKey
    let s = encrypt key bs
    let bs' = decrypt key $ (head s `addChar` 1) : drop 1 s
    return $ Just bs /= bs'

addChar c i = toEnum $ fromEnum c + i

instance Arbitrary S.ByteString where
    arbitrary = S.pack `fmap` arbitrary

instance Arbitrary Word8 where
    arbitrary = arbitraryBoundedIntegral

instance Failure a (Either a) where
    failure = Left
instance Monad (Either a) where
    return = Right
    Left l >>= f = Left l
    Right r >>= f = f r
