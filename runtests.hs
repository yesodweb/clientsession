{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE MultiParamTypeClasses #-}
import Test.Framework (defaultMain, testGroup, Test)
import Test.QuickCheck
import Test.Framework.Providers.QuickCheck2

import qualified Data.ByteString.Lazy as L

import Web.ClientSession
import System.IO.Unsafe
import Data.Word
import Control.Failure

main :: IO ()
main = defaultMain
    [ testProperty "encrypt/decrypt success" caseEncDec
    , testProperty "encrypt/decrypt failure" caseEncDecFailure
    ]

caseEncDec :: L.ByteString -> Bool
caseEncDec bs = unsafePerformIO $ do
    key <- getDefaultKey
    s <- encrypt key bs
    let bs' = decrypt key s :: Either ClientSessionException L.ByteString
    print bs'
    return $ Right bs == bs'

caseEncDecFailure :: L.ByteString -> Bool
caseEncDecFailure bs = unsafePerformIO $ do
    key <- getDefaultKey
    s <- encrypt key bs
    let bs' = decrypt key $ 'x' : s
    return $ Just bs /= bs'

instance Arbitrary L.ByteString where
    arbitrary = L.pack `fmap` arbitrary

instance Arbitrary Word8 where
    arbitrary = arbitraryBoundedIntegral

instance Failure a (Either a) where
    failure = Left
instance Monad (Either a) where
    return = Right
    Left l >>= f = Left l
    Right r >>= f = f r
