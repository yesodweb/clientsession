{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}
import Test.Framework (defaultMain)
import Test.QuickCheck
import Test.Framework.Providers.QuickCheck2
import Test.Framework.Providers.HUnit
import Test.HUnit

import qualified Data.ByteString as S
import qualified Data.ByteString.Char8 as S8

import Web.ClientSession
import System.IO.Unsafe
import qualified Data.Ascii as A

main :: IO ()
main = defaultMain
    [ testProperty "encrypt/decrypt success" propEncDec
    , testProperty "encrypt/decrypt failure" propEncDecFailure
    , testProperty "AES encrypt/decrypt success" propAES
    , testProperty "AES encryption changes bs" propAESChanges
    , testCase "specific values" caseSpecific
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
    let s = A.toByteString $ encrypt key bs
    let bs' = decrypt key $ A.unsafeFromByteString $ (S.head s + 1) `S.cons` S.drop 1 s
    return $ Just bs /= bs'

propAES :: S.ByteString -> S.ByteString -> Bool
propAES key bs = decrypt key (encrypt key bs) == Just bs

propAESChanges :: S.ByteString -> S.ByteString -> Bool
propAESChanges key bs = A.toByteString (encrypt key bs) /= bs

caseSpecific :: Assertion
caseSpecific = do
    let s = S8.pack $ show [("lo\ENQ\143XAq","\DC2\207\226\DC1;.z56|\203\222"),("\USnu#\139\ETXB\201 ","l"),("\RS\b,zM2U\184\191F)\EOT\220S\NUL","O\\\GSd\247\246\n\EOT\SYN\182U2G"),("\219\NAK\217\CAN\252","ym\STX\188\232?\\\145"),("\239k","\vRZP\a\DC2F>"),("\FS\180P &\RS\174zSL\\?@","p\170\237vZ|\GS>\SYNk\176n\r"),("","\199D\DC3\200m)"),("6\152tVhB\246)9","\ENQdfU\SUB"),("I\ACK\181\NUL","\129\&6s\130q\US)oR1\197\FSp\US\SYN0"),("\183\200<\250","\211  \131g4\207N\155"),("\248O6k\CANK\135\234.","`\205!+&Z&9\DLE\244\214HP\SI\161"),("\"I'\ACK\149 \CAN\197","\141N\201\SO\204\\o.\128\148")]
    key <- getDefaultKey
    Just s @=? decrypt key (encrypt key s)
    let s' = S.concat $ replicate 500 s
    Just s' @=? decrypt key (encrypt key s')

instance Arbitrary S.ByteString where
    arbitrary = S.pack `fmap` arbitrary
