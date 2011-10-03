import qualified Data.ByteString as B
import Web.ClientSession
import Data.Maybe
import Data.Serialize

import Criterion.Main
import Text.Printf

Right key = initKey (B.replicate 96 0xFE)
Just iv = mkIV (B.replicate 16 0xB0)

main :: IO ()
main =
  defaultMain
    [ bgroup "encrypt then decrypt"
        [ bench (printf "Message length = %d bytes" len) $
          whnf (fromJust . decrypt key . encrypt key iv) (B.replicate len 0xAA)
        | len <- [0, 50, 100, 400, 2000, 80000]]
    ]
