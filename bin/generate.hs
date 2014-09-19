module Main where

import Data.Maybe (fromMaybe, listToMaybe)
import Control.Monad (void)
import System.Environment (getArgs)
import Web.ClientSession (randomKeyEnv)

main :: IO ()
main = void $ randomKeyEnv . fromMaybe "SESSION_KEY" . listToMaybe =<< getArgs
