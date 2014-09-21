module System.LookupEnv (lookupEnv) where

import System.Environment (getEnvironment)

lookupEnv :: String -> IO (Maybe String)
lookupEnv envVar = fmap (lookup envVar) $ getEnvironment
