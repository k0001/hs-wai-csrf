{-# LANGUAGE RecordWildCards #-}

module Main (main) where

import Control.Exception qualified as Ex
import Control.Monad
import Control.Monad.IO.Class
import Data.ByteString qualified as B
import Data.CaseInsensitive qualified as CI
import Data.Map.Strict qualified as Map
import Data.Maybe
import Data.String
import Network.HTTP.Types qualified as HT
import Network.Wai qualified as W
import Network.Wai.Test qualified as WT
import Web.Cookie qualified as WC

import Wai.CSRF qualified as WCC

main :: IO ()
main = do
   testToken
   testCookies
   putStrLn "TESTS OK"

testToken :: IO ()
testToken = do
   t0 <- WCC.randomToken
   t1 <- WCC.randomToken
   when (t0 == t1) $ fail "e0"

   mt0 <- WCC.randomMaskToken t0
   mt1 <- WCC.randomMaskToken t0
   when (mt0 == mt1) $ fail "e1"

   when (WCC.unmaskToken mt0 /= t0) $ fail "e3"

   let mt064 = WCC.maskedTokenToBase64UU mt0
   when (WCC.maskedTokenFromBase64UU mt064 /= Just mt0) $ fail "e4"

testCookies :: IO ()
testCookies = do
   let c = WCC.defaultConfig

   let fapp1
         :: (Maybe WCC.Token -> Maybe (Maybe WCC.Token))
         -> W.Application
       fapp1 = WCC.middleware c . app1 c

   -- keeping cookies untouched
   WT.withSession (fapp1 \_ -> Nothing) do
      WT.assertNoClientCookieExists "t0-a" c.cookieName
      sres1 <- WT.request WT.defaultRequest
      WT.assertBody "Nothing" sres1
      WT.assertNoClientCookieExists "t0-b" c.cookieName
      sres1 <- WT.request WT.defaultRequest
      WT.assertBody "Nothing" sres1
      WT.assertNoClientCookieExists "t0-c" c.cookieName

   -- explicitly deleting cookie
   WT.withSession (fapp1 \_ -> Just Nothing) do
      WT.assertNoClientCookieExists "t1-a" c.cookieName
      sres1 <- WT.request WT.defaultRequest
      WT.assertBody "Nothing" sres1
      WT.assertClientCookieExists "t1-b" c.cookieName
      sres1 <- WT.request WT.defaultRequest
      WT.assertBody "Nothing" sres1
      WT.assertClientCookieExists "t1-c" c.cookieName

   -- explicitely setting cookie
   tok1 <- WCC.randomToken
   ck0 <- WT.withSession (fapp1 \_ -> Just (Just tok1)) do
      WT.assertNoClientCookieExists "t2-a" c.cookieName
      sres1 <- WT.request WT.defaultRequest
      WT.assertBody "Nothing" sres1
      WT.assertClientCookieExists "t2-b" c.cookieName
      Just t1 <- Map.lookup c.cookieName <$> WT.getClientCookies
      sres2 <- WT.request $ addHeader c (WC.setCookieValue t1) WT.defaultRequest
      WT.assertBody (fromString (show (Just tok1))) sres2
      WT.assertClientCookieExists "t2-c" c.cookieName
      WT.getClientCookies

   -- modify and explicitly delete
   WT.withSession (fapp1 \_ -> Just Nothing) do
      WT.assertNoClientCookieExists "t3-a" c.cookieName
      WT.modifyClientCookies \_ -> ck0
      WT.assertClientCookieExists "t3-b" c.cookieName
      Just t1 <- Map.lookup c.cookieName <$> WT.getClientCookies
      sres1 <- WT.request $ addHeader c (WC.setCookieValue t1) WT.defaultRequest
      WT.assertBody (fromString (show (Just tok1))) sres1
      WT.assertClientCookieExists "t3-c" c.cookieName
      sres2 <- WT.request WT.defaultRequest
      WT.assertBody "Nothing" sres2
      WT.assertClientCookieExists "t3-d" c.cookieName
      WT.assertClientCookieValue "t3-e" c.cookieName ""

addHeader :: WCC.Config -> B.ByteString -> W.Request -> W.Request
addHeader c t r = r{W.requestHeaders = [(CI.mk c.headerName, t)]}

app1
   :: WCC.Config
   -> (Maybe WCC.Token -> Maybe (Maybe WCC.Token))
   -> Maybe WCC.Token
   -> W.Application
app1 c g yold = \req respond -> do
   let ysc :: Maybe WC.SetCookie =
         case g yold of
            Nothing -> Nothing
            Just Nothing -> Just $ WCC.expireCookie c
            Just (Just new) -> Just $ WCC.setCookie c new
   respond
      $ W.responseLBS
         HT.status200
         ( fmap
            (\sc -> ("Set-Cookie", WC.renderSetCookieBS sc))
            (maybeToList ysc)
         )
      $ fromString (show yold)
