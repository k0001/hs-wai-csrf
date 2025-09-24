{-# LANGUAGE RecordWildCards #-}

module Main (main) where

import Control.Exception qualified as Ex
import Control.Monad
import Control.Monad.IO.Class
import Data.ByteString qualified as B
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
   testReject
   putStrLn "TESTS OK"

testReject :: IO ()
testReject = do
   tok1 <- WCC.randomToken
   let sc1 = WCC.setCookie WCC.defaultConfig tok1
       app = WCC.middleware WCC.defaultConfig \yt _ respond ->
         respond $
            W.responseLBS HT.status200 [] $
               fromString (show (yt == Just tok1))

   tok2 <- WCC.randomToken
   let sc2 = WCC.setCookie WCC.defaultConfig tok2

   WT.withSession app do
      -- Make sure the cookie is set
      WT.assertNoClientCookieExists "t0-a" "CSRF-TOKEN"
      WT.setClientCookie sc1

      -- Request succeeds because it is GET
      sres1 <- WT.request WT.defaultRequest
      WT.assertStatus 200 sres1
      WT.assertBody "True" sres1
      WT.assertClientCookieExists "t0-b" "CSRF-TOKEN"

      -- Request fails because it is POST and there is no CSRF header
      sres2 <- WT.request WT.defaultRequest{W.requestMethod = HT.methodPost}
      WT.assertStatus 403 sres2
      WT.assertBody "CSRF" sres2

      -- Request succeeds because it is POST and there is matching CSRF header
      sres3 <-
         WT.request
            WT.defaultRequest
               { W.requestMethod = HT.methodPost
               , W.requestHeaders = [("X-CSRF-TOKEN", WC.setCookieValue sc1)]
               }
      WT.assertStatus 200 sres3
      WT.assertBody "True" sres3

      -- Request fails there the request header doensn't match, even if GET.
      sres4 <- do
         WT.request
            WT.defaultRequest
               { W.requestHeaders = [("X-CSRF-TOKEN", WC.setCookieValue sc2)]
               }
      WT.assertStatus 403 sres4
      WT.assertBody "CSRF" sres4

      -- Request fails because it is POST, but there is no matching request header
      sres5 <- do
         WT.request
            WT.defaultRequest
               { W.requestMethod = HT.methodPost
               , W.requestHeaders = [("X-CSRF-TOKEN", WC.setCookieValue sc2)]
               }
      WT.assertStatus 403 sres5
      WT.assertBody "CSRF" sres5

testToken :: IO ()
testToken = do
   t0 <- WCC.randomToken
   t1 <- WCC.randomToken
   when (t0 == t1) $ fail "e0"

   mt0 <- WCC.maskToken t0
   mt1 <- WCC.maskToken t0
   when (mt0 == mt1) $ fail "e1"

   when (WCC.unmaskToken mt0 /= t0) $ fail "e3"

   let mt064 = WCC.maskedTokenToBase64UU mt0
   when (WCC.maskedTokenFromBase64UU mt064 /= Just mt0) $ fail "e4"

testCookies :: IO ()
testCookies = do
   let c = WCC.defaultConfig

   let fapp1 :: (Maybe WCC.Token -> Maybe (Maybe WCC.Token)) -> W.Application
       fapp1 = \g -> WCC.middleware c (app1 c g)

   -- keeping cookies untouched
   WT.withSession (fapp1 \_ -> Nothing) do
      WT.assertNoClientCookieExists "t0-a" "CSRF-TOKEN"
      sres1 <- WT.request WT.defaultRequest
      WT.assertBody "Nothing" sres1
      WT.assertNoClientCookieExists "t0-b" "CSRF-TOKEN"
      sres1 <- WT.request WT.defaultRequest
      WT.assertBody "Nothing" sres1
      WT.assertNoClientCookieExists "t0-c" "CSRF-TOKEN"

   -- explicitly deleting cookie
   WT.withSession (fapp1 \_ -> Just Nothing) do
      WT.assertNoClientCookieExists "t1-a" "CSRF-TOKEN"
      sres1 <- WT.request WT.defaultRequest
      WT.assertBody "Nothing" sres1
      WT.assertClientCookieExists "t1-b" "CSRF-TOKEN"
      sres1 <- WT.request WT.defaultRequest
      WT.assertBody "Nothing" sres1
      WT.assertClientCookieExists "t1-c" "CSRF-TOKEN"

   -- explicitely setting cookie
   tok1 <- WCC.randomToken
   ck0 <- WT.withSession (fapp1 \_ -> Just (Just tok1)) do
      WT.assertNoClientCookieExists "t2-a" "CSRF-TOKEN"
      sres1 <- WT.request WT.defaultRequest
      WT.assertBody "Nothing" sres1
      WT.assertClientCookieExists "t2-b" "CSRF-TOKEN"
      sres2 <- WT.request WT.defaultRequest
      WT.assertBody (fromString (show (Just tok1))) sres2
      WT.assertClientCookieExists "t2-c" "CSRF-TOKEN"
      WT.getClientCookies

   -- modify and explicitly delete
   WT.withSession (fapp1 \_ -> Just Nothing) do
      WT.assertNoClientCookieExists "t3-a" "CSRF-TOKEN"
      WT.modifyClientCookies \_ -> ck0
      WT.assertClientCookieExists "t3-b" "CSRF-TOKEN"
      sres1 <- WT.request WT.defaultRequest
      WT.assertBody (fromString (show (Just tok1))) sres1
      WT.assertClientCookieExists "t3-c" "CSRF-TOKEN"
      sres2 <- WT.request WT.defaultRequest
      WT.assertBody "Nothing" sres2
      WT.assertClientCookieExists "t3-d" "CSRF-TOKEN"
      WT.assertClientCookieValue "t3-e" "CSRF-TOKEN" ""

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
