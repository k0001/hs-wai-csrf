-- | This module exports tool to prevent cross-site request forgeries in
-- "Network.Wai". Consider using it in combination with "Wai.CryptoCookie".
module Wai.CSRF
   ( Config (..)
   , defaultConfig
   , tokenFromRequestHeader
   , tokenFromRequestCookie
   , setCookie
   , expireCookie
   , middlewareReject

    -- * Token
   , Token (..)
   , randomToken
   , tokenToBase64UU
   , tokenFromBase64UU

    -- * Masked token
   , MaskedToken (..)
   , maskedTokenToBase64UU
   , maskedTokenFromBase64UU
   , randomMaskToken
   , unmaskToken
   ) where

import Control.Monad
import Crypto.Random qualified as C
import Data.Aeson qualified as Ae
import Data.ByteArray qualified as BA
import Data.ByteArray.Encoding qualified as BA
import Data.ByteArray.Sized qualified as BAS
import Data.ByteString qualified as B
import Data.CaseInsensitive qualified as CI
import Data.Text.Encoding qualified as T
import Data.Time.Clock.POSIX qualified as Time
import Network.HTTP.Types qualified as H
import Network.Wai qualified as Wai
import Web.Cookie qualified as C

--------------------------------------------------------------------------------

-- | CSRF token.
--
-- * It is safe to send and receive the 'Token' through HTTP cookies and
-- headers.
--
-- * If you need to send or receive the 'Token' as part of the request or
-- response body, use 'MaskedToken' instead.
newtype Token = Token (BAS.SizedByteArray 32 B.ByteString)

instance Show Token where
   showsPrec n (Token s) = showsPrec n $ BAS.unSizedByteArray s

instance Eq Token where
   Token a == Token b = BA.constEq a b

-- | A CSRF token is just random 32 bytes. Its meaning and validity depends on
-- how and whether you tie it to a user session.
randomToken :: (C.MonadRandom m) => m Token
randomToken = fmap (Token . BAS.unsafeSizedByteArray) (C.getRandomBytes 32)

-- | @'tokenFromBase64UU' . 'tokenToBase64UU'  ==  'Just'@
tokenToBase64UU :: Token -> B.ByteString
tokenToBase64UU (Token t) =
   BA.convertToBase BA.Base64URLUnpadded t

-- | @'tokenFromBase64UU' . 'tokenToBase64UU'  ==  'Just'@
tokenFromBase64UU :: B.ByteString -> Maybe Token
tokenFromBase64UU b =
   case BA.convertFromBase BA.Base64URLUnpadded b of
      Right (x :: BA.Bytes) -> Token <$> BAS.fromByteArrayAccess x
      _ -> Nothing

-- | Uses 'tokenToBase64UU'.
instance Ae.ToJSON Token where
   toJSON = Ae.toJSON . T.decodeUtf8 . tokenToBase64UU

-- | Uses 'tokenFromBase64UU'.
instance Ae.FromJSON Token where
   parseJSON =
      Ae.withText
         "Wai.CSRF.Token"
         (maybe mzero pure . tokenFromBase64UU . T.encodeUtf8)

--------------------------------------------------------------------------------

-- | If you embed a 'Token' as is in a response body when HTTP body compression
-- is enabled, it is possible for a malicious actor to recover the 'Token'
-- through a /BREACH/ attack or similar. In order to prevent that, send a
-- different 'MaskedToken' (generated with 'randomMaskToken') each time
-- instead.
newtype MaskedToken = MaskedToken (BAS.SizedByteArray 64 BA.Bytes)

instance Show MaskedToken where
   showsPrec n (MaskedToken s) = showsPrec n $ BAS.unSizedByteArray s

instance Eq MaskedToken where
   MaskedToken a == MaskedToken b = BA.constEq a b

toMaskedToken :: Mask -> Token -> MaskedToken
toMaskedToken (Mask m) (Token s) =
   let x = BAS.xor m s
   in  MaskedToken $! BAS.append m (x `asTypeOf` m)

fromMaskedToken :: MaskedToken -> (Mask, Token)
fromMaskedToken (MaskedToken t) =
   let (m, x) = BAS.splitAt t
   in  (Mask m, Token $! BAS.xor m (x `asTypeOf` m))

-- | @'maskedTokenFromBase64UU' . 'maskedTokenToBase64UU'  ==  'Just'@
maskedTokenToBase64UU :: MaskedToken -> B.ByteString
maskedTokenToBase64UU (MaskedToken t) = BA.convertToBase BA.Base64URLUnpadded t

-- | @'maskedTokenFromBase64UU' . 'maskedTokenToBase64UU'  ==  'Just'@
maskedTokenFromBase64UU :: B.ByteString -> Maybe MaskedToken
maskedTokenFromBase64UU b = case BA.convertFromBase BA.Base64URLUnpadded b of
   Right (x :: BA.Bytes) -> MaskedToken <$> BAS.fromByteArrayAccess x
   _ -> Nothing

-- | See 'MaskedToken'.
newtype Mask = Mask (BAS.SizedByteArray 32 BA.Bytes)

instance Show Mask where
   showsPrec n (Mask s) = showsPrec n $ BAS.unSizedByteArray s

instance Eq Mask where
   Mask a == Mask b = BA.constEq a b

randomMask :: (C.MonadRandom m) => m Mask
randomMask = fmap (Mask . BAS.unsafeSizedByteArray) (C.getRandomBytes 32)

-- | @'unmaskToken' '<$>' 'randomMaskToken' tok@ and @'pure' tok@ produce
-- the same output @tok@.
randomMaskToken :: (C.MonadRandom m) => Token -> m MaskedToken
randomMaskToken t = flip toMaskedToken t <$> randomMask

-- | @'unmaskToken' '<$>' 'randomMaskToken' tok@ and @'pure' tok@ produce
-- the same output @tok@.
unmaskToken :: MaskedToken -> Token
unmaskToken = snd . fromMaskedToken

-- | Uses 'maskedTokenToBase64UU'.
instance Ae.ToJSON MaskedToken where
   toJSON = Ae.toJSON . T.decodeUtf8 . maskedTokenToBase64UU

-- | Uses 'maskedTokenFromBase64UU'.
instance Ae.FromJSON MaskedToken where
   parseJSON =
      Ae.withText
         "Wai.CSRF.MaskedToken"
         (maybe mzero pure . maskedTokenFromBase64UU . T.encodeUtf8)

--------------------------------------------------------------------------------

-- | Consider using 'defaultConfig' and updating desired fields only.
data Config = Config
   { cookieName :: B.ByteString
   , headerName :: B.ByteString
   }

-- | Default CSRF settings.
--
-- * Cookie name is @__Host-CSRF-TOKEN@.
--
-- * Header name is @X-CSRF-TOKEN@.
defaultConfig :: Config
defaultConfig =
   Config
      { cookieName = "__Host-CSRF-TOKEN"
      , headerName = "X-CSRF-TOKEN"
      }

-- | Obtain the 'Token' from the 'Wai.Request' headers.
--
-- Warning: Do not rely on this 'Token' unless it is equal to the one returned
-- by 'tokenFromRequestCookie'.
tokenFromRequestHeader :: Config -> Wai.Request -> Maybe Token
tokenFromRequestHeader c = \r -> do
   [t64] <- pure $ lookupMany n $ Wai.requestHeaders r
   tokenFromBase64UU t64
  where
   n = CI.mk c.headerName

-- | Obtain the 'Token' from the 'Wai.Request' cookies.
tokenFromRequestCookie :: Config -> Wai.Request -> Maybe Token
tokenFromRequestCookie c r = do
   [t64] <- pure $ lookupMany c.cookieName $ requestCookies r
   tokenFromBase64UU t64

-- | Construct a 'C.SetCookie' to set the CSRF 'Token'.
--
-- The 'C.SetCookie' has these settings, some of which could be overriden.
--
--      * Cookie name is 'Config'\'s @cookieName@.
--
--      * @HttpOnly@: No, and you shouldn't change this.
--
--      * @Max-Age@ and @Expires@: This cookie never expires. We recommend
--      relying on server-side expiration instead, as the lifetime of the
--      cookie could easily be extended by a legitimate but malicious client.
--      It is recommended that you rotate the 'Token' each time a new user
--      session is established.
--
--      * @Path@: @\/@
--
--      * @SameSite@: @Lax@.
--
--      * @Secure@: Yes.
--
--      * @Domain@: Not set.
setCookie :: Config -> Token -> C.SetCookie
setCookie c tok =
   (expireCookie c)
      { C.setCookieValue = tokenToBase64UU tok
      , C.setCookieExpires = Nothing
      , C.setCookieMaxAge = Nothing
      }

-- | Construct a 'C.SetCookie' expiring the cookie named 'Config'\'s
-- @cookieName@.
expireCookie :: Config -> C.SetCookie
expireCookie c =
   C.defaultSetCookie
      { C.setCookieName = c.cookieName
      , C.setCookieValue = ""
      , C.setCookieDomain = Nothing
      , C.setCookieExpires = Just (Time.posixSecondsToUTCTime 0)
      , C.setCookieHttpOnly = False
      , C.setCookieMaxAge = Just (negate 1)
      , C.setCookiePath = Just "/"
      , C.setCookieSameSite = Just C.sameSiteLax
      , C.setCookieSecure = True
      }

-- | Rejects the request with @403 Forbidden@, except in these situations:
--
-- * When there is no 'tokenFromRequestCookie'.
--
-- * When there is a 'tokenFromRequestCookie', there is no
-- 'tokenFromRequestHeader', and the request method is @GET@, @HEAD@,
-- @OPTIONS@, @TRACE@.
--
-- * When there is a 'tokenFromRequestCookie' and a matching
-- 'tokenFromRequestHeader'.
--
-- Important: This doesn't set any cookie. You must explicitly add
-- 'setCookie' to a 'Wai.Response' yourself.
middlewareReject :: Config -> Wai.Middleware
middlewareReject c = \app -> \req k -> case (fytc req, fyth req) of
   (Nothing, _) -> app req k
   (Just _, Nothing) | elem (Wai.requestMethod req) safeMethods -> app req k
   (Just tc, Just th) | tc == th -> app req k
   _ -> k response403
  where
   fytc = tokenFromRequestCookie c
   fyth = tokenFromRequestHeader c

safeMethods :: [H.Method]
safeMethods = [H.methodGet, H.methodHead, H.methodOptions, H.methodTrace]

response403 :: Wai.Response
response403 =
   Wai.responseLBS
      H.status403
      [("Content-Type", "text/plain;charset=utf-8")]
      "403 Forbidden"

--------------------------------------------------------------------------------

requestCookies :: Wai.Request -> [(B.ByteString, B.ByteString)]
requestCookies r = C.parseCookies =<< lookupMany "Cookie" (Wai.requestHeaders r)

lookupMany :: (Eq k) => k -> [(k, v)] -> [v]
lookupMany k = findMany (== k)

findMany :: (Eq k) => (k -> Bool) -> [(k, v)] -> [v]
findMany f = map snd . filter (\(a, _) -> f a)
