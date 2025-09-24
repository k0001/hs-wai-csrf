-- | This module exports tool to prevent cross-site request forgeries in
-- "Network.Wai". Consider using it in combination with "Wai.CryptoCookie".
module Wai.CSRF
   ( Config (..)
   , defaultConfig
   , tokenFromRequestHeader
   , tokenFromRequestCookie
   , setCookie
   , expireCookie
   , middleware

    -- * Token
   , Token (..)
   , randomToken
   , tokenToBase64UU
   , tokenFromBase64UU

    -- * Masked token
   , MaskedToken (..)
   , maskedTokenToBase64UU
   , maskedTokenFromBase64UU
   , maskToken
   , unmaskToken
   ) where

import Crypto.Random qualified as C
import Data.ByteArray qualified as BA
import Data.ByteArray.Encoding qualified as BA
import Data.ByteArray.Sized qualified as BAS
import Data.ByteString qualified as B
import Data.CaseInsensitive qualified as CI
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

--------------------------------------------------------------------------------

-- | If you embed a 'Token' as is in a response body when HTTP body compression
-- is enabled, it is possible for a malicious actor to recover the 'Token'
-- through a /BREACH/ attack or similar. In order to prevent that, send a
-- different 'MaskedToken' (generated with 'randomMaskedToken') each time
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

-- | @'fromMaskedToken' '<$>' 'randomMaskedToken' tok@ and @'pure' tok@ produce
-- the same output @tok@.
maskToken :: (C.MonadRandom m) => Token -> m MaskedToken
maskToken t = flip toMaskedToken t <$> randomMask

-- | @'fromMaskedToken' '<$>' 'randomMaskedToken' tok@ and @'pure' tok@ produce
-- the same output @tok@.
unmaskToken :: MaskedToken -> Token
unmaskToken = snd . fromMaskedToken

--------------------------------------------------------------------------------

-- | Config common to 'middleware', 'tokenFromRequestHeader' and
-- 'tokenFromRequestCookie'.
--
-- Consider using 'defaultConfig' and updating desired fields only.
data Config = Config
   { cookieName :: B.ByteString
   -- ^ Used by 'tokenFromRequestCookie', 'setCookie', 'expireCookie' and
   -- 'middleware'.
   , headerName :: B.ByteString
   -- ^ Used by 'tokenFromRequestHeader' and 'middleware'.
   , reject
      :: Token
      -> Maybe Token
      -> Wai.Request
      -> (Wai.Response -> IO Wai.ResponseReceived)
      -> Maybe (IO Wai.ResponseReceived)
   -- ^ Used by 'middleware'. This function is called if either there is no
   -- 'Token' in the expected request header (see 'Config'\'s @headerName@), or
   -- if there is a 'Token' in said header, but it is different from the
   -- 'Token' that came through a request cookie (see 'Config'\'s
   -- @cookieName@).
   --
   -- If this function produces 'Nothing', then the underlying
   -- 'Wai.Application' will be executed normally, if 'Just', then the
   -- 'Wai.Response' (which should probably have status 'H.forbidden403'), will
   -- be returned immediately.
   --
   -- The 'Token' parameter is the one that came through the cookie, and the
   -- @'Maybe' 'Token'@ parameter is the one that came through the header, if
   -- any.
   --
   -- Notice that if the token comes through the request body (see
   -- 'MaskedToken'), then it is sometimes best not to reject the request here,
   -- and instead check and potentially reject the request downstream, so as to
   -- preserve the streaming nature of processing the request body.
   }

-- | Default CSRF settings.
--
-- * Cookie name is @CSRF-TOKEN@.
--
-- * Header name is @X-CSRF-TOKEN@.
--
-- * Reject with 'H.forbidden403' all request who are neither @GET@, @HEAD@,
-- @OPTIONS@ nor @TRACE@, unless the 'Token' is present in both cookie and
-- header and they are equal.
defaultConfig :: Config
defaultConfig =
   Config
      { cookieName = "CSRF-TOKEN"
      , headerName = "X-CSRF-TOKEN"
      , reject = \_ct yht req respond -> case yht of
         Nothing | isGHOT req -> Nothing
         _ -> Just $ respond $ Wai.responseLBS H.forbidden403 [] "CSRF"
      }
  where
   isGHOT :: Wai.Request -> Bool
   isGHOT req =
      Wai.requestMethod req == H.methodGet
         || Wai.requestMethod req == H.methodHead
         || Wai.requestMethod req == H.methodOptions
         || Wai.requestMethod req == H.methodTrace

-- | Obtain the 'Token' from the 'Wai.Request' headers.
--
-- You don't need to use this if you are using 'middleware'.
tokenFromRequestHeader :: Config -> Wai.Request -> Maybe Token
tokenFromRequestHeader c = \r -> do
   [t64] <- pure $ lookupMany n $ Wai.requestHeaders r
   tokenFromBase64UU t64
  where
   n = CI.mk c.headerName

-- | Obtain the 'Token' from the 'Wai.Request' cookies.
--
-- You don't need to use this if you are using 'middleware'.
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

-- | Construct a 'Wai.Middleware' (almost) that does the following:
--
-- 1. Try to find the CSRF 'Token' among the incoming 'Wai.Request' cookies
-- (see 'Config'\'s @cookieName@), and headers
-- (see 'Config'\'s @headerName@).
--
-- 2. Accept requests where there is no 'Token' in the cookies, or where
-- there is a 'Token' in both the cookie and the header and they are equal.
--
-- 3. If the request wasn't readily accepted, use 'Config'\'s @reject@ to
-- decide if the incoming 'Wai.Request' should be rejected.
--
-- 3. If the 'Wai.Request' wasn't rejected, we pass the 'Token' found in the
-- cookie, if any, to the underlying 'Wai.Application'.
--
-- Important: This doesn't set any cookie. You must explicitly add
-- 'setCookie' to a 'Wai.Response' yourself.
middleware
   :: Config
   -> (Maybe Token -> Wai.Application)
   -> Wai.Application
middleware c = \fapp req respond -> do
   let yct = fyct req
       yht = fyht req
       accept = fapp yct req respond
   case yct of
      Nothing -> accept
      Just ct | yrej <- c.reject ct yht req respond ->
         case yht of
            Nothing -> maybe accept id yrej
            Just ht
               | ct == ht -> accept
               | otherwise -> maybe accept id yrej
  where
   fyct = tokenFromRequestCookie c
   fyht = tokenFromRequestHeader c

--------------------------------------------------------------------------------

requestCookies :: Wai.Request -> [(B.ByteString, B.ByteString)]
requestCookies r = C.parseCookies =<< lookupMany "Cookie" (Wai.requestHeaders r)

lookupMany :: (Eq k) => k -> [(k, v)] -> [v]
lookupMany k = findMany (== k)

findMany :: (Eq k) => (k -> Bool) -> [(k, v)] -> [v]
findMany f = map snd . filter (\(a, _) -> f a)
