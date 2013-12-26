{-# LANGUAGE OverloadedStrings #-}
module Main where

import System.Directory (doesFileExist)

import Control.Applicative
import Control.Monad.IO.Class (liftIO)

import qualified Data.Text as T
import qualified Data.Text.Lazy as TL
import qualified Data.Text.Encoding as TE
import qualified Data.Text.IO as TIO
import qualified Data.ByteString.Char8 as BS (ByteString)

import qualified System.Console.Haskeline as HL (runInputT, defaultSettings, getInputLineWithInitial, getPassword)

import qualified Crypto.Scrypt as Scrypt

import qualified Database.SQLite.Simple as SQL

import Web.Scotty

import Web.Cookie as Cookie

--------

type Email = T.Text
type Password = T.Text
type PasswordHash = BS.ByteString

data User = User { userEmailAddress :: T.Text, userPasswordHash :: PasswordHash }

data Group = Group T.Text
data Permission = Permission T.Text deriving (Show)

--------

encryptPass :: Password -> IO PasswordHash
encryptPass = fmap Scrypt.getEncryptedPass . Scrypt.encryptPass' . Scrypt.Pass . TE.encodeUtf8

verifyPass :: Password -> PasswordHash -> Bool
verifyPass pw h = Scrypt.verifyPass' (Scrypt.Pass $ TE.encodeUtf8 pw) (Scrypt.EncryptedPass h)

--------

-- SQL helpers missing from sqlite-simple

withTransaction :: SQL.Connection -> IO a -> IO a
withTransaction conn action = do
  SQL.execute_ conn "BEGIN TRANSACTION"
  x <- action
  SQL.execute_ conn "COMMIT"
  return x

oneOrNone :: [a] -> Maybe a
oneOrNone []  = Nothing
oneOrNone [x] = Just x
oneOrNone _   = error "Expected one or none, but got more than one!"

--------
--indexes

createDatabase :: SQL.Connection -> IO ()
createDatabase conn = do
  withTransaction conn $ do
    SQL.execute_ conn "CREATE TABLE user           (email_address TEXT PRIMARY KEY, password_hash BLOB NOT NULL)"
    SQL.execute_ conn "CREATE TABLE grp            (name TEXT PRIMARY KEY)" -- annoying, "group" is a SQL keyword
    SQL.execute_ conn "CREATE TABLE user_grp       (user_email_address TEXT NOT NULL REFERENCES user (email_address), grp_name TEXT NOT NULL REFERENCES grp (name), UNIQUE (user_email_address, grp_name))"
    SQL.execute_ conn "CREATE TABLE permission     (name TEXT PRIMARY KEY)"
    SQL.execute_ conn "CREATE TABLE grp_permission (grp_name TEXT NOT NULL REFERENCES grp (name), permission_name TEXT NOT NULL REFERENCES permission (name), UNIQUE (grp_name, permission_name))"

--------

instance SQL.FromRow User where fromRow = User <$> SQL.field <*> SQL.field
instance SQL.ToRow User where toRow (User e h) = [e, h]

instance SQL.FromRow Permission where fromRow = Permission <$> SQL.field

queryUserByEmailAddress :: SQL.Connection -> Email -> IO (Maybe User)
queryUserByEmailAddress conn emailAddress = fmap oneOrNone $ SQL.query conn "SELECT email_address, password_hash FROM user WHERE email_address = ?" (SQL.Only emailAddress)

queryUserPermissions :: SQL.Connection -> Email -> IO [Permission]
queryUserPermissions conn emailAddress = SQL.query conn "SELECT grp_permission.permission_name FROM user JOIN user_grp ON (user_grp.user_email_address = user.email_address) JOIN grp_permission ON (grp_permission.grp_name = user_grp.grp_name) WHERE user.email_address = ?" (SQL.Only emailAddress)

insertUser :: SQL.Connection -> User -> IO ()
insertUser conn = SQL.execute conn "INSERT INTO user (email_address, password_hash) VALUES (?)"

--------

--authenticate :: Email -> Password -> Bool
--authenticate u p = case Map.lookup u users of
--  Nothing -> False
--  Just h  -> verifyPass p h

authenticate :: SQL.Connection -> Email -> Password -> IO Bool
authenticate conn email pass = do
  maybeUser <- queryUserByEmailAddress conn email
  return $ case maybeUser of
    Nothing -> False
    Just user -> verifyPass pass (userPasswordHash user)

createUser :: SQL.Connection -> Email -> Password -> IO Bool
createUser conn email pass = withTransaction $ do
  maybeUser <- queryUserByEmailAddress conn email
  case maybeUser of
    Just _ -> return False
    Nothing -> do
      hash <- encryptPass pass
      insertUser conn $ User email hash
      return True

--------

insertInitialData :: SQL.Connection -> IO ()
insertInitialData conn = do
  putStrLn "I need to create an initial admin user."

  adminEmail    <- runTilJust $ HL.runInputT HL.defaultSettings $ HL.getInputLineWithInitial "Email address: " ("admin", "")
  adminPassword <- runTilJust $ HL.runInputT HL.defaultSettings $ HL.getPassword (Just '*') "Password: "

  adminPasswordHash <- encryptPass $ T.pack adminPassword

  withTransaction conn $ do
    -- TODO use above fns
    SQL.execute conn "INSERT INTO user           (email_address, password_hash) VALUES (?, ?)" (TL.pack adminEmail, adminPasswordHash)
    SQL.execute conn "INSERT INTO grp            (name) VALUES (?)" (SQL.Only $ TL.pack "admin")
    SQL.execute conn "INSERT INTO user_grp       (user_email_address, grp_name) VALUES (?, ?)" (adminEmail, TL.pack "admin")
    SQL.execute conn "INSERT INTO permission     (name) VALUES (?)" (SQL.Only $ TL.pack "admin")
    SQL.execute conn "INSERT INTO grp_permission (grp_name, permission_name) VALUES (?, ?)" (TL.pack "admin", TL.pack "admin")

  putStrLn $ "Created admin user '" ++ adminEmail ++ "'."

  where
    runTilJust :: Monad m => m (Maybe a) -> m a
    runTilJust action = action >>= maybe (runTilJust action) return

prepareDb :: IO SQL.Connection
prepareDb = do
  exists <- doesFileExist dbPath
  if exists
    then SQL.open dbPath
    else do
      conn <- SQL.open dbPath

      createDatabase conn
      putStrLn "Created new database."

      insertInitialData conn

      return conn
  where dbPath = "ProjectDelta.sqlite"

-------
-- This stuff stolen from https://gist.github.com/hdgarrood/7778032

--makeCookie :: BS.ByteString -> BS.ByteString -> SetCookie
--makeCookie k v = Cookie.def { Cookie.setCookieName = k, Cookie.setCookieValue = v }

--renderSetCookie' :: SetCookie -> Text
--renderSetCookie' = T.decodeUtf8 . B.toLazyByteString . renderSetCookie

--setCookie :: BS.ByteString -> BS.ByteString -> ActionM ()
--setCookie n v = setHeader "Set-Cookie" (renderSetCookie' (makeCookie n v))

--getCookies :: ActionM (Maybe CookiesText)
--getCookies = fmap (fmap (parseCookiesText . lazyToStrict . T.encodeUtf8)) $ reqHeader "Cookie"
--  where
--    lazyToStrict = BS.concat . BSL.toChunks

--renderCookiesTable :: CookiesText -> H.Html
--renderCookiesTable cs =
--  H.table $ do
--    H.tr $ do
--      H.th "name"
--      H.th "value"
--    forM_ cs $ \(name, val) -> do
--      H.tr $ do
--        H.td (H.toMarkup name)
--        H.td (H.toMarkup val)

--------

setCookie = setHeader "Set-Cookie" "COOKIE=value2; Expires=Wed, 09 Jun 2021 10:18:14 GMT"

main :: IO ()
main = do

  putStrLn $  "########  ########   #######        ## ########  ######  ########    ########  ######## ##       ########    ###   \n" ++
              "##     ## ##     ## ##     ##       ## ##       ##    ##    ##       ##     ## ##       ##          ##      ## ##  \n" ++
              "##     ## ##     ## ##     ##       ## ##       ##          ##       ##     ## ##       ##          ##     ##   ## \n" ++
              "########  ########  ##     ##       ## ######   ##          ##       ##     ## ######   ##          ##    ##     ##\n" ++
              "##        ##   ##   ##     ## ##    ## ##       ##          ##       ##     ## ##       ##          ##    #########\n" ++
              "##        ##    ##  ##     ## ##    ## ##       ##    ##    ##       ##     ## ##       ##          ##    ##     ##\n" ++
              "##        ##     ##  #######   ######  ########  ######     ##       ########  ######## ########    ##    ##     ##\n"

  conn <- prepareDb

  let requireAdmin action = do
        email <- param "email"
        pass <- param "pass"
        passed <- liftIO $ authenticate conn email pass
        if passed
          then action
          else do
                text $ TL.concat [TL.fromStrict email, " is not in the sudoers file. This incident will be reported."]
                liftIO $ TIO.putStrLn $ T.concat ["Failed admin attempt from user identifying as '", email, "'."]

  scotty 3000 $ do
    get "/auth" $ do
      email <- param "email"
      pass <- param "pass"
      passed <- liftIO $ authenticate conn email pass
      text $ TL.pack $ show passed

    get "/list-permissions" $ requireAdmin $ do
      userEmail <- param "user-email"
      perms <- liftIO $ queryUserPermissions conn userEmail
      text $ TL.pack $ show perms

    post "/create-user" $ requireAdmin $ do
      userEmail <- param "user-email"
      userPassword <- param "user-pass"
      createUser userEmail userPassword
