package tigase.db.custom;

import org.redisson.Redisson;
import org.redisson.api.RBucket;
import org.redisson.api.RedissonClient;
import org.redisson.config.Config;
import tigase.auth.credentials.Credentials;
import tigase.db.*;
import tigase.kernel.beans.config.ConfigField;
import tigase.xmpp.jid.BareJID;

import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

@Repository.Meta(isDefault = true, supportedUris = {"mongodb:.*"})
@Repository.SchemaId(id = Schema.SERVER_SCHEMA_ID, name = Schema.SERVER_SCHEMA_NAME)
public class RedisAuthProvider implements AuthRepository {

    protected static final String[] non_sasl_mechs = {"password"};
    protected static final String[] sasl_mechs = {"PLAIN"};

    private static final Logger log = Logger.getLogger(RedisAuthProvider.class.getName());

    @ConfigField(desc = "Redis resource url", alias = "data-source")
    private String datasource;

    @Override
    public Credentials getCredentials(BareJID user, String credentialId) throws TigaseDBException {

        logger("Getting Credentials");

        Credentials.Entry entry = new Credentials.Entry() {
            @Override
            public String getMechanism() {
                return "PLAIN";
            }

            @Override
            public boolean verifyPlainPassword(String plain) {
                try {
                    logger("Plain Check [from client] : " + plain);

                    String userid = getUserInfoByToken(plain);
                    logger(user.getLocalpart() + " ---- " + userid);

                    return user.getLocalpart().equals(userid);
                } catch (Exception ex) {
                    log.log(Level.WARNING, "Can''t authenticate user", ex);
                }
                return false;
            }
        };
        return new SingleCredential(user, getAccountStatus(user), entry);
    }

    public static void main(String args[]){
        RedisAuthProvider provider = new RedisAuthProvider();
        provider.getUserInfoByToken("Hello");
    }

    private String getUserInfoByToken(String plain) {
        try {
            logger("Redis " + datasource);
            Config config = new Config();

            config.useSingleServer()
                    .setAddress(datasource)
                    .setPassword("eliao@123.")
                    .setDatabase(1);     //redis://arbitrary_usrname:password@ipaddress:6379/0

            String authToken = "oauth:tigase:%s";

            RedissonClient client = Redisson.create(config);

            RBucket<String> userId = client.getBucket(String.format(authToken, plain));

            logger("Cached user : " + userId);
            logger("Is exists : " + userId.isExists());

            return userId.isExists() ? userId.get() : "";

        } catch (Exception ex){
            log.log(Level.WARNING, "Error in getting token:", ex);
        }
        return "";
    }

    @Override
    public void addUser(BareJID user, String password) throws TigaseDBException {
        logger("Adding User");
        throw new TigaseDBException("Not available");
    }

    @Override
    public AccountStatus getAccountStatus(BareJID user) throws TigaseDBException {
        logger("Getting User Status");
        return AccountStatus.active;
    }

    @Override
    public String getPassword(BareJID user) throws TigaseDBException {
        logger("Getting Password");
        throw new TigaseDBException("Not Available");
    }

    private void logger(String message) {
        String prefix = "#################     ";
        log.log(Level.INFO, prefix + message);
        System.err.println( prefix + message);
    }

    @Override
    public String getResourceUri() {
        logger("Getting Resource Uri");
        return null;
    }

    @Override
    public long getUsersCount() {
        logger("Get User count");
        return -1;
    }

    @Override
    public long getUsersCount(String domain) {
        logger("Get Users count domain");
        return -1;
    }

    @Override
    public void loggedIn(BareJID jid) throws TigaseDBException {
        logger("Logged In");
    }

    @Override
    public void logout(BareJID user) throws TigaseDBException {
        logger("Logged out");
    }

    @Override
    public boolean otherAuth(Map<String, Object> authProps) throws TigaseDBException, AuthorizationException {
        logger("Other Auth");
        return false;
    }

    @Override
    public void queryAuth(Map<String, Object> authProps) {
        logger("Query Auth");
        String protocol = (String) authProps.get(PROTOCOL_KEY);
        if (protocol.equals(PROTOCOL_VAL_NONSASL)) {
            authProps.put(RESULT_KEY, non_sasl_mechs);
        }

        if (protocol.equals(PROTOCOL_VAL_SASL)) {
            authProps.put(RESULT_KEY, sasl_mechs);
        }
    }

    @Override
    public void removeUser(BareJID user) throws TigaseDBException {
        logger("Remove User");
        throw new TigaseDBException("Not available");
    }

    @Override
    public void setAccountStatus(BareJID user, AccountStatus status) throws TigaseDBException {
        logger("Account Status");
        throw new TigaseDBException("Feature not supported");
    }

    @Override
    public void updatePassword(BareJID user, String password) throws TigaseDBException {
        logger("Update Password");
        throw new TigaseDBException("Not available");
    }
}
