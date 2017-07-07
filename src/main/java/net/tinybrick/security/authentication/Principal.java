package net.tinybrick.security.authentication;

/**
 * Created by ji.wang on 2017-07-06.
 */
public class Principal implements IAuthenticationToken<String>{
    String username;
    String realm = "DEFAULT";

    public Principal() {}
    public Principal(String username) {this(username, null);}
    public Principal(String username, String realm){
        setUsername(username);
        setRealm(realm);
    }

    @Override
    public String getUsername()
    {
        return username;
    }

    public void setUsername(String username)
    {
        this.username = username;
    }

    public String getRealm()
    {
        return realm;
    }

    public void setRealm(String realm)
    {
        this.realm = realm;
    }
}
