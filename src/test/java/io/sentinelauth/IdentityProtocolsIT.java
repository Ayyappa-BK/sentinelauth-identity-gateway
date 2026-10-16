package io.sentinelauth;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.Callable;
import javax.security.auth.Subject;
import org.ietf.jgss.*;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;
import static org.assertj.core.api.Assertions.*;
@EnabledIfSystemProperty(named="sentinel.protocol",matches="true")
class IdentityProtocolsIT {
 static IdentityProperties properties(){return new IdentityProperties(
  System.getenv().getOrDefault("TEST_LDAP_URL","ldap://localhost:1389"),"dc=sentinel,dc=test",
  "uid=reader,dc=sentinel,dc=test",read("reader_password"),"SENTINEL.TEST","HTTP/gateway@SENTINEL.TEST",
  System.getenv().getOrDefault("TEST_KEYTAB","work/http.keytab"),true);}
 static String read(String name){try{return Files.readString(Path.of(System.getenv().getOrDefault("TEST_SECRET_DIR",".secrets"),name)).strip();}catch(Exception ex){throw new IllegalStateException("Initialize test credentials first",ex);}}
 @Test void actualUserBindAndGroups(){assertThat(new LdapDirectory(properties()).authenticate("alice",read("alice_password")).roles()).containsExactly("ROLE_USER");}
 @Test void actualAdminBindAndGroups(){assertThat(new LdapDirectory(properties()).authenticate("bob",read("bob_password")).roles()).containsExactly("ROLE_ADMIN","ROLE_USER");}
 @Test void noImplicitRoleForValidBind(){assertThat(new LdapDirectory(properties()).authenticate("unprivileged",read("alice_password")).roles()).isEmpty();}
 @Test void actualBindRejectsWrongPassword(){assertThatThrownBy(()->new LdapDirectory(properties()).authenticate("alice","wrong")).isInstanceOf(org.springframework.security.authentication.BadCredentialsException.class);}
 @Test void unknownIdentityRejected(){assertThatThrownBy(()->new LdapDirectory(properties()).resolve("missing")).isInstanceOf(org.springframework.security.authentication.BadCredentialsException.class);}
 @Test void actualDirectoryHealth(){new LdapDirectory(properties()).checkAvailability();}
 @Test void realTicketAcceptedWithMutualAuthentication()throws Exception{
  var login=GatewayIT.login(read("alice_password"));var acceptor=new KerberosAcceptor(properties());
  try {Subject.callAs(login.getSubject(),(Callable<Void>)()->{
   var m=GSSManager.getInstance();var client=m.createContext(m.createName("HTTP@gateway",GSSName.NT_HOSTBASED_SERVICE),new Oid("1.3.6.1.5.5.2"),null,GSSContext.DEFAULT_LIFETIME);
   try{
    client.requestMutualAuth(true);client.requestCredDeleg(false);
    var input=client.initSecContext(new byte[0],0,0);String header="Negotiate "+Base64.getEncoder().encodeToString(input);
    var result=acceptor.accept(header);assertThat(result.username()).isEqualTo("alice");
    var output=Base64.getDecoder().decode(result.responseToken());client.initSecContext(output,0,output.length);
    assertThat(client.isEstablished()).isTrue();assertThat(client.getMutualAuthState()).isTrue();
    assertThat(new LdapDirectory(properties()).resolve(result.username()).roles()).containsExactly("ROLE_USER");
    assertThatThrownBy(()->acceptor.accept(header)).isInstanceOf(org.springframework.security.authentication.BadCredentialsException.class);
   }finally{client.dispose();}return null;
  });}finally{login.logout();acceptor.close();}
 }
 @Test void realKdcRejectsWrongPassword(){assertThatThrownBy(()->GatewayIT.login("wrong")).isInstanceOf(javax.security.auth.login.LoginException.class);}
}
