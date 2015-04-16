package us.kbase.auth.fakesrv;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.ConnectException;
import java.net.URL;
import java.util.Arrays;
import java.util.Map;

import junit.framework.Assert;

import org.junit.Test;

import us.kbase.auth.AuthConfig;
import us.kbase.auth.AuthUser;
import us.kbase.auth.ConfigurableAuthService;
import us.kbase.auth.UserDetail;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;

public class AuthFakeServiceTest {
    
    @Test
    public void test() throws Exception {
        int port = 23456;
        AuthFakeService.main(new String[] {"" + port});
        URL url = new URL("http://localhost:" + port);
        try {
            AuthConfig cfg = new AuthConfig().withKBaseAuthServerURL(url).withGlobusAuthURL(url);
            ConfigurableAuthService as = new ConfigurableAuthService(cfg);
            AuthUser u = as.login("kbasetest", "kbasetest");
            System.out.println(new ObjectMapper().configure(SerializationFeature.INDENT_OUTPUT, true).writeValueAsString(u));
            Map<String, UserDetail> d0 = as.fetchUserDetail(Arrays.asList("kbasetest22", "nardevuser1"), u.getToken());
            System.out.println(new ObjectMapper().configure(SerializationFeature.INDENT_OUTPUT, true).writeValueAsString(d0));
        } finally {
            BufferedReader br = new BufferedReader(new InputStreamReader(
                    new URL("http://localhost:" + port + "/shutdown").openStream()));
            System.out.println(br.readLine());
            br.close();
        }
        Thread.sleep(200);
        try {
            AuthConfig cfg = new AuthConfig().withKBaseAuthServerURL(url).withGlobusAuthURL(url);
            ConfigurableAuthService as = new ConfigurableAuthService(cfg);
            as.login("kbasetest", "kbasetest");
            Assert.fail("Fake service should be unreachable");
        } catch (ConnectException ex) {
            Assert.assertEquals("Connection refused", ex.getMessage());
        }
    }
}
