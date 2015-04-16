package us.kbase.auth.fakesrv;

import java.io.IOException;
import java.net.URL;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.servlet.ServletContextHandler;
import org.eclipse.jetty.servlet.ServletHolder;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;

import us.kbase.auth.AuthConfig;
import us.kbase.auth.AuthToken;
import us.kbase.auth.AuthUser;
import us.kbase.auth.ConfigurableAuthService;
import us.kbase.auth.UserDetail;

public class AuthFakeService extends HttpServlet {
    private static final String HEXES = "0123456789abcdef";
    
    private static Server jettyServerSingleton = null;

    private void setupResponseHeaders(HttpServletRequest request, HttpServletResponse response) {
        response.setHeader("Access-Control-Allow-Origin", "*");
        String allowedHeaders = request.getHeader("HTTP_ACCESS_CONTROL_REQUEST_HEADERS");
        response.setHeader("Access-Control-Allow-Headers", allowedHeaders == null ? "authorization" : allowedHeaders);
        response.setContentType("application/json");
    }

    @Override
    protected void doOptions(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        setupResponseHeaders(request, response);
        response.setContentLength(0);
        response.getOutputStream().print("");
        response.getOutputStream().flush();
    }

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        doPost(request, response);
    }
    
    @Override
    protected void doPost(HttpServletRequest request, final HttpServletResponse response) throws ServletException, IOException {
        setupResponseHeaders(request, response);
        try {
            String ret = null;
            String urlPath = request.getPathInfo();
            if (urlPath.contains("Sessions/Login")) {
                String userId = request.getParameter("user_id");
                String password = request.getParameter("password");
                String tokenText = request.getParameter("token");
                String fieldsText = request.getParameter("fields");
                Set<String> fieldSet = fieldsText == null ? null :
                    new LinkedHashSet<String>(Arrays.asList(fieldsText.split(",")));
                AuthToken token = null;
                if (userId != null) {
                    if (password == null)
                        password = "";
                    final Calendar cal = Calendar.getInstance();
                    cal.setTime(new Date());
                    cal.add(Calendar.YEAR, 1);
                    cal.add(Calendar.DAY_OF_YEAR, -1);
                    long exp = cal.getTime().getTime() / 1000;
                    token = new AuthToken("un=" + userId + "|tokenid=3be5a452-0d97-11e2-81d0-12313809f035|" +
                            "expiry=" + exp + "|client_id=" + userId + "|token_type=Bearer|SigningSubject=" +
                            "http://localhost/nowhere|sig=" + stringToHex(password));
                } else if (tokenText != null) {
                    token = new AuthToken(tokenText);
                    userId = token.getClientId();
                    password = hexToString(token.getSignature());
                } else {
                    ret = "{\"user_id\": null}";
                }
                if (ret == null) {
                    checkUserPassword(userId, password);
                    Map<String, Object> map = new LinkedHashMap<String, Object>();
                    putMapPropIfNeeded(fieldSet, map, "email", getEmail(userId));
                    putMapPropIfNeeded(fieldSet, map, "groups", new ArrayList<String>());
                    putMapPropIfNeeded(fieldSet, map, "token", token.toString());
                    putMapPropIfNeeded(fieldSet, map, "verified", true);
                    putMapPropIfNeeded(fieldSet, map, "user_id", userId);
                    putMapPropIfNeeded(fieldSet, map, "name", getFullName(userId));
                    putMapPropIfNeeded(fieldSet, map, "kbase_sessionid", "0bbc5029ba4caa16d7b0742afd05065b80eb922a5e8ae2485fcdfb2b6b356aad");
                    putMapPropIfNeeded(fieldSet, map, "opt_in", false);
                    putMapPropIfNeeded(fieldSet, map, "system_admin", false);
                    ret = new ObjectMapper().configure(SerializationFeature.INDENT_OUTPUT, true).writeValueAsString(map);
                }
            } else if (urlPath.contains("groups/") && urlPath.contains("/members/")) {
                AuthToken token = new AuthToken(request.getHeader("X-Globus-Goauthtoken"));
                checkUserPassword(token.getClientId(), hexToString(token.getSignature()));
                String userId = urlPath.substring(urlPath.lastIndexOf('/') + 1);
                if (!checkUserExists(userId)) {
                    response.setStatus(404);
                    response.getWriter().write("User id doesn't contain 'test' substring");
                    return;
                }
                Map<String, Object> map = new LinkedHashMap<String, Object>();
                map.put("username", userId);
                map.put("email", getEmail(userId));
                map.put("name", getFullName(userId));
                ret = new ObjectMapper().configure(SerializationFeature.INDENT_OUTPUT, true).writeValueAsString(map);
            } else if (urlPath.endsWith("/shutdown")) {
                ret = "Will be done in a second";
                new Thread(new Runnable() {
                    @Override
                    public void run() {
                        try { 
                            Thread.sleep(100); 
                            System.out.println("AuthFakeService is shutdown");
                            jettyServerSingleton.stop();
                        } catch (Exception ex) {
                            ex.printStackTrace();
                        }
                    }
                }).start();
            } else {
                throw new Exception("Url path is not supported: " + urlPath);
            }
            response.getWriter().write(ret);
        } catch (Exception ex) {
            String msg = ex.getMessage();
            if (msg == null)
                msg = "Unknown error";
            response.setStatus(401);
            response.getWriter().write(msg);
        }
    }

    private static void putMapPropIfNeeded(Set<String> fieldSet, Map<String, Object> map, String prop, Object value) {
        if (fieldSet != null && !fieldSet.contains(prop))
            return;
        map.put(prop, value);
    }
    
    private static void checkUserPassword(String userId, String password) throws Exception {
        if (!checkUserExists(userId))
            throw new Exception("User id doesn't contain 'test' substring");
        if (!checkPassword(userId, password))
            throw new Exception("User id doesn't match password");
    }
    
    private static boolean checkUserExists(String userId) {
        return userId.contains("test");
    }
    
    private static boolean checkPassword(String userId, String password) {
        return password.equals(userId);
    }
    
    private static String getFullName(String userId) {
        return userId;
    }
    
    private static String getEmail(String userId) {
        return userId + "@localhost";
    }
    
    public static String stringToHex(String text) {
        byte[] raw = text.getBytes(Charset.forName("utf-8"));
        final StringBuilder hex = new StringBuilder(2 * raw.length);
        for (final byte b : raw)
            hex.append(HEXES.charAt((b & 0xF0) >> 4)).append(HEXES.charAt((b & 0x0F)));
        return hex.toString();
    }

    public static String hexToString(String hex) {
        hex = hex.toLowerCase();
        byte[] ret = new byte[hex.length() / 2];
        for (int i = 0; i < ret.length; i++)
            ret[i] = Byte.parseByte(hex.substring(i * 2, (i + 1) * 2), 16);
        return new String(ret, Charset.forName("utf-8"));
    }
    
    public static void main(String[] args) throws Exception {
        if (args.length != 1) {
            System.out.println("Usage: <program> <port>");
            return;
        }
        int port = Integer.parseInt(args[0]);
        Server jettyServer = new Server(port);
        ServletContextHandler context = new ServletContextHandler(ServletContextHandler.SESSIONS);
        context.setContextPath("/");
        jettyServer.setHandler(context);
        context.addServlet(new ServletHolder(new AuthFakeService()),"/*");
        jettyServer.start();
        jettyServerSingleton = jettyServer;
        //jettyPort = jettyServer.getConnectors()[0].getLocalPort();
        //jettyServer.join();
    }
}
