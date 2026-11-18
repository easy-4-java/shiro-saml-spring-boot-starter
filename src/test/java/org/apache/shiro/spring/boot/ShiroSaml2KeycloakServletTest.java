package org.apache.shiro.spring.boot;

import com.alibaba.fastjson.JSONObject;
import net.shibboleth.utilities.java.support.xml.SerializeSupport;
import org.jsoup.Connection;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.junit.jupiter.api.io.TempDir;
import org.opensaml.core.config.InitializationService;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.saml.saml2.core.NameID;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml.saml2.metadata.KeyDescriptor;
import org.opensaml.security.credential.UsageType;
import org.opensaml.xmlsec.keyinfo.KeyInfoSupport;
import org.springframework.boot.web.servlet.context.ServletWebServerApplicationContext;
import org.springframework.util.StreamUtils;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.PublicKey;
import java.util.Base64;
import java.util.Objects;
import java.util.concurrent.TimeUnit;

import static org.apache.shiro.spring.boot.ShiroSaml2EmbeddedServletTest.callbackUrl;
import static org.apache.shiro.spring.boot.ShiroSaml2EmbeddedServletTest.startServlet;
import static org.assertj.core.api.Assertions.assertThat;

@EnabledIfEnvironmentVariable(named = "SAML_TEST_KEYCLOAK_HOME", matches = ".+")
class ShiroSaml2KeycloakServletTest {

    private static final String REALM = "saml-servlet-it";
    private static final String USER = "external-idp-user";
    private static final String PASSWORD = "local-idp-test-password";

    @TempDir
    Path scratch;

    @Test
    void verifiesKeycloakSignedAssertionThroughEmbeddedTomcat() throws Exception {
        InitializationService.initialize();
        try (ServletWebServerApplicationContext servlet = startServlet()) {
            String recipient = callbackUrl(servlet);
            Path home = Paths.get(System.getenv("SAML_TEST_KEYCLOAK_HOME"));
            int port = importRealm(home, recipient);
            String issuer = "http://127.0.0.1:" + port + "/realms/" + REALM;
            ProcessBuilder command = new ProcessBuilder(home.resolve("bin/kc.sh").toString(), "start-dev",
                    "--import-realm", "--http-host=127.0.0.1", "--http-port=" + port);
            command.environment().put("JAVA_HOME", System.getenv("KEYCLOAK_JAVA_HOME"));
            Path log = scratch.resolve("keycloak.log");
            Process idp = command.redirectErrorStream(true).redirectOutput(log.toFile()).start();
            try {
                byte[] metadata = awaitMetadata(idp, issuer + "/protocol/saml/descriptor", log);
                servlet.getBean(ShiroSaml2EmbeddedServletTest.FixturePrincipalRepository.class)
                        .configure(signingKey(metadata, issuer), recipient, issuer);

                Connection browser = Jsoup.newSession().timeout(10_000);
                Connection.Response loginPage = browser.newRequest(issuer + "/protocol/saml/clients/servlet").execute();
                Document login = loginPage.parse();
                Element loginForm = login.selectFirst("form#kc-form-login");
                assertThat(loginForm).as("Keycloak login form").isNotNull();
                String loginAction = loginForm.absUrl("action");
                assertThat(loginAction).startsWith(issuer + "/login-actions/");
                // Keycloak marks loopback login cookies Secure. Forward them only to the same test origin.
                Document loginResult = browser.newRequest(loginAction).cookies(loginPage.cookies())
                        .data("username", USER, "password", PASSWORD).post();
                Element responseForm = loginResult.selectFirst("form:has(input[name=SAMLResponse])");
                assertThat(responseForm).as("Keycloak SAML POST form").isNotNull();
                assertThat(responseForm.absUrl("action")).isEqualTo(recipient);
                String response = responseForm.selectFirst("input[name=SAMLResponse]").val();

                Connection.Response accepted = post(browser, recipient, response);
                assertThat(accepted.statusCode()).isEqualTo(200);
                JSONObject result = JSONObject.parseObject(accepted.body());
                assertThat(result.getString("status")).isEqualTo("success");
                assertThat(result.getJSONObject("principal").getString("userid")).isEqualTo(USER);

                org.w3c.dom.Element altered = parse(Base64.getDecoder().decode(response));
                org.w3c.dom.Element name = (org.w3c.dom.Element) altered.getElementsByTagNameNS(
                        NameID.DEFAULT_ELEMENT_NAME.getNamespaceURI(), NameID.DEFAULT_ELEMENT_LOCAL_NAME).item(0);
                assertThat(name.getTextContent()).isEqualTo(USER);
                name.setTextContent("modified-test-subject");
                String changed = Base64.getEncoder().encodeToString(
                        SerializeSupport.nodeToString(altered).getBytes(StandardCharsets.UTF_8));
                assertThat(post(Jsoup.newSession().timeout(10_000), recipient, changed).statusCode()).isEqualTo(401);
            } finally {
                idp.destroy();
                if (!idp.waitFor(10, TimeUnit.SECONDS)) {
                    idp.destroyForcibly();
                    idp.waitFor(10, TimeUnit.SECONDS);
                }
            }
        }
    }

    private static int importRealm(Path home, String recipient) throws IOException {
        Path imports = home.resolve("data/import");
        Files.createDirectories(imports);
        try (InputStream template = ShiroSaml2KeycloakServletTest.class.getResourceAsStream("/keycloak-realm.json")) {
            String realm = StreamUtils.copyToString(Objects.requireNonNull(template), StandardCharsets.UTF_8);
            Files.write(imports.resolve(REALM + "-realm.json"),
                    realm.replace("${ACS}", recipient).getBytes(StandardCharsets.UTF_8));
        }
        try (ServerSocket socket = new ServerSocket(0, 1, InetAddress.getByName("127.0.0.1"))) {
            return socket.getLocalPort();
        }
    }

    private static byte[] awaitMetadata(Process idp, String url, Path log) throws Exception {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(90);
        IOException lastError = null;
        while (idp.isAlive() && System.nanoTime() < deadline) {
            try {
                return Jsoup.connect(url).timeout(2_000).ignoreContentType(true).execute().bodyAsBytes();
            } catch (IOException e) {
                lastError = e;
                TimeUnit.MILLISECONDS.sleep(500);
            }
        }
        String output = new String(Files.readAllBytes(log), StandardCharsets.UTF_8);
        throw new IllegalStateException("Keycloak did not serve realm metadata.\n" + output, lastError);
    }

    private static PublicKey signingKey(byte[] metadata, String issuer) throws Exception {
        org.w3c.dom.Element element = parse(metadata);
        EntityDescriptor descriptor = (EntityDescriptor) XMLObjectProviderRegistrySupport.getUnmarshallerFactory()
                .getUnmarshaller(element).unmarshall(element);
        assertThat(descriptor.getEntityID()).isEqualTo(issuer);
        KeyDescriptor signing = descriptor.getIDPSSODescriptor("urn:oasis:names:tc:SAML:2.0:protocol")
                .getKeyDescriptors().stream().filter(key -> key.getUse() == UsageType.SIGNING)
                .findFirst().orElseThrow(() -> new IllegalStateException("Keycloak metadata has no signing key"));
        return KeyInfoSupport.getCertificates(signing.getKeyInfo()).get(0).getPublicKey();
    }

    private static org.w3c.dom.Element parse(byte[] xml) throws Exception {
        return XMLObjectProviderRegistrySupport.getParserPool().parse(new ByteArrayInputStream(xml)).getDocumentElement();
    }

    private static Connection.Response post(Connection browser, String recipient, String response) throws IOException {
        return browser.newRequest(recipient).data("SAMLResponse", response).followRedirects(false)
                .ignoreContentType(true).ignoreHttpErrors(true).method(Connection.Method.POST).execute();
    }
}
