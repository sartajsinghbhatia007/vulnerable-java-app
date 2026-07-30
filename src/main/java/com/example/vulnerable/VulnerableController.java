package com.example.vulnerable;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.web.bind.annotation.*;
import org.w3c.dom.Document;
import org.yaml.snakeyaml.Yaml;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.*;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.sql.*;
import java.util.*;

/**
 * Intentionally Vulnerable REST Controller
 * DO NOT USE IN PRODUCTION - FOR SECURITY TESTING ONLY
 */
@RestController
@RequestMapping("/api")
public class VulnerableController {

    // In-memory user store (simulating database)
    private static final List<Map<String, Object>> users = new ArrayList<>();

    static {
        Map<String, Object> admin = new HashMap<>();
        admin.put("id", 1);
        admin.put("username", "admin");
        admin.put("password", "hashed_password");
        admin.put("email", "admin@example.com");
        admin.put("role", "admin");
        users.add(admin);

        Map<String, Object> user = new HashMap<>();
        user.put("id", 2);
        user.put("username", "user");
        user.put("password", "hashed_password");
        user.put("email", "user@example.com");
        user.put("role", "user");
        users.add(user);
    }

    @GetMapping("/")
    public String index() {
        return """
                <html>
                <head><title>Vulnerable Java App</title></head>
                <body>
                    <h1>Intentionally Vulnerable Spring Boot Application</h1>
                    <p>This application contains numerous security vulnerabilities for testing purposes.</p>
                    <h2>Available Endpoints:</h2>
                    <ul>
                        <li>POST /api/login - SQL Injection</li>
                        <li>GET /api/exec?cmd=ls - Command Injection</li>
                        <li>GET /api/files?filename=test.txt - Path Traversal</li>
                        <li>POST /api/upload - Unrestricted File Upload</li>
                        <li>GET /api/search?query=test - XSS</li>
                        <li>GET /api/proxy?url=http://example.com - SSRF</li>
                        <li>POST /api/evaluate - RCE via Script Engine</li>
                        <li>POST /api/deserialize - Insecure Deserialization</li>
                        <li>DELETE /api/admin/users/{id} - Missing Authentication</li>
                        <li>GET /api/users/{id} - IDOR</li>
                        <li>POST /api/parse-xml - XXE Injection</li>
                        <li>POST /api/parse-yaml - YAML Deserialization</li>
                        <li>POST /api/register - Mass Assignment</li>
                        <li>GET /api/debug - Sensitive Data Exposure</li>
                        <li>GET /redirect?url= - Open Redirect</li>
                    </ul>
                </body>
                </html>
                """;
    }

    // VULNERABILITY: SQL Injection (CWE-89)
    @PostMapping("/login")
    public Map<String, Object> login(@RequestBody Map<String, String> credentials) {
        String username = credentials.get("username");
        String password = credentials.get("password");

        // Vulnerable: Direct string concatenation simulating SQL injection
        String query = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'";
        System.out.println("Query: " + query);  // This would be vulnerable in real SQL

        Map<String, Object> response = new HashMap<>();
        for (Map<String, Object> user : users) {
            if (user.get("username").equals(username)) {
                // VULNERABILITY: Weak JWT with predictable secret (CWE-327)
                String token = "fake_jwt_token_" + username + "_" + System.currentTimeMillis();
                response.put("success", true);
                response.put("token", token);
                response.put("user", user);
                return response;
            }
        }

        response.put("success", false);
        response.put("message", "Invalid credentials");
        return response;
    }

    // VULNERABILITY: Command Injection (CWE-78)
    @GetMapping("/exec")
    public Map<String, Object> executeCommand(@RequestParam String cmd) {
        Map<String, Object> response = new HashMap<>();
        try {
            // Vulnerable: User input directly in shell command
            Process process = Runtime.getRuntime().exec(cmd);
            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            StringBuilder output = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\n");
            }
            process.waitFor();

            response.put("success", true);
            response.put("output", output.toString());
        } catch (Exception e) {
            response.put("error", e.getMessage());
        }
        return response;
    }

    // VULNERABILITY: Path Traversal (CWE-22)
    @GetMapping("/files")
    public Map<String, Object> getFile(@RequestParam String filename) {
        Map<String, Object> response = new HashMap<>();
        try {
            // Vulnerable: No sanitization of file path
            String filePath = System.getProperty("user.dir") + "/uploads/" + filename;
            String content = new String(Files.readAllBytes(Paths.get(filePath)));
            response.put("content", content);
        } catch (IOException e) {
            response.put("error", "File not found");
        }
        return response;
    }

    // VULNERABILITY: Unrestricted File Upload (CWE-434)
    @PostMapping("/upload")
    public Map<String, Object> uploadFile(@RequestParam("file") String fileContent,
                                          @RequestParam("filename") String filename) {
        Map<String, Object> response = new HashMap<>();
        try {
            // Vulnerable: No file type validation, no size limits
            String uploadPath = System.getProperty("user.dir") + "/uploads/" + filename;
            Files.write(Paths.get(uploadPath), fileContent.getBytes());

            response.put("success", true);
            response.put("filename", filename);
            response.put("path", uploadPath);
        } catch (IOException e) {
            response.put("error", e.getMessage());
        }
        return response;
    }

    // VULNERABILITY: Cross-Site Scripting (XSS) (CWE-79)
    @GetMapping("/search")
    public String search(@RequestParam String query) {
        // Vulnerable: Reflects user input without sanitization
        return "<h1>Search Results for: " + query + "</h1>";
    }

    // VULNERABILITY: Server-Side Request Forgery (SSRF) (CWE-918)
    @GetMapping("/proxy")
    public Map<String, Object> proxy(@RequestParam String url) {
        Map<String, Object> response = new HashMap<>();
        try {
            // Vulnerable: No URL validation, allows internal network access
            URL targetUrl = new URL(url);
            HttpURLConnection connection = (HttpURLConnection) targetUrl.openConnection();
            connection.setRequestMethod("GET");

            BufferedReader reader = new BufferedReader(new InputStreamReader(connection.getInputStream()));
            StringBuilder content = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                content.append(line);
            }
            reader.close();

            response.put("data", content.toString());
            response.put("status", connection.getResponseCode());
        } catch (Exception e) {
            response.put("error", e.getMessage());
        }
        return response;
    }

    // VULNERABILITY: Remote Code Execution via Script Engine (CWE-94)
    @PostMapping("/evaluate")
    public Map<String, Object> evaluate(@RequestBody Map<String, String> request) {
        Map<String, Object> response = new HashMap<>();
        try {
            String expression = request.get("expression");
            // Vulnerable: Evaluating user input (similar to eval in other languages)
            // In Java, this would typically use ScriptEngine, but we'll simulate
            response.put("warning", "Would execute: " + expression);
            response.put("result", "Execution simulated (dangerous in real implementation)");
        } catch (Exception e) {
            response.put("error", e.getMessage());
        }
        return response;
    }

    // VULNERABILITY: Insecure Deserialization (CWE-502)
    @PostMapping("/deserialize")
    public Map<String, Object> deserialize(@RequestBody byte[] data) {
        Map<String, Object> response = new HashMap<>();
        try {
            // Vulnerable: Deserializing untrusted data
            ByteArrayInputStream bis = new ByteArrayInputStream(data);
            ObjectInputStream ois = new ObjectInputStream(bis);
            Object obj = ois.readObject();
            ois.close();

            response.put("result", obj.toString());
        } catch (Exception e) {
            response.put("error", e.getMessage());
        }
        return response;
    }

    // VULNERABILITY: Missing Authentication (CWE-862)
    @DeleteMapping("/admin/users/{userId}")
    public Map<String, Object> deleteUser(@PathVariable int userId) {
        // Vulnerable: No authentication or authorization check!
        users.removeIf(u -> (int) u.get("id") == userId);

        Map<String, Object> response = new HashMap<>();
        response.put("success", true);
        response.put("message", "User deleted");
        return response;
    }

    // VULNERABILITY: Insecure Direct Object Reference (IDOR) (CWE-639)
    @GetMapping("/users/{userId}")
    public Map<String, Object> getUser(@PathVariable int userId) {
        // Vulnerable: No authorization check - any user can view any user's data
        for (Map<String, Object> user : users) {
            if ((int) user.get("id") == userId) {
                return user;
            }
        }

        Map<String, Object> response = new HashMap<>();
        response.put("error", "User not found");
        return response;
    }

    // VULNERABILITY: XML External Entity (XXE) Injection (CWE-611)
    @PostMapping("/parse-xml")
    public Map<String, Object> parseXml(@RequestBody String xmlData) {
        Map<String, Object> response = new HashMap<>();
        try {
            // XXE hardening: disable DOCTYPE declarations and external entity resolution.
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
            factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
            factory.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
            factory.setXIncludeAware(false);
            factory.setExpandEntityReferences(false);
            DocumentBuilder builder = factory.newDocumentBuilder();
            Document document = builder.parse(new ByteArrayInputStream(xmlData.getBytes()));

            response.put("result", "XML parsed successfully");
            response.put("root", document.getDocumentElement().getNodeName());
        } catch (Exception e) {
            response.put("error", e.getMessage());
        }
        return response;
    }

    // VULNERABILITY: YAML Deserialization (CWE-502)
    @PostMapping("/parse-yaml")
    public Map<String, Object> parseYaml(@RequestBody Map<String, String> request) {
        Map<String, Object> response = new HashMap<>();
        try {
            String yamlContent = request.get("yamlContent");
            // Vulnerable: YAML parsing can execute arbitrary code
            Yaml yaml = new Yaml();
            Object parsed = yaml.load(yamlContent);

            response.put("result", parsed);
        } catch (Exception e) {
            response.put("error", e.getMessage());
        }
        return response;
    }

    // VULNERABILITY: Mass Assignment (CWE-915)
    @PostMapping("/register")
    public Map<String, Object> register(@RequestBody Map<String, Object> userData) {
        // Vulnerable: Directly assigning all properties from user input
        Map<String, Object> newUser = new HashMap<>();
        newUser.put("id", users.size() + 1);
        newUser.putAll(userData);  // Attacker could set role: 'admin'

        users.add(newUser);

        Map<String, Object> response = new HashMap<>();
        response.put("success", true);
        response.put("user", newUser);
        return response;
    }

    // VULNERABILITY: Sensitive Data Exposure (CWE-200)
    @GetMapping("/debug")
    public Map<String, Object> debug() {
        // Vulnerable: Exposes sensitive environment variables and secrets
        Map<String, Object> response = new HashMap<>();
        response.put("environment", System.getenv());
        response.put("properties", System.getProperties());
        response.put("jwt_secret", VulnerableApplication.JWT_SECRET);
        response.put("admin_password", VulnerableApplication.ADMIN_PASSWORD);
        response.put("db_password", VulnerableApplication.DB_PASSWORD);
        response.put("api_key", VulnerableApplication.API_KEY);
        response.put("users", users);
        return response;
    }

    // VULNERABILITY: Insecure Randomness (CWE-330)
    @GetMapping("/token")
    public Map<String, Object> getToken() {
        // Vulnerable: Random is not cryptographically secure
        Random random = new Random();
        String token = "";
        for (int i = 0; i < 16; i++) {
            token += (char) ('a' + random.nextInt(26));
        }

        Map<String, Object> response = new HashMap<>();
        response.put("token", token);
        return response;
    }

    // VULNERABILITY: Open Redirect (CWE-601)
    @GetMapping("/redirect")
    public void redirect(@RequestParam String url, HttpServletResponse response) throws IOException {
        // Vulnerable: No validation of redirect URL
        response.sendRedirect(url);
    }

    // VULNERABILITY: Information Disclosure through Error Messages (CWE-209)
    @GetMapping("/error-test")
    public Map<String, Object> errorTest() {
        Map<String, Object> response = new HashMap<>();
        try {
            throw new Exception("Database connection failed: jdbc:mysql://admin:password@localhost:3306/mydb");
        } catch (Exception e) {
            // Vulnerable: Exposes sensitive information in error message
            response.put("error", e.getMessage());
            response.put("stackTrace", Arrays.toString(e.getStackTrace()));
        }
        return response;
    }

    // VULNERABILITY: Weak Cryptography (CWE-327)
    @PostMapping("/hash")
    public Map<String, Object> hashPassword(@RequestBody Map<String, String> request) {
        Map<String, Object> response = new HashMap<>();
        try {
            String password = request.get("password");
            // Vulnerable: Using weak hash algorithm (MD5)
            MessageDigest md = MessageDigest.getInstance("MD5");
            byte[] hash = md.digest(password.getBytes());
            StringBuilder hexString = new StringBuilder();
            for (byte b : hash) {
                hexString.append(String.format("%02x", b));
            }

            response.put("hash", hexString.toString());
            response.put("algorithm", "MD5");
        } catch (Exception e) {
            response.put("error", e.getMessage());
        }
        return response;
    }

    @GetMapping("/health")
    public Map<String, String> health() {
        Map<String, String> response = new HashMap<>();
        response.put("status", "running");
        response.put("vulnerabilities", "many");
        return response;
    }
}
