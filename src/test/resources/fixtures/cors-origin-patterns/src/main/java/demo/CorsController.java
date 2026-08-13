package demo;

import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class CorsController {

    // originPatterns is set, so Spring does NOT fall back to the "allow
    // every origin" default even though "origins" itself is absent.
    @CrossOrigin(originPatterns = "https://*.example.com", allowCredentials = "true")
    @GetMapping("/api/ping")
    public String ping() {
        return "pong";
    }
}
