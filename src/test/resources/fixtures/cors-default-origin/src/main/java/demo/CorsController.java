package demo;

import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class CorsController {

    // No "origins" attribute at all: Spring defaults this to allowing every
    // origin, which combined with allowCredentials=true is the same
    // vulnerable combination as an explicit origins = "*".
    @CrossOrigin(allowCredentials = "true")
    @GetMapping("/api/ping")
    public String ping() {
        return "pong";
    }
}
