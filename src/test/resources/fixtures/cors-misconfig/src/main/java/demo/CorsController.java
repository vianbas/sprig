package demo;

import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class CorsController {

    @CrossOrigin(origins = "*", allowCredentials = "true")
    @GetMapping("/api/ping")
    public String ping() {
        return "pong";
    }
}
