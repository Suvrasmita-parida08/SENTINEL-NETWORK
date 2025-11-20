package com.example.sentinel.controller;

import com.example.sentinel.model.User;
import com.example.sentinel.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;
import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/auth")
public class AuthController {
    @Autowired
    UserRepository userRepo;

    private final String GOOGLE_TOKENINFO = "https://oauth2.googleapis.com/tokeninfo";

    @PostMapping("/google")
    public ResponseEntity<?> googleAuth(@RequestBody Map<String,String> body){
        String idToken = body.get("id_token");
        if(idToken==null) return ResponseEntity.badRequest().body(Map.of("error","id_token required"));
        RestTemplate rt = new RestTemplate();
        Map<String,String> params = new HashMap<>();
        params.put("id_token", idToken);
        try {
            // call tokeninfo
            Map resp = rt.getForObject(GOOGLE_TOKENINFO + "?id_token={id_token}", Map.class, params);
            if(resp == null || resp.get("sub") == null) return ResponseEntity.status(400).body(Map.of("error","invalid token"));
            String sub = (String) resp.get("sub");
            String email = (String) resp.get("email");
            String name = (String) resp.get("name");
            User user = userRepo.findByGoogleSub(sub).orElseGet(() -> {
                User u = new User();
                u.setGoogleSub(sub);
                u.setEmail(email);
                u.setName(name);
                return userRepo.save(u);
            });
            // issue demo token (in prod use JWT)
            String token = "demo-token-" + user.getId() + "-" + System.currentTimeMillis()/1000;
            // for demo mapping, we might store token somewhere (omitted)
            return ResponseEntity.ok(Map.of("token", token, "user", Map.of("id", user.getId(), "email", user.getEmail())));
        } catch(Exception e){
            return ResponseEntity.status(400).body(Map.of("error","token verification failed", "detail", e.getMessage()));
        }
    }
}
