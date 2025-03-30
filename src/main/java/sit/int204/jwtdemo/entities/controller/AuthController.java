package sit.int204.jwtdemo.entities.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import sit.int204.jwtdemo.entities.Dto.AccessToken;
import sit.int204.jwtdemo.entities.Dto.JwtRequestUser;
import sit.int204.jwtdemo.entities.service.UserService;

import java.util.Map;

@RequestMapping("/authentications")
@RestController
public class AuthController {
    @Autowired
    private UserService userService;

    @PostMapping("/login")
    public ResponseEntity<Object> login(
            @RequestBody JwtRequestUser user) {
        return ResponseEntity.ok(userService.authenticateUser(user));
    }

    @PostMapping("/refresh-token")
    public ResponseEntity< Object > refreshToken(
            @RequestHeader("x-refresh-token") String refreshToken) {
        return ResponseEntity.ok(userService.refreshToken(refreshToken));
    }
}
