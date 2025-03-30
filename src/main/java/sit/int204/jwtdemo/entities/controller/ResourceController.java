package sit.int204.jwtdemo.entities.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/resources")
public class ResourceController {

    @GetMapping("/users")
    //@PreAuthorize("hasAnyAuthority('USER','ADMIN','MANAGER')")
    public ResponseEntity<Object> getUserResource() {
        return ResponseEntity.ok("User resourcse");
    }

    @GetMapping("/admins")
    //@PreAuthorize("hasAuthority('ADMIN')")
    public ResponseEntity<Object> getAdminResource() {
        return ResponseEntity.ok("Admin resources");
    }
}
