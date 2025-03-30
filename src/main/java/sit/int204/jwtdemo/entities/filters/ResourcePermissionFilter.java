package sit.int204.jwtdemo.entities.filters;

import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ResponseStatusException;
import sit.int204.jwtdemo.entities.entities.AuthUserDetail;

import java.io.IOException;
import java.security.Principal;

// เป็น custom filter ที่ทำหน้าที่ตรวจสอบสิทธิ์การเข้าถึงของผู้ใช้ที่เข้ามาเรียกใช้ API ที่อยู่ใน path /api/resources/{resourceId}
@Component
@Order(1) //filter นี้จะทำงานในลำดับแรก และจะตรวจสอบว่า user มีสิทธิ์เข้าถึง resource นั้นๆ หรือไม่ก่อนที่จะให้ดำเนินการต่อ
public class ResourcePermissionFilter implements Filter {
    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse
            , FilterChain filterChain) throws IOException, ServletException {
        HttpServletRequest request = (HttpServletRequest) servletRequest;

        //ตรวจสอบว่า URL ของ request ตรงกับ pattern หรือไม่:
        if (request.getRequestURI().matches("/api/resources/\\S+")) {
            //ดึงข้อมูลของ user จาก request.getUserPrincipal():
            Principal principal = request.getUserPrincipal();
            //ตรวจสอบว่า principal มีค่า และแปลงเป็น AuthUserDetail:
            AuthUserDetail user = principal == null ? null
                    : (AuthUserDetail) ((UsernamePasswordAuthenticationToken) principal).getPrincipal();
            //ถ้า user เป็น null หรือไม่มีข้อมูลสิทธิ์การเข้าถึง จะส่ง HTTP 401 Unauthorized:
            if (user == null) {
                throw new ResponseStatusException(HttpStatus.UNAUTHORIZED
                        ,"You do not have permission to access this resource");
            }
        }
        //หากผู้ใช้มีสิทธิ์ที่ถูกต้อง จะให้คำขอผ่านไปยัง filter ถัดไป:
        filterChain.doFilter(servletRequest, servletResponse);
    }
}
