package com.secubd.secure_demo.repository;

import com.secubd.secure_demo.model.AuditLog;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;
import java.time.LocalDateTime;
import java.util.List;

@Repository
public interface AuditLogRepository extends JpaRepository<AuditLog, Long> {
    List<AuditLog> findByUsername(String username);
    List<AuditLog> findByUsernameAndTimestampAfter(String username, LocalDateTime timestamp);

    @Query("SELECT a FROM AuditLog a WHERE a.success = false AND a.timestamp > :since")
    List<AuditLog> findFailedAttemptsSince(LocalDateTime since);
}