package com.cigama.auth0.repository;

import com.cigama.auth0.entity.UserSecuritySetting;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.UUID;

@Repository
public interface UserSecuritySettingRepository extends JpaRepository<UserSecuritySetting, UUID> {
}
