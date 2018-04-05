package com.legalfab.cms.db;

import org.springframework.data.jpa.repository.JpaRepository;

import com.legalfab.cms.model.UserActivity;

public interface ActivityDB extends JpaRepository<UserActivity, Long>{

}
