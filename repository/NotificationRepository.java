package com.groceryBazar.repository;

import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;

import com.groceryBazar.model.Notification;

public interface NotificationRepository extends JpaRepository<Notification, Long> {



}
