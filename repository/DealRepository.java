package com.groceryBazar.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import com.groceryBazar.model.Deal;

public interface DealRepository extends JpaRepository<Deal,Long> {

}
