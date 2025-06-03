package com.groceryBazar.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import com.groceryBazar.model.Address;

public interface AddressRepository extends JpaRepository<Address, Long> {

}
