package com.groceryBazar.controller;

import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import com.groceryBazar.model.Home;
import com.groceryBazar.response.ApiResponse;
import com.groceryBazar.service.HomeService;

import java.util.List;

@RestController
@RequiredArgsConstructor
public class HomeController {

    private final HomeService homeService;

    @GetMapping
    public ResponseEntity<ApiResponse> home(){
        ApiResponse apiResponse = new ApiResponse();
        apiResponse.setMessage("GroceryBazar");
        return new ResponseEntity<>(apiResponse, HttpStatus.ACCEPTED);
    }




}
