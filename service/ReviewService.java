package com.groceryBazar.service;

import javax.naming.AuthenticationException;

import com.groceryBazar.exception.ReviewNotFoundException;
import com.groceryBazar.model.Product;
import com.groceryBazar.model.Review;
import com.groceryBazar.model.User;
import com.groceryBazar.request.CreateReviewRequest;

import java.util.List;

public interface ReviewService {

    Review createReview(CreateReviewRequest req,
                        User user,
                        Product product);

    List<Review> getReviewsByProductId(Long productId);

    Review updateReview(Long reviewId,
                        String reviewText,
                        double rating,
                        Long userId) throws ReviewNotFoundException, AuthenticationException;


    void deleteReview(Long reviewId, Long userId) throws ReviewNotFoundException, AuthenticationException;

}
