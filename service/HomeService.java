package com.groceryBazar.service;

import java.util.List;

import com.groceryBazar.model.Home;
import com.groceryBazar.model.HomeCategory;

public interface HomeService {

    Home creatHomePageData(List<HomeCategory> categories);

}
